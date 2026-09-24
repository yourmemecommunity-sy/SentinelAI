-- 0008: user invitations, the "an organization always has an active OWNER" guarantee, and per-organization provider
-- credential metadata. Plaintext secrets never enter the database: invitation tokens are stored as HMACs, provider
-- credentials as AES-256-GCM ciphertext produced by the gateway.

-- ---------------------------------------------------------------- invitations
CREATE TABLE invitations (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email            text NOT NULL CHECK (email = lower(email) AND position('@' IN email) > 1),
  role_id          uuid NOT NULL REFERENCES roles(id),
  token_hash       text NOT NULL UNIQUE,                       -- HMAC(pepper, token); the token itself is shown once
  expires_at       timestamptz NOT NULL,
  accepted_at      timestamptz,
  revoked_at       timestamptz,
  created_by       uuid NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, organization_id),
  FOREIGN KEY (created_by, organization_id) REFERENCES users(id, organization_id) ON DELETE CASCADE,
  CHECK (NOT (accepted_at IS NOT NULL AND revoked_at IS NOT NULL))
);
CREATE INDEX invitations_org_idx ON invitations (organization_id, created_at DESC);
-- At most one live invitation per address per organization.
CREATE UNIQUE INDEX invitations_one_open_per_email ON invitations (organization_id, email) WHERE accepted_at IS NULL AND revoked_at IS NULL;

ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON invitations USING (organization_id = app_org_id()) WITH CHECK (organization_id = app_org_id());
GRANT SELECT, INSERT, UPDATE ON invitations TO sentinel_app;

-- Accepting runs BEFORE the new user has any tenant context, so it is a privileged function that does exactly one thing:
-- redeem a live invitation atomically (single use, not expired, not revoked) and create the user with the invited role.
CREATE OR REPLACE FUNCTION app_accept_invitation(p_hash text, p_password_hash text)
RETURNS TABLE (status text, user_id uuid, organization_id uuid, role text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  inv invitations%ROWTYPE;
  new_id uuid;
BEGIN
  SELECT * INTO inv FROM invitations i
   WHERE i.token_hash = p_hash AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > now()
   FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'invalid'::text, NULL::uuid, NULL::uuid, NULL::text;
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM users u WHERE u.email = inv.email) THEN
    RETURN QUERY SELECT 'email_taken'::text, NULL::uuid, NULL::uuid, NULL::text;
    RETURN;
  END IF;
  INSERT INTO users (organization_id, email, password_hash, role_id)
  VALUES (inv.organization_id, inv.email, p_password_hash, inv.role_id)
  RETURNING id INTO new_id;
  UPDATE invitations SET accepted_at = now() WHERE id = inv.id;
  RETURN QUERY SELECT 'ok'::text, new_id, inv.organization_id, (SELECT r.name FROM roles r WHERE r.id = inv.role_id);
END $$;
REVOKE ALL ON FUNCTION app_accept_invitation(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_accept_invitation(text, text) TO sentinel_app;

-- ---------------------------------------------------------------- every organization keeps an active OWNER
-- Enforced in the database, not only in the API: no code path (a bug, a direct query, a future endpoint) can leave an
-- organization with nobody able to administer it.
CREATE OR REPLACE FUNCTION ensure_active_owner() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  owner_role uuid := (SELECT id FROM roles WHERE name = 'OWNER');
  org uuid := OLD.organization_id;
BEGIN
  -- Only a change that removes an active OWNER can violate the invariant.
  IF OLD.role_id = owner_role AND OLD.disabled_at IS NULL
     AND (TG_OP = 'DELETE' OR NEW.role_id <> owner_role OR NEW.disabled_at IS NOT NULL) THEN
    -- Deleting the organization cascades to its users; that is allowed.
    IF TG_OP = 'DELETE' AND NOT EXISTS (SELECT 1 FROM organizations o WHERE o.id = org) THEN
      RETURN OLD;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM users u WHERE u.organization_id = org AND u.id <> OLD.id
                     AND u.role_id = owner_role AND u.disabled_at IS NULL) THEN
      RAISE EXCEPTION 'an organization must keep at least one active OWNER' USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END $$;
CREATE TRIGGER users_keep_an_owner BEFORE UPDATE OF role_id, disabled_at OR DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION ensure_active_owner();

-- Disabling a user must end their sessions, not only block the next login.
CREATE OR REPLACE FUNCTION revoke_sessions_of_disabled_user() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  IF NEW.disabled_at IS NOT NULL AND OLD.disabled_at IS NULL THEN
    UPDATE refresh_tokens SET revoked_at = now()
     WHERE user_id = NEW.id AND organization_id = NEW.organization_id AND revoked_at IS NULL;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER users_revoke_sessions_on_disable AFTER UPDATE OF disabled_at ON users
  FOR EACH ROW EXECUTE FUNCTION revoke_sessions_of_disabled_user();

-- ---------------------------------------------------------------- per-organization provider credentials
-- credentials_encrypted already exists (0001). These columns describe it without revealing it.
ALTER TABLE providers
  ADD COLUMN credential_key_id   text,                        -- which gateway key sealed it (rotation)
  ADD COLUMN credential_hint     text CHECK (credential_hint IS NULL OR credential_hint ~ '^[A-Za-z0-9_-]{0,4}$'),
  ADD COLUMN updated_by          uuid,
  ADD COLUMN updated_at          timestamptz NOT NULL DEFAULT now(),
  ADD CONSTRAINT providers_credential_consistent CHECK ((credentials_encrypted IS NULL) = (credential_key_id IS NULL)),
  -- Per-organization base URLs are an SSRF surface (a tenant could point the gateway at internal hosts); base URLs remain
  -- operator configuration only.
  ADD CONSTRAINT providers_no_tenant_base_url CHECK (base_url IS NULL);
