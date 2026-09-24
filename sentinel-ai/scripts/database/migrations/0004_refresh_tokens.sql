-- SentinelAI 0004: rotating refresh tokens with reuse detection.
-- Only SHA-256(token) is stored. Every login starts a "family"; each refresh revokes the presented token and issues a
-- successor in the same family. Presenting an already-revoked token means it was stolen or replayed => the whole family is revoked.

CREATE TABLE refresh_tokens (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL,
  user_id          uuid NOT NULL,
  family_id        uuid NOT NULL,
  token_hash       text NOT NULL UNIQUE,
  expires_at       timestamptz NOT NULL,
  revoked_at       timestamptz,
  replaced_by      uuid,
  created_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (user_id, organization_id) REFERENCES users(id, organization_id) ON DELETE CASCADE
);
CREATE INDEX refresh_tokens_user_idx   ON refresh_tokens (organization_id, user_id);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);

ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON refresh_tokens
  USING (organization_id = app_org_id()) WITH CHECK (organization_id = app_org_id());
GRANT SELECT, INSERT, UPDATE ON refresh_tokens TO sentinel_app;   -- no DELETE: revocation is a state change

-- Pre-tenant lookup (a refresh request carries no organization).
CREATE OR REPLACE FUNCTION app_find_refresh_token(p_hash text)
RETURNS TABLE (id uuid, organization_id uuid, user_id uuid, family_id uuid, expires_at timestamptz,
               revoked_at timestamptz, role text, user_disabled_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT t.id, t.organization_id, t.user_id, t.family_id, t.expires_at, t.revoked_at, r.name, u.disabled_at
  FROM refresh_tokens t
  JOIN users u ON u.id = t.user_id AND u.organization_id = t.organization_id
  JOIN roles r ON r.id = u.role_id
  WHERE t.token_hash = p_hash
$$;
REVOKE ALL ON FUNCTION app_find_refresh_token(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_find_refresh_token(text) TO sentinel_app;
