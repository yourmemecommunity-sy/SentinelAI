-- SentinelAI 0002: pre-tenant lookups and organization signup.
-- Authentication happens BEFORE the organization is known, so RLS would hide every row. These
-- SECURITY DEFINER functions are the only sanctioned way around it, each returning the minimum
-- columns and taking one exact-match argument (no enumeration, no wildcards).

CREATE OR REPLACE FUNCTION app_find_api_key(p_prefix text)
RETURNS TABLE (id uuid, organization_id uuid, key_hash text, role text, expires_at timestamptz, revoked_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT k.id, k.organization_id, k.key_hash, r.name, k.expires_at, k.revoked_at
  FROM api_keys k JOIN roles r ON r.id = k.role_id
  WHERE k.prefix = p_prefix
$$;

CREATE OR REPLACE FUNCTION app_find_login(p_email text)
RETURNS TABLE (id uuid, organization_id uuid, password_hash text, role text, disabled_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT u.id, u.organization_id, u.password_hash, r.name, u.disabled_at
  FROM users u JOIN roles r ON r.id = u.role_id
  WHERE u.email = lower(p_email)
$$;

-- Creates an organization and its first OWNER atomically (RLS would otherwise forbid the insert).
CREATE OR REPLACE FUNCTION app_signup_organization(p_name text, p_slug text, p_email text, p_password_hash text)
RETURNS TABLE (organization_id uuid, user_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE v_org uuid; v_user uuid;
BEGIN
  INSERT INTO organizations (name, slug) VALUES (p_name, p_slug) RETURNING id INTO v_org;
  INSERT INTO users (organization_id, email, password_hash, role_id)
    VALUES (v_org, lower(p_email), p_password_hash, (SELECT id FROM roles WHERE name = 'OWNER'))
    RETURNING id INTO v_user;
  RETURN QUERY SELECT v_org, v_user;
END $$;

REVOKE ALL ON FUNCTION app_find_api_key(text), app_find_login(text), app_signup_organization(text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_find_api_key(text), app_find_login(text), app_signup_organization(text, text, text, text) TO sentinel_app;
