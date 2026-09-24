-- SentinelAI 0005: expose last_used_at to the pre-tenant API-key lookup so the gateway can refresh it at most hourly
-- (a write on every request would turn every read into a write).
DROP FUNCTION IF EXISTS app_find_api_key(text);

CREATE FUNCTION app_find_api_key(p_prefix text)
RETURNS TABLE (id uuid, organization_id uuid, key_hash text, role text, expires_at timestamptz, revoked_at timestamptz, last_used_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT k.id, k.organization_id, k.key_hash, r.name, k.expires_at, k.revoked_at, k.last_used_at
  FROM api_keys k JOIN roles r ON r.id = k.role_id
  WHERE k.prefix = p_prefix
$$;

REVOKE ALL ON FUNCTION app_find_api_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_find_api_key(text) TO sentinel_app;
