-- 0010: DevicePulse diagnostics API.
-- Nothing here can hold device telemetry or model output: a request row records who asked, which diagnostic type, the
-- outcome and how many findings were returned; feedback is a rating and an optional reason code (no free text).
-- Both expire (expires_at) and are deleted by app_purge_devicepulse(); a user can delete their own rows at any time.

-- ---------------------------------------------------------------- least-privilege role for mobile clients
-- DEVICE_CLIENT can call the DevicePulse endpoints and nothing else (no ai:use, no scan:use, no keys:manage), so a
-- credential leaked from a phone cannot be used as a general model proxy or to mint more keys.
ALTER TABLE roles DROP CONSTRAINT roles_name_check;
ALTER TABLE roles ADD CONSTRAINT roles_name_check
  CHECK (name IN ('OWNER','ADMIN','SECURITY_ANALYST','DEVELOPER','VIEWER','DEVICE_CLIENT'));
INSERT INTO roles (name, permissions) VALUES ('DEVICE_CLIENT', '["devicepulse:use"]');
-- ADMIN must hold devicepulse:use to grant DEVICE_CLIENT (a caller may only grant permissions it holds).
UPDATE roles
   SET permissions = permissions || '["devicepulse:use"]'::jsonb
 WHERE name = 'ADMIN' AND NOT permissions ? 'devicepulse:use';

-- ---------------------------------------------------------------- explanation requests
CREATE TABLE devicepulse_requests (
  id               uuid PRIMARY KEY,                        -- the request_id returned to the client (server-generated)
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor_type       text NOT NULL CHECK (actor_type IN ('user', 'api_key')),
  actor_id         text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 64),
  diagnostic_type  text NOT NULL CHECK (diagnostic_type ~ '^[a-z_]{1,32}$'),
  status           text NOT NULL CHECK (status IN ('completed', 'insufficient_data')),
  finding_count    integer NOT NULL CHECK (finding_count BETWEEN 0 AND 50),
  -- The security_events row of the screened input (no foreign key: security_events is append-only with its own retention).
  input_event_id   uuid,
  created_at       timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL,
  UNIQUE (id, organization_id),
  CHECK (expires_at > created_at)
);
CREATE INDEX devicepulse_requests_actor_idx ON devicepulse_requests (organization_id, actor_type, actor_id);
CREATE INDEX devicepulse_requests_expiry_idx ON devicepulse_requests (expires_at);

-- ---------------------------------------------------------------- feedback (enum-only)
CREATE TABLE devicepulse_feedback (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL,
  request_id       uuid NOT NULL UNIQUE,                    -- one rating per explanation
  rating           text NOT NULL CHECK (rating IN ('helpful', 'not_helpful')),
  reason_code      text CHECK (reason_code IN ('inaccurate', 'unclear', 'not_actionable', 'too_generic', 'wrong_language', 'other')),
  created_at       timestamptz NOT NULL DEFAULT now(),
  -- Same organization as the request, and deleted with it (expiry or user deletion).
  FOREIGN KEY (request_id, organization_id) REFERENCES devicepulse_requests(id, organization_id) ON DELETE CASCADE
);

ALTER TABLE devicepulse_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON devicepulse_requests USING (organization_id = app_org_id()) WITH CHECK (organization_id = app_org_id());
ALTER TABLE devicepulse_feedback ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON devicepulse_feedback USING (organization_id = app_org_id()) WITH CHECK (organization_id = app_org_id());
-- No UPDATE: rows are written once; DELETE serves user-initiated erasure.
GRANT SELECT, INSERT, DELETE ON devicepulse_requests, devicepulse_feedback TO sentinel_app;

-- ---------------------------------------------------------------- retention
-- Expired rows of every organization. SECURITY DEFINER because the purge runs without a tenant (RLS would hide every
-- row); it takes no argument and can only delete rows that are already past their expiry.
CREATE OR REPLACE FUNCTION app_purge_devicepulse() RETURNS integer
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  WITH d AS (DELETE FROM devicepulse_requests WHERE expires_at <= now() RETURNING 1) SELECT count(*)::integer FROM d
$$;
REVOKE ALL ON FUNCTION app_purge_devicepulse() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_purge_devicepulse() TO sentinel_app;
