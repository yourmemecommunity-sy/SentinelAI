-- SentinelAI 0001: core schema, multi-tenancy, row-level security.
-- NOTE: the migration/owner role bypasses RLS (needed by the SECURITY DEFINER functions in 0002) and must never be
-- used as the application login. The app connects as a member of sentinel_app, which is subject to RLS.
-- Tenancy rule: every tenant-owned row carries organization_id; RLS restricts the app role to
-- rows where organization_id = app_org_id(). If app.org_id is unset, app_org_id() is NULL and NO
-- rows are visible or writable (fail closed).
-- No content columns exist by design: prompts/responses/secrets are never stored.

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinel_app') THEN
    CREATE ROLE sentinel_app NOLOGIN;   -- ops grants this role to the real login role
  END IF;
END $$;

CREATE OR REPLACE FUNCTION app_org_id() RETURNS uuid
  LANGUAGE sql STABLE AS $$ SELECT NULLIF(current_setting('app.org_id', true), '')::uuid $$;

-- ---------------------------------------------------------------- global tables
CREATE TABLE organizations (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name                  text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  slug                  text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  zero_retention        boolean NOT NULL DEFAULT true,
  audit_retention_days  integer NOT NULL DEFAULT 90 CHECK (audit_retention_days >= 0),
  created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE roles (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         text NOT NULL UNIQUE CHECK (name IN ('OWNER','ADMIN','SECURITY_ANALYST','DEVELOPER','VIEWER')),
  permissions  jsonb NOT NULL DEFAULT '[]'::jsonb
);
INSERT INTO roles (name, permissions) VALUES
  ('OWNER',            '["*"]'),
  ('ADMIN',            '["org:manage","users:manage","policies:write","policies:read","events:read","providers:manage","keys:manage","usage:read","ai:use","scan:use","audit:read"]'),
  ('SECURITY_ANALYST', '["policies:read","policies:write","events:read","usage:read","scan:use","audit:read","evaluation:run"]'),
  ('DEVELOPER',        '["ai:use","scan:use","policies:read","keys:manage","usage:read"]'),
  ('VIEWER',           '["policies:read","events:read","usage:read"]');

-- ---------------------------------------------------------------- tenant tables
CREATE TABLE users (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email            text NOT NULL UNIQUE CHECK (email = lower(email)),   -- one org per user (see docs/database/schema.md)
  password_hash    text NOT NULL,
  role_id          uuid NOT NULL REFERENCES roles(id),
  mfa_enabled      boolean NOT NULL DEFAULT false,
  disabled_at      timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, organization_id)
);

CREATE TABLE teams (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name             text NOT NULL,
  UNIQUE (organization_id, name),
  UNIQUE (id, organization_id)
);

CREATE TABLE team_members (
  organization_id  uuid NOT NULL,
  team_id          uuid NOT NULL,
  user_id          uuid NOT NULL,
  PRIMARY KEY (team_id, user_id),
  FOREIGN KEY (team_id, organization_id) REFERENCES teams(id, organization_id) ON DELETE CASCADE,
  FOREIGN KEY (user_id, organization_id) REFERENCES users(id, organization_id) ON DELETE CASCADE
);

CREATE TABLE projects (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name             text NOT NULL,
  UNIQUE (organization_id, name),
  UNIQUE (id, organization_id)
);

CREATE TABLE api_keys (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id       uuid,
  name             text NOT NULL,
  prefix           text NOT NULL UNIQUE CHECK (length(prefix) = 12),
  key_hash         text NOT NULL UNIQUE,           -- HMAC-SHA256(pepper, full key); the key itself is shown once
  role_id          uuid NOT NULL REFERENCES roles(id),
  created_by       uuid,
  expires_at       timestamptz,
  revoked_at       timestamptz,
  last_used_at     timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (project_id, organization_id) REFERENCES projects(id, organization_id) ON DELETE SET NULL (project_id),
  FOREIGN KEY (created_by, organization_id) REFERENCES users(id, organization_id) ON DELETE SET NULL (created_by)
);

CREATE TABLE providers (
  id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider_type          text NOT NULL CHECK (provider_type ~ '^[a-z][a-z0-9_-]{1,31}$'),
  credentials_encrypted  bytea,                    -- envelope-encrypted; never plaintext
  base_url               text,
  enabled                boolean NOT NULL DEFAULT true,
  UNIQUE (organization_id, provider_type),
  UNIQUE (id, organization_id)
);

CREATE TABLE models (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL,
  provider_id      uuid NOT NULL,
  model_id         text NOT NULL,
  allowed          boolean NOT NULL DEFAULT true,
  UNIQUE (provider_id, model_id),
  UNIQUE (id, organization_id),
  FOREIGN KEY (provider_id, organization_id) REFERENCES providers(id, organization_id) ON DELETE CASCADE
);

CREATE TABLE policies (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  policy_id        text NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 128),
  version          integer NOT NULL CHECK (version >= 1),
  active           boolean NOT NULL DEFAULT false,
  created_by       uuid,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, policy_id, version),
  UNIQUE (id, organization_id)
);
-- at most one active version per (organization, policy_id)
CREATE UNIQUE INDEX policies_one_active ON policies (organization_id, policy_id) WHERE active;

CREATE TABLE policy_rules (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL,
  policy_pk        uuid NOT NULL,
  position         integer NOT NULL,
  entity           text NOT NULL,
  action           text NOT NULL CHECK (action IN ('ALLOW','HASH','MASK','TOKENIZE','REDACT','QUARANTINE','BLOCK')),
  severity         text CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  min_confidence   real NOT NULL DEFAULT 0 CHECK (min_confidence BETWEEN 0 AND 1),
  scope            jsonb,
  FOREIGN KEY (policy_pk, organization_id) REFERENCES policies(id, organization_id) ON DELETE CASCADE,
  -- Defence in depth: mirrors the engine's non-overridable floors (ADR-0003).
  CONSTRAINT policy_rules_no_unsafe_allow CHECK (NOT (action = 'ALLOW' AND (
      severity = 'CRITICAL' OR entity IN (
        'PRIVATE_KEY','AWS_CREDENTIAL','GOOGLE_CREDENTIAL','GITHUB_TOKEN','JWT','OAUTH_TOKEN','PASSWORD',
        'CONNECTION_STRING','API_KEY','CREDIT_CARD',
        'PROMPT_INJECTION','SYSTEM_PROMPT_EXTRACTION','JAILBREAK','DATA_EXFILTRATION')))),
  UNIQUE (policy_pk, position)
);

CREATE TABLE security_events (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id             uuid,
  request_id          text NOT NULL,
  application         text,
  provider            text,
  model               text,
  direction           text NOT NULL CHECK (direction IN ('INPUT','OUTPUT')),
  event_type          text NOT NULL CHECK (event_type IN ('scan','ai_request','ai_response','fail_closed','policy_change','auth')),
  risk_level          text NOT NULL CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  risk_score          integer NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  action              text NOT NULL CHECK (action IN ('ALLOW','HASH','MASK','TOKENIZE','REDACT','QUARANTINE','BLOCK')),
  entity_types        text[] NOT NULL DEFAULT '{}',
  policy_id           text NOT NULL,
  failed_closed       boolean NOT NULL DEFAULT false,
  fail_closed_reason  text,
  detector_version    text NOT NULL,
  latency_ms          real,
  "timestamp"         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, organization_id)
);

CREATE TABLE scan_results (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL,
  event_id         uuid NOT NULL,
  detections_meta  jsonb NOT NULL DEFAULT '[]'::jsonb,   -- entity/severity/confidence/location/digest ONLY
  risk_factors     jsonb NOT NULL DEFAULT '[]'::jsonb,
  FOREIGN KEY (event_id, organization_id) REFERENCES security_events(id, organization_id) ON DELETE CASCADE
);

CREATE TABLE audit_logs (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor_id         uuid,
  actor_type       text NOT NULL DEFAULT 'user' CHECK (actor_type IN ('user','api_key','system')),
  action           text NOT NULL,
  target           text,
  metadata         jsonb NOT NULL DEFAULT '{}'::jsonb,
  "timestamp"      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE files (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  sha256           text NOT NULL,
  mime             text NOT NULL,
  size_bytes       bigint NOT NULL CHECK (size_bytes >= 0),
  storage_key      text,                                 -- NULL unless org policy enables retention
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, organization_id)
);

CREATE TABLE file_scans (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL,
  file_id          uuid NOT NULL,
  verdict          text NOT NULL CHECK (verdict IN ('CLEAN','SANITIZED','BLOCKED','ERROR')),
  findings_meta    jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (file_id, organization_id) REFERENCES files(id, organization_id) ON DELETE CASCADE
);

CREATE TABLE usage (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  day              date NOT NULL,
  provider         text NOT NULL,
  requests         bigint NOT NULL DEFAULT 0,
  blocked          bigint NOT NULL DEFAULT 0,
  sanitized        bigint NOT NULL DEFAULT 0,
  UNIQUE (organization_id, day, provider)
);

CREATE TABLE evaluation_runs (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id   uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  dataset_version   text NOT NULL,
  critical_total    integer NOT NULL,
  critical_failed   integer NOT NULL,
  metrics           jsonb NOT NULL,
  ran_at            timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- indexes
CREATE INDEX users_org_idx                ON users (organization_id);
CREATE INDEX api_keys_org_idx             ON api_keys (organization_id);
CREATE INDEX policies_org_idx             ON policies (organization_id);
CREATE INDEX security_events_org_ts_idx   ON security_events (organization_id, "timestamp" DESC);
CREATE INDEX security_events_user_idx     ON security_events (user_id);
CREATE INDEX security_events_ts_idx       ON security_events ("timestamp");
CREATE INDEX security_events_risk_idx     ON security_events (organization_id, risk_level);
CREATE INDEX security_events_type_idx     ON security_events (organization_id, event_type);
CREATE INDEX audit_logs_org_ts_idx        ON audit_logs (organization_id, "timestamp" DESC);
CREATE INDEX usage_org_day_idx            ON usage (organization_id, day);

-- ---------------------------------------------------------------- row-level security
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['users','teams','team_members','projects','api_keys','providers','models','policies',
      'policy_rules','security_events','scan_results','audit_logs','files','file_scans','usage','evaluation_runs']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (organization_id = app_org_id()) WITH CHECK (organization_id = app_org_id())', t);
  END LOOP;
END $$;

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON organizations USING (id = app_org_id()) WITH CHECK (id = app_org_id());

-- ---------------------------------------------------------------- privileges for the app role
GRANT USAGE ON SCHEMA public TO sentinel_app;
GRANT SELECT ON roles TO sentinel_app;
GRANT SELECT, UPDATE ON organizations TO sentinel_app;          -- creation goes through the privileged signup function
GRANT SELECT, INSERT, UPDATE, DELETE ON users, teams, team_members, projects, api_keys, providers, models,
      policies, policy_rules, files, file_scans, usage, evaluation_runs TO sentinel_app;
-- Append-only evidence: the app role can never rewrite or delete history.
GRANT SELECT, INSERT ON security_events, scan_results, audit_logs TO sentinel_app;
