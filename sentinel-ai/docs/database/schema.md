# Database Schema Notes

Migrations `0001-0006` are implemented (`scripts/database/migrations`, runner `scripts/database/migrate.mjs`, checksummed, transactional). Verified on PGlite; not yet run against a real PostgreSQL server.

Also: `refresh_tokens` (migration 0004; hashed, RLS, family-based revocation).

Tables: organizations, users, roles, teams, api_keys, providers, models, policies, policy_rules, security_events, scan_results,
audit_logs, files, file_scans, projects, usage, evaluation_runs (see [ERD](erd.md)).

## Rules
- Every tenant-owned table has `organization_id uuid NOT NULL REFERENCES organizations(id)`; composite FKs include it so a child row cannot point at another tenant's parent.
- **Roles.** Migrations run as the *owner* role (bypasses RLS; needed by the `SECURITY DEFINER` functions). The application connects as a member of `sentinel_app`, which is subject to RLS. Never use the owner role as the app login.
- **Pre-tenant lookups** (`app_find_api_key`, `app_find_login`, `app_signup_organization`) are `SECURITY DEFINER`, exact-match, minimum-column functions; `EXECUTE` is revoked from PUBLIC.
- **DB-level policy floor:** the `policy_rules_no_unsafe_allow` CHECK rejects `ALLOW` for credentials, cards, threat entities and CRITICAL severity even if the application is bypassed (kept in sync with the engine and TS lists by a contract test).
- **Row-level security** enabled on all tenant tables with `organization_id = current_setting('app.org_id')::uuid`; the gateway sets it per transaction (`SET LOCAL`). With no org set, no rows are visible or writable. `apps/api/tests/db/tenantIsolation.test.ts` proves cross-tenant reads, inserts, updates, deletes and FK references fail, and a meta-test fails if any table with `organization_id` lacks RLS.
- `api_keys.key_hash` = HMAC-SHA256(pepper, key); only a short prefix is stored for identification. `users.password_hash` = Argon2id.
- `providers.credentials_encrypted` = envelope-encrypted per organization (KMS-backed key in cloud; env key in dev).
- **No content columns.** `security_events` stores entity *types*, counts, risk, action, policy id, detector version; never values.
- Retention: a scheduled job deletes `security_events`/`audit_logs` older than `organizations.audit_retention_days`; `zero_retention` skips event-row persistence.

## Required indexes
`organization_id`, `user_id`, `timestamp`, `risk_level`, `event_type` on `security_events` (composite `(organization_id, timestamp DESC)` first);
`(organization_id, policy_id, version)` unique on `policies`; `key_hash` unique on `api_keys`.
