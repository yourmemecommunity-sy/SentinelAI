# Task 3 — Real PostgreSQL

Run: **2026-09-26 07:49 UTC** against **PostgreSQL 18.6** running natively in WSL2 (not PGlite).

| Check | Result |
|---|---|
| Migrations on a brand-new database | **All 8 applied** (`0001`–`0008`; the task named `0001`–`0006`, the repository now has 8), exit 0 |
| Re-running the runner | `already up to date` (idempotent), exit 0 |
| Checksums recorded | 8 rows in `schema_migrations` with SHA-256 per file |
| RLS enabled | on every tenant table (`roles` and `schema_migrations` are global by design); `FORCE` is not used — the gateway runs as a non-owner role and refuses to start on one that would bypass RLS (`rlsEnforcement.test.ts`) |
| Full DB suite on this server | **130 passed, 0 failed, 0 skipped** |
| Tenant-isolation suite | **40 / 40 passed** (names below) |

Commands: `DATABASE_URL=… node scripts/database/migrate-pg.mjs` (run from the built API image) and
`SENTINEL_TEST_DATABASE_URL=postgresql://…@127.0.0.1:5432/sentinel npx vitest run tests/db` (in `apps/api`).
```
# STEP 3 - Real PostgreSQL  (2026-09-26T07:49:01Z)
server: PostgreSQL 18.6 (Ubuntu 18.6-0ubuntu0.26.04.1) on x86_64-pc- (WSL-native PostgreSQL, not PGlite)

## Migrations on a brand-new database
NOTICE:  database "sentinel_migration_check" does not exist, skipping
$ node scripts/database/migrate-pg.mjs   (first run)
applied 0001_init.sql
applied 0002_auth_lookup.sql
applied 0003_events_api_key.sql
applied 0004_refresh_tokens.sql
applied 0005_api_key_last_used.sql
applied 0006_admin_evaluation_permission.sql
applied 0007_file_scan_events.sql
applied 0008_users_teams_providers.sql
applied 8 migration(s)
[exit 0]
$ node scripts/database/migrate-pg.mjs   (second run: must be a no-op)
already up to date
[exit 0]

## Applied migrations recorded by the runner
                List of tables
 Schema |       Name        | Type  |  Owner   
--------+-------------------+-------+----------
 public | api_keys          | table | sentinel
 public | audit_logs        | table | sentinel
 public | evaluation_runs   | table | sentinel
 public | file_scans        | table | sentinel
 public | files             | table | sentinel
 public | invitations       | table | sentinel
 public | models            | table | sentinel
 public | organizations     | table | sentinel
 public | policies          | table | sentinel
 public | policy_rules      | table | sentinel
 public | projects          | table | sentinel
 public | providers         | table | sentinel
 public | refresh_tokens    | table | sentinel
 public | roles             | table | sentinel
 public | scan_results      | table | sentinel
 public | schema_migrations | table | sentinel
 public | security_events   | table | sentinel
 public | team_members      | table | sentinel
 public | teams             | table | sentinel
 public | usage             | table | sentinel
 public | users             | table | sentinel
(21 rows)

                 name                 |                             checksum                             |          appl
--------------------------------------+------------------------------------------------------------------+--------------
 0001_init.sql                        | 342fde3b1346b9788923561386243bda386d82acefd1e338b7889533e41ee30f | 2026-09-26 07
 0002_auth_lookup.sql                 | ecf1e86a7231accd1f286e7b0c85493012bb01f02dc8f59280c6a6c657c4144b | 2026-09-26 07
 0003_events_api_key.sql              | 46ecf2e636ad2be44171e7b2bc186f9bb20c987a0af719908ec0062ac5bb3378 | 2026-09-26 07
 0004_refresh_tokens.sql              | 49e777bdf5177ba2383d88963d3b9ee1015abbe72b6b828ef9618ca26cbda16f | 2026-09-26 07
 0005_api_key_last_used.sql           | f5a24b2ac0bddcd387466e9c73216beccf73e32878759f7861ca7e12c817ef02 | 2026-09-26 07
 0006_admin_evaluation_permission.sql | 2c499366b0deba0f3a7e90be02171486b829d0cfc74624a8f8b12cd6da4a862f | 2026-09-26 07
 0007_file_scan_events.sql            | e497c730f158d1f0f3aa1146e470e860c9b9061b57d6ee6a57f31caa19ef4e8b | 2026-09-26 07
 0008_users_teams_providers.sql       | 99070fecc88f39a44b251f48d1ac98c0d601710221fef952627b4a486720bb55 | 2026-09-26 07
(8 rows)


## Row-level security enabled per table
      relname      | rls | forced 
-------------------+-----+--------
 api_keys          | t   | f
 audit_logs        | t   | f
 evaluation_runs   | t   | f
 file_scans        | t   | f
 files             | t   | f
 invitations       | t   | f
 models            | t   | f
 organizations     | t   | f
 policies          | t   | f
 policy_rules      | t   | f
 projects          | t   | f
 providers         | t   | f
 refresh_tokens    | t   | f
 roles             | f   | f
 scan_results      | t   | f
 schema_migrations | f   | f
 security_events   | t   | f
 team_members      | t   | f
 teams             | t   | f
 usage             | t   | f
 users             | t   | f
(21 rows)


## Full DB test suite on this server (incl. the tenant-isolation suite)
vitest tests/db -> exit 0
TOTAL tests=130 passed=130 failed=0 skipped=0
  db/apiKeyManagement.test.ts              {'passed': 19}
  db/authFlow.test.ts                      {'passed': 17}
  db/directory.test.ts                     {'passed': 15}
  db/migrations.test.ts                    {'passed': 3}
  db/providerCredentials.test.ts           {'passed': 15}
  db/repositories.test.ts                  {'passed': 15}
  db/rlsEnforcement.test.ts                {'passed': 6}
  db/tenantIsolation.test.ts               {'passed': 40}

## Tenant-isolation test names (first 40 lines)
 ✓ tests/db/tenantIsolation.test.ts > schema-level guarantees > every table with an organization_id column has RLS enabled and a tenant policy
 ✓ tests/db/tenantIsolation.test.ts > schema-level guarantees > required indexes exist on security_events
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > reads on users only ever return the caller's organization
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > reads on teams only ever return the caller's organization
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > reads on projects only ever return the caller's organization
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > reads on api_keys only ever return the caller's organization
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > reads on providers only ever return the caller's organization
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > reads on policies only ever return the caller's organization
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > reads on policy_rules only ever return the caller's organization
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > reads on security_events only ever return the caller's organization
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > reads on audit_logs only ever return the caller's organization
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > reads on usage only ever return the caller's organization
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on users when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on teams when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on team_members when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on projects when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on api_keys when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on providers when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on models when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on policies when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on policy_rules when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on security_events when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on scan_results when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on audit_logs when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on files when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on file_scans when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on usage when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > fails closed on evaluation_runs when no organization is set
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > a tenant sees only its own organization row
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > cannot insert rows for another organization
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > cannot update or delete another organization's rows (0 rows affected)
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > cannot move a row into another organization by updating organization_id
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > a malformed org context errors instead of leaking
 ✓ tests/db/tenantIsolation.test.ts > tenant isolation (RLS, as the application role) > composite foreign keys forbid cross-tenant references, even for the owner role
 ✓ tests/db/tenantIsolation.test.ts > evidence integrity and policy floors > security_events and audit_logs are append-only for the application role
 ✓ tests/db/tenantIsolation.test.ts > evidence integrity and policy floors > the database refuses to store an ALLOW rule for credentials/threats or CRITICAL severity
 ✓ tests/db/tenantIsolation.test.ts > evidence integrity and policy floors > only one active version per policy id
 ✓ tests/db/tenantIsolation.test.ts > pre-tenant lookups (SECURITY DEFINER) > app_find_api_key resolves a key by exact prefix without an org context, and returns nothin
 ✓ tests/db/tenantIsolation.test.ts > pre-tenant lookups (SECURITY DEFINER) > the app role cannot read api_keys directly without a tenant, and PUBLIC cannot call the lo
 ✓ tests/db/tenantIsolation.test.ts > pre-tenant lookups (SECURITY DEFINER) > app_signup_organization creates an organization and OWNER atomically
```
