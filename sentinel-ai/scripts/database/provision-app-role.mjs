#!/usr/bin/env node
// Creates (or updates) the LOGIN role the gateway connects as, and makes it a member of sentinel_app.
//
// Why this exists: PostgreSQL skips row-level security for superusers, BYPASSRLS roles and table owners. The owner/superuser
// that runs migrations must therefore never be the role the gateway uses, or tenant isolation silently switches off. The
// gateway checks this at startup and refuses to run in production if it is violated.
//
//   DATABASE_URL=postgresql://<owner>:...@host/db  APP_DB_USER=sentinel_api  APP_DB_PASSWORD=...  \
//     node scripts/database/provision-app-role.mjs
//
// The password is read from the environment only and never printed. Must run AFTER migrations (sentinel_app must exist).
import pg from "pg";

const url = process.env.DATABASE_URL;
const user = process.env.APP_DB_USER ?? "sentinel_api";
const password = process.env.APP_DB_PASSWORD;
if (!url) { console.error("DATABASE_URL (owner role) is required"); process.exit(2); }
if (!password || password.length < 16) { console.error("APP_DB_PASSWORD (>= 16 chars) is required"); process.exit(2); }
if (!/^[a-z_][a-z0-9_]{0,62}$/.test(user)) { console.error("APP_DB_USER must be a plain lower-case identifier"); process.exit(2); }

const client = new pg.Client({ connectionString: url });
await client.connect();
try {
  await client.query("BEGIN");
  await client.query("SELECT pg_advisory_xact_lock($1)", [7_406_252_615]);   // same key as migrate-pg.mjs: never concurrent
  const exists = (await client.query("SELECT 1 FROM pg_roles WHERE rolname = $1", [user])).rowCount > 0;
  // Identifiers cannot be bound as parameters; `user` is validated above. The password is passed through a literal built
  // by the server-side quote_literal to avoid any client-side quoting.
  const lit = (await client.query("SELECT quote_literal($1) AS l", [password])).rows[0].l;
  await client.query(`${exists ? "ALTER" : "CREATE"} ROLE "${user}" LOGIN PASSWORD ${lit} NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE INHERIT`);
  await client.query(`GRANT sentinel_app TO "${user}"`);
  // Read-only view of which migrations are applied, so application pods can wait for the schema they ship with
  // (wait-for-schema.mjs) without ever holding the owner's credentials.
  await client.query("GRANT SELECT ON schema_migrations TO sentinel_app");
  await client.query("COMMIT");
  console.log(`${exists ? "updated" : "created"} login role ${user} (member of sentinel_app, NOSUPERUSER NOBYPASSRLS)`);
} catch (err) {
  await client.query("ROLLBACK").catch(() => undefined);
  console.error(`provisioning failed: ${err.message}`);
  process.exit(1);
} finally {
  await client.end();
}
