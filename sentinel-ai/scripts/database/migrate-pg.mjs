#!/usr/bin/env node
// Applies the migrations to a REAL PostgreSQL server using node-postgres (migrate.mjs is driver-agnostic; this is the pg adapter).
//   DATABASE_URL=postgresql://sentinel:...@host:5432/sentinel node scripts/database/migrate-pg.mjs
// DATABASE_URL must be the OWNER role, not the application role.
import pg from "pg";
import { runMigrations } from "./migrate.mjs";

const url = process.env.DATABASE_URL;
if (!url) { console.error("DATABASE_URL is required"); process.exit(2); }

const client = new pg.Client({ connectionString: url });
await client.connect();
const db = {
  exec: (sql) => client.query(sql),
  query: async (sql, params = []) => ({ rows: (await client.query(sql, params)).rows }),
};
// One runner at a time, cluster-wide: Kubernetes Job retries, overlapping upgrades or two replicas starting together would
// otherwise race (both see a migration as pending; the loser fails half-way). Session-level advisory lock; released on
// disconnect even if this process dies.
export const MIGRATION_LOCK_KEY = 7_406_252_615;   // arbitrary constant shared with provision-app-role.mjs
try {
  await client.query("SELECT pg_advisory_lock($1)", [MIGRATION_LOCK_KEY]);
  const applied = await runMigrations(db, undefined, (m) => console.log(m));
  console.log(applied.length === 0 ? "already up to date" : `applied ${applied.length} migration(s)`);
} finally {
  await client.end();
}
