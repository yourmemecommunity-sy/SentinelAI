#!/usr/bin/env node
// SentinelAI migration runner. Applies scripts/database/migrations/*.sql in filename order, each in one
// transaction, recording a SHA-256 checksum. Re-running is a no-op; editing an already-applied migration is an error
// (write a new migration instead).
//
// Usage: DATABASE_URL=postgresql://owner:...@host/db node scripts/database/migrate.mjs
// DATABASE_URL must be the OWNER role, not the application role (see 0001_init.sql).
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "migrations");

/**
 * @param {{ exec: (sql: string) => Promise<unknown>, query: (sql: string, params?: unknown[]) => Promise<{ rows: any[] }> }} db
 * @returns {Promise<string[]>} names of migrations applied by this call
 */
export async function runMigrations(db, dir = DEFAULT_DIR, log = () => {}) {
  await db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
    name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`);
  const applied = [];
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) {
    const sql = readFileSync(join(dir, file), "utf8");
    const checksum = createHash("sha256").update(sql).digest("hex");
    const { rows } = await db.query("SELECT checksum FROM schema_migrations WHERE name = $1", [file]);
    if (rows.length > 0) {
      if (rows[0].checksum !== checksum) throw new Error(`migration ${file} was modified after being applied; add a new migration instead`);
      continue;
    }
    await db.exec("BEGIN");
    try {
      await db.exec(sql);
      await db.query("INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)", [file, checksum]);
      await db.exec("COMMIT");
    } catch (err) {
      await db.exec("ROLLBACK");
      throw new Error(`migration ${file} failed: ${err.message}`);
    }
    log(`applied ${file}`);
    applied.push(file);
  }
  return applied;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const url = process.env.DATABASE_URL;
  if (!url) { console.error("DATABASE_URL is required"); process.exit(1); }
  const { default: pg } = await import("pg");
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    const applied = await runMigrations({ exec: (s) => client.query(s), query: (s, p) => client.query(s, p) }, DEFAULT_DIR, console.log);
    console.log(applied.length ? `done: ${applied.length} migration(s) applied` : "up to date");
  } catch (err) {
    console.error(err.message);
    process.exitCode = 1;
  } finally {
    await client.end();
  }
}
