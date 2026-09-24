import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";

const MIGRATIONS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../scripts/database/migrations");

/**
 * Set SENTINEL_TEST_DATABASE_URL to run the database suites against a REAL PostgreSQL server (see
 * scripts/development/wsl-infra.sh). Each call then creates a fresh, isolated database on that server and applies the
 * migrations to it, so the same tests prove the same guarantees on real Postgres. Without it, PGlite is used: fast and
 * in-process, but not a real server.
 */
export const REAL_DATABASE_URL = process.env.SENTINEL_TEST_DATABASE_URL;
export const USING_REAL_POSTGRES = !!REAL_DATABASE_URL;   // true only for suites that opt in via allowRealServer

/** The subset of the PGlite surface the tests use, so a real-Postgres adapter can stand in for it. */
export interface TestDb {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
  exec(sql: string): Promise<unknown>;
  transaction<T>(fn: (tx: TestDb) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

/**
 * node-postgres adapter with PGlite's shape, backed by a POOL.
 *
 * A pool, not one shared connection: `SET LOCAL ROLE` and `set_config('app.org_id', ..., true)` are transaction-scoped, so two
 * overlapping transactions on a single connection would interleave and one tenant's scope could apply to another's query. That is
 * exactly how production's PgTenantDb behaves (a connection per transaction), and a shared-connection adapter produced a false
 * cross-tenant failure until this was fixed.
 */
class PgTestDb implements TestDb {
  constructor(private readonly pool: import("pg").Pool, private readonly dbName: string | null, private readonly adminUrl: string) {}

  async query<T = Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<{ rows: T[] }> {
    return { rows: (await this.pool.query(sql, params)).rows as T[] };
  }
  async exec(sql: string): Promise<unknown> { return this.pool.query(sql); }

  async transaction<T>(fn: (tx: TestDb) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    const scoped: TestDb = {
      query: async <R = Record<string, unknown>>(sql: string, params: unknown[] = []) => ({ rows: (await client.query(sql, params)).rows as R[] }),
      exec: (sql: string) => client.query(sql),
      transaction: (inner) => inner(scoped),          // already inside one
      close: async () => undefined,
    };
    try {
      await client.query("BEGIN");
      const out = await fn(scoped);
      await client.query("COMMIT");
      return out;
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
    if (!this.dbName) return;
    const pg = await import("pg");
    const admin = new pg.default.Client({ connectionString: this.adminUrl });
    await admin.connect();
    try { await admin.query(`DROP DATABASE IF EXISTS "${this.dbName}" WITH (FORCE)`); } finally { await admin.end(); }
  }
}

const MIGRATION_SQL = (): string[] =>
  readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort().map((f) => readFileSync(join(MIGRATIONS_DIR, f), "utf8"));

/**
 * Fresh Postgres with every migration applied (connected as the owner/superuser role).
 *
 * `allowRealServer` is opt-in per suite: only the database-semantics suites (tests/db) target a real server, because they are
 * what real Postgres actually proves. The service e2e suites keep PGlite - pointing them at a networked server adds an hour of
 * round trips and makes timing-sensitive tests (kill-the-engine, PDF parsing) flake without testing anything new about Postgres.
 */
export async function createMigratedDb(opts: { allowRealServer?: boolean } = {}): Promise<TestDb> {
  if (REAL_DATABASE_URL && opts.allowRealServer) {
    const pg = await import("pg");
    const name = `sentinel_test_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const admin = new pg.default.Client({ connectionString: REAL_DATABASE_URL });
    await admin.connect();
    try { await admin.query(`CREATE DATABASE "${name}"`); } finally { await admin.end(); }

    const url = new URL(REAL_DATABASE_URL);
    url.pathname = `/${name}`;
    const pool = new pg.default.Pool({ connectionString: url.toString(), max: 10 });
    for (const sql of MIGRATION_SQL()) await pool.query(sql);
    return new PgTestDb(pool, name, REAL_DATABASE_URL);
  }
  const db = new PGlite();
  for (const sql of MIGRATION_SQL()) await db.exec(sql);
  return db as unknown as TestDb;
}

export type Rows = Record<string, unknown>[];

/** Run SQL as the RLS-restricted application role scoped to one organization (or none). */
export async function asTenant<T = Rows>(
  db: TestDb, orgId: string | null, sql: string, params: unknown[] = [],
): Promise<T> {
  await db.exec("RESET ROLE; SET ROLE sentinel_app");
  try {
    await db.query("SELECT set_config('app.org_id', $1, false)", [orgId ?? ""]);
    return (await db.query(sql, params)).rows as T;
  } finally {
    await db.exec("RESET ROLE");
    await db.exec("RESET app.org_id");
  }
}

export async function seedTwoOrgs(db: TestDb) {
  const one = async (sql: string, p: unknown[] = []) => ((await db.query(sql, p)).rows[0] as Record<string, string>);
  const orgA = (await one("INSERT INTO organizations (name, slug) VALUES ('Org A','org-a') RETURNING id")).id!;
  const orgB = (await one("INSERT INTO organizations (name, slug) VALUES ('Org B','org-b') RETURNING id")).id!;
  const role = (await one("SELECT id FROM roles WHERE name = 'DEVELOPER'")).id!;
  const seed = async (org: string, tag: string) => {
    const user = (await one(
      "INSERT INTO users (organization_id, email, password_hash, role_id) VALUES ($1,$2,'x',$3) RETURNING id",
      [org, `${tag}@example.com`, role])).id!;
    await db.query("INSERT INTO teams (organization_id, name) VALUES ($1,$2)", [org, `team-${tag}`]);
    await db.query("INSERT INTO projects (organization_id, name) VALUES ($1,$2)", [org, `proj-${tag}`]);
    await db.query(
      "INSERT INTO api_keys (organization_id, name, prefix, key_hash, role_id) VALUES ($1,$2,$3,$4,$5)",
      [org, `key-${tag}`, `sk_test_${tag}`.padEnd(12, "0").slice(0, 12), `hash-${tag}`, role]);
    await db.query("INSERT INTO providers (organization_id, provider_type) VALUES ($1,'gemini')", [org]);
    const pol = (await one(
      "INSERT INTO policies (organization_id, policy_id, version, active) VALUES ($1,'p',1,true) RETURNING id", [org])).id!;
    await db.query(
      "INSERT INTO policy_rules (organization_id, policy_pk, position, entity, action) VALUES ($1,$2,0,'EMAIL','MASK')", [org, pol]);
    await db.query(
      `INSERT INTO security_events (organization_id, user_id, request_id, direction, event_type, risk_level, risk_score, action, policy_id, detector_version)
       VALUES ($1,$2,$3,'INPUT','scan','LOW',1,'ALLOW','p','v')`, [org, user, `req-${tag}`]);
    await db.query("INSERT INTO audit_logs (organization_id, action) VALUES ($1,'seed')", [org]);
    await db.query("INSERT INTO usage (organization_id, day, provider) VALUES ($1, current_date, 'gemini')", [org]);
  };
  await seed(orgA, "a");
  await seed(orgB, "b");
  return { orgA, orgB };
}
