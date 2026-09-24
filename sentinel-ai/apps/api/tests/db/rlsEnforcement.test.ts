import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checkRlsEnforced } from "../../src/db/tenantDb.js";
import { createMigratedDb, seedTwoOrgs, type TestDb } from "../helpers/testDb.js";

/**
 * The gateway refuses to start in production unless RLS applies to its database role. These tests pin down exactly which
 * roles PostgreSQL exempts from RLS, and prove the check agrees with what the database actually does (the rows visible).
 * Runs on PGlite and, with SENTINEL_TEST_DATABASE_URL, on a real server.
 */
let db: TestDb;
let orgA: string;
const created: string[] = [];

beforeAll(async () => {
  db = await createMigratedDb({ allowRealServer: true });
  ({ orgA } = await seedTwoOrgs(db));
});
afterAll(async () => {
  await db.exec("RESET ROLE");
  for (const r of created) await db.exec(`DROP ROLE IF EXISTS ${r}`).catch(() => undefined);
  await db.close();
});

/** Roles are cluster-wide on a real server, so every test role gets a unique name. */
async function role(attrs: string, grantApp: boolean): Promise<string> {
  const name = `rls_${randomUUID().replace(/-/g, "").slice(0, 10)}`;
  await db.exec(`CREATE ROLE ${name} NOLOGIN ${attrs}`);
  if (grantApp) await db.exec(`GRANT sentinel_app TO ${name}`);
  created.push(name);
  return name;
}

async function as<T>(name: string | null, fn: () => Promise<T>): Promise<T> {
  await db.exec(name ? `SET ROLE ${name}` : "RESET ROLE");
  try { return await fn(); } finally { await db.exec("RESET ROLE"); }
}

/** Ground truth: how many api_keys rows the role can see with NO tenant set. RLS enforced => 0. */
async function visibleWithoutTenant(name: string): Promise<number> {
  return as(name, async () => {
    await db.query("SELECT set_config('app.org_id', '', false)");
    return (await db.query<{ n: number }>("SELECT count(*)::int AS n FROM api_keys")).rows[0]!.n;
  });
}

describe("checkRlsEnforced agrees with what PostgreSQL actually does", () => {
  it("the migration owner (superuser) is NOT subject to RLS - and the check says so", async () => {
    const s = await as(null, () => checkRlsEnforced(db));
    expect(s.enforced).toBe(false);
    expect(s.reason).toMatch(/superuser|owns/);
    // ground truth: without any tenant the owner still sees every organization's keys
    expect((await db.query<{ n: number }>("SELECT count(*)::int AS n FROM api_keys")).rows[0]!.n).toBeGreaterThan(0);
  });

  it("a login role that is a member of sentinel_app IS subject to RLS", async () => {
    const r = await role("NOSUPERUSER NOBYPASSRLS INHERIT", true);
    expect(await as(r, () => checkRlsEnforced(db))).toEqual({ enforced: true, role: r, reason: null });
    expect(await visibleWithoutTenant(r)).toBe(0);
  });

  it("the same role scoped to one organization sees only that organization", async () => {
    const r = await role("NOSUPERUSER NOBYPASSRLS INHERIT", true);
    const orgs = await as(r, async () => {
      await db.query("SELECT set_config('app.org_id', $1, false)", [orgA]);
      return (await db.query<{ o: string }>("SELECT DISTINCT organization_id AS o FROM api_keys")).rows.map((x) => x.o);
    });
    expect(orgs).toEqual([orgA]);
  });

  it("a BYPASSRLS role is reported as NOT enforced (and really does see everything)", async () => {
    const r = await role("NOSUPERUSER BYPASSRLS INHERIT", true);
    const s = await as(r, () => checkRlsEnforced(db));
    expect(s.enforced).toBe(false);
    expect(s.reason).toMatch(/BYPASSRLS/);
    expect(await visibleWithoutTenant(r)).toBeGreaterThan(0);
  });

  it("a role without sentinel_app is reported as not usable (it has no application grants)", async () => {
    const r = await role("NOSUPERUSER NOBYPASSRLS", false);
    const s = await as(r, () => checkRlsEnforced(db));
    expect(s.enforced).toBe(false);
    expect(s.reason).toMatch(/not a member of sentinel_app/);
  });

  it("sentinel_app itself (what assumeRole switches to) is enforced", async () => {
    expect((await as("sentinel_app", () => checkRlsEnforced(db))).enforced).toBe(true);
  });
});
