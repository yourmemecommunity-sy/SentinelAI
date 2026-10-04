import type { TestDb } from "../helpers/testDb.js";
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { asTenant, createMigratedDb, seedTwoOrgs } from "../helpers/testDb.js";

const TENANT_TABLES = ["users", "teams", "team_members", "projects", "api_keys", "providers", "models", "policies",
  "policy_rules", "security_events", "scan_results", "audit_logs", "files", "file_scans", "usage", "evaluation_runs", "red_team_rounds"];
const SEEDED = ["users", "teams", "projects", "api_keys", "providers", "policies", "policy_rules", "security_events",
  "audit_logs", "usage"];

let db: TestDb;
let orgA: string;
let orgB: string;

beforeAll(async () => {
  db = await createMigratedDb({ allowRealServer: true });
  ({ orgA, orgB } = await seedTwoOrgs(db));
});
afterAll(async () => { await db.close(); });

describe("schema-level guarantees", () => {
  it("every table with an organization_id column has RLS enabled and a tenant policy", async () => {
    const { rows } = await db.query<{ table_name: string; rls: boolean; policies: number }>(`
      SELECT c.relname AS table_name, c.relrowsecurity AS rls,
             (SELECT count(*)::int FROM pg_policies p WHERE p.tablename = c.relname) AS policies
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r'
        AND EXISTS (SELECT 1 FROM information_schema.columns col
                    WHERE col.table_name = c.relname AND col.table_schema = 'public' AND col.column_name = 'organization_id')`);
    const names = rows.map((r) => r.table_name);
    for (const t of TENANT_TABLES) expect(names).toContain(t);
    for (const r of rows) {
      expect(r.rls, `RLS disabled on ${r.table_name}`).toBe(true);
      expect(r.policies, `no policy on ${r.table_name}`).toBeGreaterThan(0);
    }
  });

  it("required indexes exist on security_events", async () => {
    const { rows } = await db.query<{ indexdef: string }>("SELECT indexdef FROM pg_indexes WHERE tablename = 'security_events'");
    const defs = rows.map((r) => r.indexdef).join("\n");
    for (const col of ["organization_id", "user_id", "timestamp", "risk_level", "event_type"]) expect(defs).toContain(col);
  });
});

describe("tenant isolation (RLS, as the application role)", () => {
  it.each(SEEDED)("reads on %s only ever return the caller's organization", async (table) => {
    for (const [me, other] of [[orgA, orgB], [orgB, orgA]] as const) {
      const rows = await asTenant<{ organization_id: string }[]>(db, me, `SELECT organization_id FROM ${table}`);
      expect(rows.length).toBeGreaterThan(0);
      expect(rows.every((r) => r.organization_id === me)).toBe(true);
      expect(rows.some((r) => r.organization_id === other)).toBe(false);
    }
  });

  it.each(TENANT_TABLES)("fails closed on %s when no organization is set", async (table) => {
    expect(await asTenant(db, null, `SELECT 1 FROM ${table}`)).toHaveLength(0);
  });

  it("a tenant sees only its own organization row", async () => {
    const rows = await asTenant<{ id: string }[]>(db, orgA, "SELECT id FROM organizations");
    expect(rows.map((r) => r.id)).toEqual([orgA]);
  });

  it("cannot insert rows for another organization", async () => {
    await expect(asTenant(db, orgA, "INSERT INTO teams (organization_id, name) VALUES ($1, 'evil')", [orgB])).rejects.toThrow(/row-level security/);
  });

  it("cannot update or delete another organization's rows (0 rows affected)", async () => {
    await asTenant(db, orgA, "UPDATE policies SET active = false WHERE organization_id = $1", [orgB]);
    await asTenant(db, orgA, "DELETE FROM users WHERE organization_id = $1", [orgB]);
    expect((await asTenant(db, orgB, "SELECT 1 FROM policies WHERE active"))).toHaveLength(1);
    expect((await asTenant(db, orgB, "SELECT 1 FROM users"))).toHaveLength(1);
  });

  it("cannot move a row into another organization by updating organization_id", async () => {
    await expect(asTenant(db, orgA, "UPDATE teams SET organization_id = $1", [orgB])).rejects.toThrow();
  });

  it("a malformed org context errors instead of leaking", async () => {
    await expect(asTenant(db, "not-a-uuid", "SELECT * FROM users")).rejects.toThrow();
  });

  it("composite foreign keys forbid cross-tenant references, even for the owner role", async () => {
    const [polB] = (await db.query<{ id: string }>("SELECT id FROM policies WHERE organization_id = $1", [orgB])).rows;
    await expect(db.query(
      "INSERT INTO policy_rules (organization_id, policy_pk, position, entity, action) VALUES ($1,$2,9,'PHONE','MASK')",
      [orgA, polB!.id])).rejects.toThrow(/foreign key/);
  });
});

describe("evidence integrity and policy floors", () => {
  it("security_events and audit_logs are append-only for the application role", async () => {
    for (const t of ["security_events", "audit_logs"]) {
      await expect(asTenant(db, orgA, `UPDATE ${t} SET organization_id = organization_id`)).rejects.toThrow(/permission denied/);
      await expect(asTenant(db, orgA, `DELETE FROM ${t}`)).rejects.toThrow(/permission denied/);
    }
  });

  it("the database refuses to store an ALLOW rule for credentials/threats or CRITICAL severity", async () => {
    const [pol] = await asTenant<{ id: string }[]>(db, orgA, "SELECT id FROM policies");
    for (const [entity, severity] of [["API_KEY", null], ["CREDIT_CARD", null], ["PROMPT_INJECTION", null], ["EMAIL", "CRITICAL"]]) {
      await expect(asTenant(db, orgA,
        "INSERT INTO policy_rules (organization_id, policy_pk, position, entity, action, severity) VALUES ($1,$2,100,$3,'ALLOW',$4)",
        [orgA, pol!.id, entity, severity])).rejects.toThrow(/policy_rules_no_unsafe_allow/);
    }
    // ...but a sanitizing rule for the same entity is fine.
    await asTenant(db, orgA, "INSERT INTO policy_rules (organization_id, policy_pk, position, entity, action) VALUES ($1,$2,101,'CREDIT_CARD','TOKENIZE')", [orgA, pol!.id]);
  });

  it("only one active version per policy id", async () => {
    await expect(db.query("INSERT INTO policies (organization_id, policy_id, version, active) VALUES ($1,'p',2,true)", [orgA])).rejects.toThrow(/policies_one_active|duplicate key/);
  });
});

describe("pre-tenant lookups (SECURITY DEFINER)", () => {
  it("app_find_api_key resolves a key by exact prefix without an org context, and returns nothing otherwise", async () => {
    const found = await asTenant<{ organization_id: string; role: string }[]>(db, null, "SELECT * FROM app_find_api_key('sk_test_a000')");
    expect(found).toHaveLength(1);
    expect(found[0]!.organization_id).toBe(orgA);
    expect(await asTenant(db, null, "SELECT * FROM app_find_api_key('nonexistent0')")).toHaveLength(0);
    expect(await asTenant(db, null, "SELECT * FROM app_find_api_key('%')")).toHaveLength(0);
  });

  it("the app role cannot read api_keys directly without a tenant, and PUBLIC cannot call the lookups", async () => {
    expect(await asTenant(db, null, "SELECT key_hash FROM api_keys")).toHaveLength(0);
    // Roles are cluster-wide, not per-database, so on a real server this must not collide with an earlier run.
    const stranger = `stranger_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
    await db.exec(`CREATE ROLE ${stranger} NOLOGIN`);
    try {
      await db.exec(`SET ROLE ${stranger}`);
      await expect(db.query("SELECT * FROM app_find_login('a@example.com')")).rejects.toThrow(/permission denied/);
    } finally {
      await db.exec("RESET ROLE");
      await db.exec(`DROP ROLE IF EXISTS ${stranger}`);
    }
  });

  it("app_signup_organization creates an organization and OWNER atomically", async () => {
    const [r] = await asTenant<{ organization_id: string; user_id: string }[]>(db, null,
      "SELECT * FROM app_signup_organization('New Co','new-co','Boss@Example.com','hash')");
    const [u] = await asTenant<{ email: string; role: string }[]>(db, r!.organization_id,
      "SELECT email, (SELECT name FROM roles WHERE id = role_id) AS role FROM users");
    expect(u).toEqual({ email: "boss@example.com", role: "OWNER" });
    const [login] = await asTenant<{ role: string }[]>(db, null, "SELECT * FROM app_find_login('BOSS@example.com')");
    expect(login!.role).toBe("OWNER");
  });
});
