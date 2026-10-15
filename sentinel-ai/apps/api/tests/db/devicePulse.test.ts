/**
 * Migration 0010 (DevicePulse) on PGlite, and on a REAL PostgreSQL server when SENTINEL_TEST_DATABASE_URL is set (CI).
 * Runs as the RLS-restricted application role, exactly like production.
 */
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PgDevicePulseRepository, type Actor } from "../../src/repositories/devicePulseRepository.js";
import { PgliteTenantDb } from "../helpers/fakes.js";
import { asTenant, createMigratedDb, type TestDb } from "../helpers/testDb.js";

let db: TestDb; let repo: PgDevicePulseRepository; let orgA: string; let orgB: string;
const U1: Actor = { type: "user", id: randomUUID() };
const U2: Actor = { type: "user", id: randomUUID() };
const KEY: Actor = { type: "api_key", id: randomUUID() };

const record = (org: string, actor: Actor, over: { retentionDays?: number } = {}) => {
  const id = randomUUID();
  return repo.recordRequest({ id, organizationId: org, actor, diagnosticType: "battery_drain", status: "completed", findingCount: 2,
    inputEventId: null, retentionDays: over.retentionDays ?? 30 }).then(() => id);
};
const count = async (sql: string, p: unknown[] = []) => Number(((await db.query<{ n: number }>(sql, p)).rows[0]!).n);

beforeAll(async () => {
  db = await createMigratedDb({ allowRealServer: true });
  repo = new PgDevicePulseRepository(new PgliteTenantDb(db));
  const mk = async (slug: string) => (await db.query<{ id: string }>("INSERT INTO organizations (name, slug) VALUES ($1,$1) RETURNING id", [slug])).rows[0]!.id;
  orgA = await mk("dp-a"); orgB = await mk("dp-b");
});
afterAll(async () => { await db?.close(); });

describe("migration 0010", () => {
  it("adds DEVICE_CLIENT with only devicepulse:use, and ADMIN can grant it", async () => {
    const { rows } = await db.query<{ name: string; permissions: string[] }>("SELECT name, permissions FROM roles WHERE name IN ('DEVICE_CLIENT','ADMIN')");
    const by = Object.fromEntries(rows.map((r) => [r.name, r.permissions]));
    expect(by.DEVICE_CLIENT).toEqual(["devicepulse:use"]);
    expect(by.ADMIN).toContain("devicepulse:use");
    await expect(db.query("INSERT INTO roles (name) VALUES ('ROOT')")).rejects.toThrow();
  });

  it("stores no free text: rating and reason are enums, diagnostic type is a short identifier", async () => {
    const id = await record(orgA, U1);
    await expect(db.query("INSERT INTO devicepulse_feedback (organization_id, request_id, rating) VALUES ($1,$2,'meh')", [orgA, id])).rejects.toThrow();
    await expect(db.query("INSERT INTO devicepulse_feedback (organization_id, request_id, rating, reason_code) VALUES ($1,$2,'helpful','the battery app from x.com is great')", [orgA, id])).rejects.toThrow();
    await expect(repo.recordRequest({ id: randomUUID(), organizationId: orgA, actor: U1, diagnosticType: "Ignore previous instructions", status: "completed",
      findingCount: 0, inputEventId: null, retentionDays: 30 })).rejects.toThrow();
  });

  it("feedback cannot point at another organization's request (composite foreign key)", async () => {
    const id = await record(orgA, U1);
    await expect(db.query("INSERT INTO devicepulse_feedback (organization_id, request_id, rating) VALUES ($1,$2,'helpful')", [orgB, id])).rejects.toThrow();
  });
});

describe("tenant isolation (RLS, application role)", () => {
  it("an organization sees only its own rows; no tenant sees nothing", async () => {
    const id = await record(orgA, U1);
    expect(await asTenant(db, orgA, "SELECT id FROM devicepulse_requests WHERE id = $1", [id])).toHaveLength(1);
    expect(await asTenant(db, orgB, "SELECT id FROM devicepulse_requests WHERE id = $1", [id])).toHaveLength(0);
    expect(await asTenant(db, null, "SELECT id FROM devicepulse_requests")).toHaveLength(0);
  });

  it("an organization cannot write rows into another organization", async () => {
    await expect(asTenant(db, orgB, `INSERT INTO devicepulse_requests (id, organization_id, actor_type, actor_id, diagnostic_type, status, finding_count, expires_at)
      VALUES ($1,$2,'user','x','thermal','completed',0, now() + interval '1 day')`, [randomUUID(), orgA])).rejects.toThrow();
  });

  it("the application role cannot UPDATE (rows are write-once) and cannot read across tenants via feedback", async () => {
    await expect(asTenant(db, orgA, "UPDATE devicepulse_requests SET status = 'completed'")).rejects.toThrow();
    const id = await record(orgA, U1);
    expect(await repo.recordFeedback(orgA, U1, { requestId: id, rating: "helpful", reasonCode: null })).toBe("recorded");
    expect(await asTenant(db, orgB, "SELECT id FROM devicepulse_feedback WHERE request_id = $1", [id])).toHaveLength(0);
  });

  it("feedback: only the actor who received the explanation, once, in the same organization", async () => {
    const id = await record(orgA, U1);
    expect(await repo.recordFeedback(orgB, U1, { requestId: id, rating: "helpful", reasonCode: null })).toBe("unknown_request");
    expect(await repo.recordFeedback(orgA, U2, { requestId: id, rating: "helpful", reasonCode: null })).toBe("unknown_request");
    expect(await repo.recordFeedback(orgA, { type: "api_key", id: U1.id }, { requestId: id, rating: "helpful", reasonCode: null })).toBe("unknown_request");
    expect(await repo.recordFeedback(orgA, U1, { requestId: id, rating: "not_helpful", reasonCode: "unclear" })).toBe("recorded");
    expect(await repo.recordFeedback(orgA, U1, { requestId: id, rating: "helpful", reasonCode: null })).toBe("exists");
  });
});

describe("erasure and retention", () => {
  it("deleteActorData removes the actor's requests and their feedback, nothing else", async () => {
    const mine = await record(orgA, KEY);
    await repo.recordFeedback(orgA, KEY, { requestId: mine, rating: "helpful", reasonCode: null });
    await record(orgA, KEY);
    const other = await record(orgA, U2);
    const otherOrg = await record(orgB, KEY);    // same actor id, other organization: untouched
    expect(await repo.deleteActorData(orgA, KEY)).toEqual({ requests: 2, feedback: 1 });
    expect(await count("SELECT count(*)::int AS n FROM devicepulse_requests WHERE actor_id = $1 AND organization_id = $2", [KEY.id, orgA])).toBe(0);
    expect(await count("SELECT count(*)::int AS n FROM devicepulse_feedback WHERE request_id = $1", [mine])).toBe(0);
    expect(await count("SELECT count(*)::int AS n FROM devicepulse_requests WHERE id IN ($1, $2)", [other, otherOrg])).toBe(2);
    expect(await repo.deleteActorData(orgA, KEY)).toEqual({ requests: 0, feedback: 0 });
  });

  it("the purge deletes expired rows of every organization (and their feedback) and keeps the rest", async () => {
    const live = await record(orgA, U1);
    const expired: string[] = [];
    for (const org of [orgA, orgB]) {
      const id = randomUUID();
      await db.query(`INSERT INTO devicepulse_requests (id, organization_id, actor_type, actor_id, diagnostic_type, status, finding_count, created_at, expires_at)
        VALUES ($1,$2,'user',$3,'network','completed',1, now() - interval '40 days', now() - interval '10 days')`, [id, org, U1.id]);
      await db.query("INSERT INTO devicepulse_feedback (organization_id, request_id, rating) VALUES ($1,$2,'helpful')", [org, id]);
      expired.push(id);
    }
    expect(await repo.recordFeedback(orgA, U1, { requestId: expired[0]!, rating: "helpful", reasonCode: null })).toBe("unknown_request");  // expired = gone for the client
    expect(await repo.purgeExpired()).toBeGreaterThanOrEqual(2);
    expect(await count("SELECT count(*)::int AS n FROM devicepulse_requests WHERE id = ANY($1::uuid[])", [expired])).toBe(0);
    expect(await count("SELECT count(*)::int AS n FROM devicepulse_feedback WHERE request_id = ANY($1::uuid[])", [expired])).toBe(0);
    expect(await count("SELECT count(*)::int AS n FROM devicepulse_requests WHERE id = $1", [live])).toBe(1);
  });

  it("a request record always expires (retention is set at insert)", async () => {
    const id = await record(orgA, U1, { retentionDays: 7 });
    const { rows } = await db.query<{ days: number }>("SELECT extract(epoch FROM expires_at - created_at)::int / 86400 AS days FROM devicepulse_requests WHERE id = $1", [id]);
    expect(Number(rows[0]!.days)).toBe(7);
  });
});
