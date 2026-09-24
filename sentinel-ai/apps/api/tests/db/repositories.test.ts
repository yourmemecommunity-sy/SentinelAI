import type { TestDb } from "../helpers/testDb.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PgAuditLogWriter } from "../../src/events/auditLog.js";
import { PgEventSink, type SecurityEventInput } from "../../src/events/eventSink.js";
import { PgPolicyRepository } from "../../src/repositories/policyRepository.js";
import { DbApiKeyAuthenticator, createApiKey, hashApiKey } from "../../src/security/apiKeys.js";
import { ROLE_PERMISSIONS } from "../../src/security/rbac.js";
import { createMigratedDb } from "../helpers/testDb.js";
import { PgliteTenantDb, makeScan } from "../helpers/fakes.js";

const PEPPER = "x".repeat(40);
let db: TestDb; let tdb: PgliteTenantDb; let orgA: string; let orgB: string; let orgZero: string;

const event = (org: string, over: Partial<SecurityEventInput> = {}): SecurityEventInput => ({
  organizationId: org, userId: null, apiKeyId: null, requestId: "r1", application: "app", provider: "gemini", model: "m",
  direction: "INPUT", eventType: "ai_request", riskLevel: "HIGH", riskScore: 70, action: "REDACT", entityTypes: ["EMAIL"],
  policyId: "p@1", failedClosed: false, failClosedReason: null, detectorVersion: "v", latencyMs: 2.5,
  scan: makeScan("REDACT", { detections: [{ entity: "EMAIL", confidence: 0.9, severity: "MEDIUM", location: { start: 1, end: 5 }, detector: "pii", detector_version: "1", value_digest: "deadbeef" }] }),
  ...over,
});

beforeAll(async () => {
  db = await createMigratedDb({ allowRealServer: true }); tdb = new PgliteTenantDb(db);
  const mk = async (slug: string, zero: boolean) => ((await db.query<{ id: string }>("INSERT INTO organizations (name, slug, zero_retention) VALUES ($1,$1,$2) RETURNING id", [slug, zero])).rows[0]!.id);
  orgA = await mk("org-a", false); orgB = await mk("org-b", false); orgZero = await mk("org-zero", true);
});
afterAll(async () => { await db.close(); });

describe("RBAC map and database seed agree", () => {
  it("roles.permissions in the DB equals ROLE_PERMISSIONS in code", async () => {
    const { rows } = await db.query<{ name: string; permissions: string[] }>("SELECT name, permissions FROM roles");
    expect(rows).toHaveLength(5);
    for (const r of rows) expect([...r.permissions].sort(), r.name).toEqual([...ROLE_PERMISSIONS[r.name as keyof typeof ROLE_PERMISSIONS]].sort());
  });
});

describe("API keys", () => {
  it("creates keys, stores only an HMAC, and authenticates the exact key", async () => {
    const k = await createApiKey(tdb, PEPPER, { organizationId: orgA, name: "ci", role: "DEVELOPER" });
    expect(k.key).toMatch(/^snl_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{43}$/);
    const stored = (await db.query<{ key_hash: string; prefix: string }>("SELECT key_hash, prefix FROM api_keys WHERE id = $1", [k.id])).rows[0]!;
    expect(stored.key_hash).toBe(hashApiKey(k.key, PEPPER));
    expect(JSON.stringify(stored)).not.toContain(k.key.slice(13));           // secret part is not stored
    const auth = new DbApiKeyAuthenticator(tdb, PEPPER);
    expect(await auth.authenticate(k.key)).toEqual({ organizationId: orgA, role: "DEVELOPER", apiKeyId: k.id, userId: null });
  });

  it("rejects wrong secret, wrong pepper, malformed, unknown and empty keys", async () => {
    const k = await createApiKey(tdb, PEPPER, { organizationId: orgA, name: "k2", role: "VIEWER" });
    const auth = new DbApiKeyAuthenticator(tdb, PEPPER);
    const tampered = k.key.slice(0, -1) + (k.key.endsWith("A") ? "B" : "A");
    for (const bad of [tampered, `${k.key}x`, k.key.slice(0, 20), "", undefined, "snl_AAAAAAAA_" + "A".repeat(43), "' OR 1=1 --"]) {
      expect(await auth.authenticate(bad), String(bad)).toBeNull();
    }
    expect(await new DbApiKeyAuthenticator(tdb, "y".repeat(40)).authenticate(k.key)).toBeNull();
  });

  it("rejects revoked and expired keys", async () => {
    const auth = new DbApiKeyAuthenticator(tdb, PEPPER);
    const revoked = await createApiKey(tdb, PEPPER, { organizationId: orgA, name: "rev", role: "ADMIN" });
    await db.query("UPDATE api_keys SET revoked_at = now() WHERE id = $1", [revoked.id]);
    expect(await auth.authenticate(revoked.key)).toBeNull();
    const expired = await createApiKey(tdb, PEPPER, { organizationId: orgA, name: "exp", role: "ADMIN", expiresAt: new Date(Date.now() - 1000) });
    expect(await auth.authenticate(expired.key)).toBeNull();
    const future = await createApiKey(tdb, PEPPER, { organizationId: orgA, name: "fut", role: "ADMIN", expiresAt: new Date(Date.now() + 3_600_000) });
    expect(await auth.authenticate(future.key)).not.toBeNull();
  });

  it("a key resolves to ITS organization only", async () => {
    const kb = await createApiKey(tdb, PEPPER, { organizationId: orgB, name: "b", role: "OWNER" });
    expect((await new DbApiKeyAuthenticator(tdb, PEPPER).authenticate(kb.key))?.organizationId).toBe(orgB);
  });
});

describe("PgEventSink", () => {
  it("records metadata, per-detection evidence (digest, no text) and usage in a retaining org", async () => {
    const sink = new PgEventSink(tdb);
    const id = await sink.record(event(orgA));
    await sink.record(event(orgA, { action: "BLOCK", riskLevel: "CRITICAL", riskScore: 95, entityTypes: ["API_KEY"] }));
    const stored = await sink.get(orgA, id);
    expect(stored).toMatchObject({ id, organizationId: orgA, action: "REDACT", entityTypes: ["EMAIL"], policyId: "p@1", provider: "gemini" });
    const meta = (await db.query<{ detections_meta: { digest: string }[] }>("SELECT detections_meta FROM scan_results WHERE event_id = $1", [id])).rows[0]!;
    expect(meta.detections_meta[0]!.digest).toBe("deadbeef");
    const u = await sink.usage(orgA, 7);
    expect(u).toEqual([{ day: expect.any(String), provider: "gemini", requests: 2, blocked: 1, sanitized: 1 }]);
  });

  it("zero-retention orgs keep the event row but no scan_results", async () => {
    const sink = new PgEventSink(tdb);
    const id = await sink.record(event(orgZero));
    expect(await sink.get(orgZero, id)).not.toBeNull();
    expect((await db.query("SELECT 1 FROM scan_results WHERE event_id = $1", [id])).rows).toHaveLength(0);
  });

  it("filters, paginates and never crosses organizations", async () => {
    const sink = new PgEventSink(tdb);
    const idB = await sink.record(event(orgB));
    expect(await sink.get(orgA, idB)).toBeNull();                                  // A cannot read B's event by id
    expect((await sink.list(orgA, { limit: 50 })).every((e) => e.organizationId === orgA)).toBe(true);
    expect((await sink.list(orgA, { limit: 50, riskLevel: "CRITICAL" })).map((e) => e.action)).toEqual(["BLOCK"]);
    expect((await sink.list(orgA, { limit: 1 }))).toHaveLength(1);
    await expect(new PgEventSink(tdb).record({ ...event(orgA), organizationId: "not-a-uuid" })).rejects.toThrow();
  });

  it("the event table cannot hold content: the stored row has no text-bearing column", async () => {
    const cols = (await db.query<{ column_name: string }>("SELECT column_name FROM information_schema.columns WHERE table_name = 'security_events'")).rows.map((c) => c.column_name);
    for (const forbidden of ["text", "prompt", "content", "response", "message", "value", "secret"]) expect(cols).not.toContain(forbidden);
  });
});

describe("PgPolicyRepository", () => {
  const repo = () => new PgPolicyRepository(tdb);

  it("no active policy -> undefined (engine baseline applies)", async () => {
    expect(await repo().getEffectivePolicy(orgB)).toBeUndefined();
  });

  it("creates versions, keeps exactly one active, and round-trips rules (incl. scope)", async () => {
    const r = repo();
    expect(await r.createVersion(orgA, "eng", [{ entity: "EMAIL", action: "REDACT" }], null)).toBe(1);
    expect(await r.createVersion(orgA, "eng", [{ entity: "CREDIT_CARD", action: "TOKENIZE", severity: "CRITICAL", min_confidence: 0.5, scope: { environments: ["production"] } }], null)).toBe(2);
    const list = (await r.list(orgA)).filter((p) => p.policy_id === "eng");
    expect(list.map((p) => [p.version, p.active])).toEqual([[2, true], [1, false]]);
    expect(await r.get(orgA, "eng")).toEqual({ policy_id: "eng", version: 2, active: true,
      rules: [{ entity: "CREDIT_CARD", action: "TOKENIZE", severity: "CRITICAL", min_confidence: 0.5, scope: { environments: ["production"] } }] });
  });

  it("effective policy is the union of active policies; deactivate removes it", async () => {
    const r = repo();
    await r.createVersion(orgA, "second", [{ entity: "PHONE", action: "REDACT" }], null);
    const eff = await r.getEffectivePolicy(orgA);
    expect(eff?.policy_id.split("+").sort()).toEqual(["eng@2", "second@1"]);
    expect(eff?.rules.map((x) => x.entity).sort()).toEqual(["CREDIT_CARD", "PHONE"]);
    expect(await r.deactivate(orgA, "second")).toBe(true);
    expect(await r.deactivate(orgA, "nonexistent")).toBe(false);
    expect((await r.getEffectivePolicy(orgA))?.policy_id).toBe("eng@2");
  });

  it("policies are invisible across organizations", async () => {
    expect(await repo().get(orgB, "eng")).toBeNull();
    expect((await repo().list(orgB))).toHaveLength(0);
  });

  it("the database itself rejects an unsafe ALLOW even if application validation is bypassed", async () => {
    await expect(repo().createVersion(orgA, "bad", [{ entity: "PASSWORD", action: "ALLOW" }], null)).rejects.toThrow(/policy_rules_no_unsafe_allow/);
    expect((await repo().get(orgA, "bad"))).toBeNull();                              // transaction rolled back
  });
});

describe("audit log", () => {
  it("is append-only metadata and tenant-scoped", async () => {
    await new PgAuditLogWriter(tdb).record({ organizationId: orgA, actorId: null, actorType: "api_key", action: "policy.create", target: "eng", metadata: { version: 1 } });
    const rows = (await db.query<{ organization_id: string; action: string }>("SELECT organization_id, action FROM audit_logs WHERE action = 'policy.create'")).rows;
    expect(rows).toEqual([{ organization_id: orgA, action: "policy.create" }]);
  });
});
