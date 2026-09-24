import type { TestDb } from "../helpers/testDb.js";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AiRouter } from "@sentinelai/ai-router";
import { buildApp } from "../../src/app.js";
import { PgAuditLogWriter } from "../../src/events/auditLog.js";
import { PgEventSink } from "../../src/events/eventSink.js";
import { MAX_ACTIVE_KEYS, PgApiKeyRepository } from "../../src/repositories/apiKeyRepository.js";
import { PgAuthRepository } from "../../src/repositories/authRepository.js";
import { PgPolicyRepository } from "../../src/repositories/policyRepository.js";
import { DbApiKeyAuthenticator } from "../../src/security/apiKeys.js";
import { CompositeAuthenticator } from "../../src/security/authenticators.js";
import { hashPassword } from "../../src/security/passwords.js";
import { ROLES, roleCanGrant, type RoleName } from "../../src/security/rbac.js";
import { AccessTokens } from "../../src/security/tokens.js";
import { AuthService } from "../../src/services/authService.js";
import { SecureAiService } from "../../src/services/secureAiService.js";
import { FakeProvider, FakeScanner, PgliteTenantDb, TEST_CONFIG } from "../helpers/fakes.js";
import { createMigratedDb } from "../helpers/testDb.js";

const PW = "Tr0ub4dor&3-horse-staple";
const PEPPER = "p".repeat(40);
let db: TestDb; let tdb: PgliteTenantDb; let app: FastifyInstance; let orgA: string; let orgB: string;
const jwt: Record<string, string> = {};

const bearer = (t: string) => ({ authorization: `Bearer ${t}` });
const call = (method: "GET" | "POST" | "DELETE", url: string, token: string, payload?: unknown) =>
  app.inject({ method, url, headers: bearer(token), ...(payload !== undefined ? { payload: payload as object } : {}) });
const create = (token: string, body: object) => call("POST", "/v1/api-keys", token, body);

async function addUser(org: string, email: string, role: RoleName): Promise<void> {
  await db.query("INSERT INTO users (organization_id, email, password_hash, role_id) VALUES ($1,$2,$3,(SELECT id FROM roles WHERE name=$4))", [org, email, await hashPassword(PW), role]);
}
async function login(email: string): Promise<string> {
  const r = await app.inject({ method: "POST", url: "/v1/auth/login", payload: { email, password: PW } });
  return r.json().access_token as string;
}

beforeAll(async () => {
  db = await createMigratedDb({ allowRealServer: true }); tdb = new PgliteTenantDb(db);
  const tokens = new AccessTokens({ secret: TEST_CONFIG.jwtAccessSecret!, ttlSeconds: 900 });
  const scanner = new FakeScanner(); const events = new PgEventSink(tdb); const policies = new PgPolicyRepository(tdb); const audit = new PgAuditLogWriter(tdb);
  app = buildApp({
    config: { ...TEST_CONFIG, apiKeyPepper: PEPPER }, scanner, events, policies, auditLog: audit, ping: async () => true,
    auth: new CompositeAuthenticator(new DbApiKeyAuthenticator(tdb, PEPPER), tokens),
    service: new SecureAiService({ scanner, router: new AiRouter().register(new FakeProvider()), policies, events }),
    authService: new AuthService({ repo: new PgAuthRepository(tdb), tokens, audit, accessTtlSeconds: 900, refreshTtlSeconds: 86_400 }),
    apiKeys: new PgApiKeyRepository(tdb, PEPPER), signupEnabled: true, authLimits: { ipPerMinute: 100_000, emailPerMinute: 100_000 },
  }, { logger: false });

  const signup = async (org: string, email: string) => (await app.inject({ method: "POST", url: "/v1/auth/signup", payload: { organization_name: org, email, password: PW } })).json();
  const a = await signup("Org A", "owner@a.example"); const b = await signup("Org B", "owner@b.example");
  orgA = a.user.organization_id; orgB = b.user.organization_id;
  jwt.OWNER = a.access_token; jwt.OWNER_B = b.access_token;
  for (const role of ["ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"] as const) { await addUser(orgA, `${role.toLowerCase()}@a.example`, role); jwt[role] = await login(`${role.toLowerCase()}@a.example`); }
});
afterAll(async () => { await app.close(); await db.close(); });

describe("roleCanGrant (privilege-escalation matrix)", () => {
  const grid = Object.fromEntries(ROLES.map((c) => [c, ROLES.filter((t) => roleCanGrant(c, t))]));
  it("OWNER can grant every role", () => expect(grid.OWNER).toEqual([...ROLES]));
  it("ADMIN can grant everything except OWNER", () => { expect(grid.ADMIN).not.toContain("OWNER"); expect(grid.ADMIN).toEqual(expect.arrayContaining(["ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"])); });
  it("DEVELOPER can grant only DEVELOPER (VIEWER holds events:read, which DEVELOPER lacks)", () => expect(grid.DEVELOPER).toEqual(["DEVELOPER"]));
  it("hierarchy sanity: ADMIN holds every permission of SECURITY_ANALYST, DEVELOPER and VIEWER combined only where intended", () => {
    for (const lower of ["SECURITY_ANALYST"] as const) expect(roleCanGrant("ADMIN", lower)).toBe(true);
    expect(roleCanGrant("SECURITY_ANALYST", "ADMIN")).toBe(false);
  });
  it("nobody below OWNER can ever grant OWNER, and no role can grant more than it holds", () => {
    for (const c of ROLES) if (c !== "OWNER") expect(roleCanGrant(c, "OWNER")).toBe(false);
    expect(roleCanGrant("VIEWER", "DEVELOPER")).toBe(false);
    expect(roleCanGrant("VIEWER", "VIEWER")).toBe(true);
  });
});

describe("creating keys", () => {
  it("OWNER creates a key: the secret is returned once, works immediately, and is never listed", async () => {
    const res = await create(jwt.OWNER!, { name: "ci", role: "DEVELOPER", expires_in_days: 30 });
    expect(res.statusCode).toBe(201);
    const k = res.json();
    expect(k.key).toMatch(/^snl_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{43}$/);
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(k).toMatchObject({ name: "ci", role: "DEVELOPER", revoked_at: null, prefix: k.key.slice(0, 12) });
    const days = (new Date(k.expires_at).getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(29); expect(days).toBeLessThan(31);

    // it authenticates
    expect((await app.inject({ method: "GET", url: "/v1/auth/me", headers: { "x-sentinel-api-key": k.key } })).json()).toMatchObject({ api_key_id: k.id, role: "DEVELOPER", organization_id: orgA });

    // listings never carry the secret, its hash or its random part
    const list = await call("GET", "/v1/api-keys", jwt.OWNER!);
    const dump = list.body;
    expect(dump).not.toContain(k.key); expect(dump).not.toContain(k.key.slice(13)); expect(dump).not.toMatch(/key_hash|"key"/);
    expect(list.json().api_keys.find((x: { id: string }) => x.id === k.id)).toMatchObject({ name: "ci", prefix: k.key.slice(0, 12) });
  });

  it("stores only an HMAC, and defaults to a 90 day expiry", async () => {
    const k = (await create(jwt.OWNER!, { name: "default-expiry", role: "VIEWER" })).json();
    const days = (new Date(k.expires_at).getTime() - Date.now()) / 86_400_000;
    expect(Math.round(days)).toBe(90);
    const stored = (await db.query<{ key_hash: string }>("SELECT key_hash FROM api_keys WHERE id = $1", [k.id])).rows[0]!.key_hash;
    expect(stored).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify((await db.query("SELECT * FROM api_keys")).rows)).not.toContain(k.key);
  });

  it("enforces the escalation rule over HTTP: each role can only mint what it may grant", async () => {
    for (const caller of ROLES) {
      for (const target of ROLES) {
        if (!(caller === "OWNER" || caller === "ADMIN" || caller === "DEVELOPER")) continue; // only these hold keys:manage
        const res = await create(jwt[caller]!, { name: `${caller}->${target}`, role: target });
        expect(res.statusCode, `${caller} -> ${target}`).toBe(roleCanGrant(caller, target) ? 201 : 403);
        if (res.statusCode === 403) expect(res.json()).toMatchObject({ reason: "cannot_grant_role" });
      }
    }
  });

  it("roles without keys:manage cannot touch key management at all", async () => {
    for (const role of ["SECURITY_ANALYST", "VIEWER"]) {
      expect((await create(jwt[role]!, { name: "x", role: "VIEWER" })).statusCode, role).toBe(403);
      expect((await call("GET", "/v1/api-keys", jwt[role]!)).statusCode, role).toBe(403);
    }
    expect((await app.inject({ method: "GET", url: "/v1/api-keys" })).statusCode).toBe(401);
  });

  it("an API key can NEVER create, list or revoke keys, even an OWNER-role key (no self-perpetuating credentials)", async () => {
    const owner = (await create(jwt.OWNER!, { name: "owner-key", role: "OWNER" })).json();
    const h = { "x-sentinel-api-key": owner.key };
    expect((await app.inject({ method: "POST", url: "/v1/api-keys", headers: h, payload: { name: "child", role: "VIEWER" } })).json()).toMatchObject({ reason: "user_session_required" });
    expect((await app.inject({ method: "GET", url: "/v1/api-keys", headers: h })).statusCode).toBe(403);
    expect((await app.inject({ method: "DELETE", url: `/v1/api-keys/${owner.id}`, headers: h })).statusCode).toBe(403);
  });

  it("validates input: unknown fields/roles, bad expiry, empty name", async () => {
    for (const bad of [{ name: "x", role: "ROOT" }, { name: "", role: "VIEWER" }, { name: "x", role: "VIEWER", expires_in_days: 0 },
      { name: "x", role: "VIEWER", expires_in_days: 366 }, { name: "x", role: "VIEWER", admin: true }, { role: "VIEWER" }, { name: "x", role: "VIEWER", expires_in_days: 1.5 }]) {
      expect((await create(jwt.OWNER!, bad)).statusCode, JSON.stringify(bad)).toBe(422);
    }
  });

  it("caps active keys per organization", async () => {
    const before = Number((await db.query<{ n: string }>("SELECT count(*) n FROM api_keys WHERE organization_id = $1 AND revoked_at IS NULL", [orgB])).rows[0]!.n);
    const repo = new PgApiKeyRepository(tdb, PEPPER);
    for (let i = before; i < MAX_ACTIVE_KEYS; i++) await repo.create(orgB, `bulk-${i}`, "VIEWER", null, new Date(Date.now() + 86_400_000));
    const res = await create(jwt.OWNER_B!, { name: "one-too-many", role: "VIEWER" });
    expect(res.statusCode).toBe(409);
    expect(res.json()).toEqual({ error: "key_limit_reached" });
  }, 120_000);
});

describe("revoking keys", () => {
  it("a revoked key stops authenticating immediately; revoking twice is harmless", async () => {
    const k = (await create(jwt.OWNER!, { name: "temp", role: "DEVELOPER" })).json();
    const h = { "x-sentinel-api-key": k.key };
    expect((await app.inject({ method: "GET", url: "/v1/auth/me", headers: h })).statusCode).toBe(200);
    expect((await call("DELETE", `/v1/api-keys/${k.id}`, jwt.OWNER!)).statusCode).toBe(204);
    expect((await app.inject({ method: "GET", url: "/v1/auth/me", headers: h })).statusCode).toBe(401);
    expect((await call("DELETE", `/v1/api-keys/${k.id}`, jwt.OWNER!)).statusCode).toBe(204);
    expect((await call("GET", "/v1/api-keys", jwt.OWNER!)).json().api_keys.find((x: { id: string }) => x.id === k.id).revoked_at).toBeTruthy();
  });

  it("cannot revoke a key more privileged than yourself, but can revoke your own tier", async () => {
    const ownerKey = (await create(jwt.OWNER!, { name: "priv", role: "OWNER" })).json();
    const adminKey = (await create(jwt.OWNER!, { name: "adm", role: "ADMIN" })).json();
    expect((await call("DELETE", `/v1/api-keys/${ownerKey.id}`, jwt.ADMIN!)).json()).toMatchObject({ reason: "key_has_higher_privilege" });
    expect((await call("DELETE", `/v1/api-keys/${adminKey.id}`, jwt.ADMIN!)).statusCode).toBe(204);
    const devKey = (await create(jwt.DEVELOPER!, { name: "dev", role: "DEVELOPER" })).json();
    expect((await call("DELETE", `/v1/api-keys/${devKey.id}`, jwt.DEVELOPER!)).statusCode).toBe(204);
    expect((await call("DELETE", `/v1/api-keys/${adminKey.id}`, jwt.DEVELOPER!)).statusCode).toBe(403);
  });

  it("cannot see or revoke another organization's keys (404, and the key keeps working)", async () => {
    const k = (await create(jwt.OWNER!, { name: "a-key", role: "DEVELOPER" })).json();
    expect((await call("DELETE", `/v1/api-keys/${k.id}`, jwt.OWNER_B!)).statusCode).toBe(404);
    expect((await app.inject({ method: "GET", url: "/v1/auth/me", headers: { "x-sentinel-api-key": k.key } })).statusCode).toBe(200);
    expect((await call("GET", "/v1/api-keys", jwt.OWNER_B!)).json().api_keys.some((x: { id: string }) => x.id === k.id)).toBe(false);
  });

  it("malformed ids are 404", async () => {
    for (const id of ["nope", "1' OR '1'='1", "../x"]) expect((await call("DELETE", `/v1/api-keys/${encodeURIComponent(id)}`, jwt.OWNER!)).statusCode).toBe(404);
  });
});

describe("auditing and usage tracking", () => {
  it("create and revoke are audited with metadata only (never the key)", async () => {
    const k = (await create(jwt.OWNER!, { name: "audited", role: "DEVELOPER" })).json();
    await call("DELETE", `/v1/api-keys/${k.id}`, jwt.OWNER!);
    const rows = (await db.query<{ action: string; target: string; metadata: unknown }>("SELECT action, target, metadata FROM audit_logs WHERE target = $1 ORDER BY \"timestamp\"", [k.id])).rows;
    expect(rows.map((r) => r.action)).toEqual(["apikey.create", "apikey.revoke"]);
    expect(JSON.stringify(rows)).not.toContain(k.key);
  });

  it("last_used_at is populated on first use and not rewritten on every request", async () => {
    const k = (await create(jwt.OWNER!, { name: "usage", role: "DEVELOPER" })).json();
    expect(k.last_used_at).toBeNull();
    await app.inject({ method: "GET", url: "/v1/auth/me", headers: { "x-sentinel-api-key": k.key } });
    await new Promise((r) => setTimeout(r, 300));
    const first = (await db.query<{ last_used_at: Date }>("SELECT last_used_at FROM api_keys WHERE id = $1", [k.id])).rows[0]!.last_used_at;
    expect(first).toBeTruthy();
    await app.inject({ method: "GET", url: "/v1/auth/me", headers: { "x-sentinel-api-key": k.key } });
    await new Promise((r) => setTimeout(r, 300));
    const second = (await db.query<{ last_used_at: Date }>("SELECT last_used_at FROM api_keys WHERE id = $1", [k.id])).rows[0]!.last_used_at;
    expect(new Date(second).getTime()).toBe(new Date(first).getTime());   // within the hour: no rewrite
  });

  it("an expired key no longer authenticates", async () => {
    const k = (await create(jwt.OWNER!, { name: "short", role: "DEVELOPER", expires_in_days: 1 })).json();
    await db.query("UPDATE api_keys SET expires_at = now() - interval '1 minute' WHERE id = $1", [k.id]);
    expect((await app.inject({ method: "GET", url: "/v1/auth/me", headers: { "x-sentinel-api-key": k.key } })).statusCode).toBe(401);
  });
});
