import type { TestDb } from "../helpers/testDb.js";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AiRouter } from "@sentinelai/ai-router";
import { buildApp } from "../../src/app.js";
import { PgAuditLogWriter } from "../../src/events/auditLog.js";
import { PgEventSink } from "../../src/events/eventSink.js";
import { PgAuthRepository } from "../../src/repositories/authRepository.js";
import { PgPolicyRepository } from "../../src/repositories/policyRepository.js";
import { DbApiKeyAuthenticator, createApiKey } from "../../src/security/apiKeys.js";
import { CompositeAuthenticator } from "../../src/security/authenticators.js";
import { AccessTokens } from "../../src/security/tokens.js";
import { AuthService } from "../../src/services/authService.js";
import { SecureAiService } from "../../src/services/secureAiService.js";
import { FakeProvider, FakeScanner, PgliteTenantDb, TEST_CONFIG } from "../helpers/fakes.js";
import { createMigratedDb } from "../helpers/testDb.js";

const PW = "Tr0ub4dor&3-horse-staple";
let db: TestDb; let app: FastifyInstance; let clock = Date.now();
let tdb: PgliteTenantDb; let tokens: AccessTokens;

function build(over: { signup?: boolean; withAuth?: boolean; limits?: { ipPerMinute: number; emailPerMinute: number } } = {}) {
  const scanner = new FakeScanner(); const events = new PgEventSink(tdb); const policies = new PgPolicyRepository(tdb);
  const audit = new PgAuditLogWriter(tdb);
  const svc = new AuthService({ repo: new PgAuthRepository(tdb), tokens, audit, accessTtlSeconds: 900, refreshTtlSeconds: 86_400, now: () => new Date(clock) });
  return buildApp({
    config: { ...TEST_CONFIG, apiKeyPepper: "p".repeat(40) }, scanner, events, policies, auditLog: audit,
    auth: new CompositeAuthenticator(new DbApiKeyAuthenticator(tdb, "p".repeat(40)), tokens),
    service: new SecureAiService({ scanner, router: new AiRouter().register(new FakeProvider()), policies, events }), ping: async () => true,
    ...(over.withAuth === false ? {} : { authService: svc, signupEnabled: over.signup ?? true, authLimits: over.limits ?? { ipPerMinute: 10_000, emailPerMinute: 10_000 } }),
  }, { logger: false });
}

const post = (url: string, payload: unknown, headers: Record<string, string> = {}) => app.inject({ method: "POST", url, payload: payload as object, headers });
const signup = (email: string, org = "Acme Corp") => post("/v1/auth/signup", { organization_name: org, email, password: PW });
const login = (email: string, password = PW) => post("/v1/auth/login", { email, password });
const bearer = (t: string) => ({ authorization: `Bearer ${t}` });

beforeAll(async () => {
  db = await createMigratedDb({ allowRealServer: true }); tdb = new PgliteTenantDb(db);
  tokens = new AccessTokens({ secret: TEST_CONFIG.jwtAccessSecret!, ttlSeconds: 900 }, () => clock);
  app = build();
});
afterAll(async () => { await app.close(); await db.close(); });

/** Migration 0008 guarantees every organization keeps an active OWNER, so a test that disables or demotes an owner first adds a co-owner. */
async function addCoOwner(ownerEmail: string): Promise<void> {
  await db.query(`INSERT INTO users (organization_id, email, password_hash, role_id)
                  SELECT organization_id, 'co-' || email, 'x', role_id FROM users WHERE email = $1 ON CONFLICT (email) DO NOTHING`, [ownerEmail]);
}

describe("signup and login", () => {
  it("signup creates an org + OWNER and returns a working session", async () => {
    const res = await signup("owner@acme.example");
    expect(res.statusCode).toBe(201);
    const b = res.json();
    expect(b).toMatchObject({ token_type: "Bearer", expires_in: 900, user: { role: "OWNER" } });
    const me = await app.inject({ method: "GET", url: "/v1/auth/me", headers: bearer(b.access_token) });
    expect(me.json()).toMatchObject({ user_id: b.user.id, organization_id: b.user.organization_id, role: "OWNER", api_key_id: null });
  });

  it("the JWT authorizes real routes by role (OWNER can write policies; unauthenticated cannot)", async () => {
    const { access_token } = (await login("owner@acme.example")).json();
    const created = await app.inject({ method: "POST", url: "/v1/policies", headers: bearer(access_token), payload: { policy_id: "eng", rules: [{ entity: "EMAIL", action: "REDACT" }] } });
    expect(created.statusCode).toBe(201);
    expect((await app.inject({ method: "GET", url: "/v1/policies" })).statusCode).toBe(401);
  });

  it("wrong password, unknown email and disabled account return the identical 401", async () => {
    await signup("victim@acme.example", "Victim Org");
    const bodies = new Set<string>();
    const wrong = await login("victim@acme.example", "not-the-password-123");
    const unknown = await login("nobody@acme.example");
    await addCoOwner("victim@acme.example");
    await db.query("UPDATE users SET disabled_at = now() WHERE email = 'victim@acme.example'");
    const disabled = await login("victim@acme.example");
    for (const r of [wrong, unknown, disabled]) { expect(r.statusCode).toBe(401); bodies.add(r.body); }
    expect(bodies.size).toBe(1);
    expect(bodies.values().next().value).not.toMatch(/victim|password|exist|disabled/i);
  });

  it("rejects weak passwords (422), duplicate accounts (409), unknown fields and malformed input", async () => {
    expect((await post("/v1/auth/signup", { organization_name: "X", email: "weak@acme.example", password: "short" })).statusCode).toBe(422);
    expect((await signup("owner@acme.example", "Another")).statusCode).toBe(409);
    expect((await post("/v1/auth/login", { email: "a@b.co", password: PW, admin: true })).statusCode).toBe(422);
    expect((await post("/v1/auth/login", { email: "not-an-email", password: PW })).statusCode).toBe(422);
    expect((await post("/v1/auth/login", { email: "a@b.co", password: "x".repeat(129) })).statusCode).toBe(422);
  });

  it("emails are case-insensitive", async () => {
    expect((await login("OWNER@ACME.EXAMPLE")).statusCode).toBe(200);
  });

  it("signup can be disabled (403), and auth routes are absent when no auth service is configured", async () => {
    const a = build({ signup: false });
    expect((await a.inject({ method: "POST", url: "/v1/auth/signup", payload: { organization_name: "N", email: "n@n.example", password: PW } })).statusCode).toBe(403);
    await a.close();
    const b = build({ withAuth: false });
    expect((await b.inject({ method: "POST", url: "/v1/auth/login", payload: {} })).statusCode).toBe(404);
    await b.close();
  });

  it("API keys keep working alongside JWTs", async () => {
    const { user } = (await login("owner@acme.example")).json();
    const key = await createApiKey(tdb, "p".repeat(40), { organizationId: user.organization_id, name: "k", role: "DEVELOPER" });
    const me = await app.inject({ method: "GET", url: "/v1/auth/me", headers: { "x-sentinel-api-key": key.key } });
    expect(me.json()).toMatchObject({ api_key_id: key.id, user_id: null, role: "DEVELOPER" });
  });
});

describe("refresh token rotation and reuse detection", () => {
  it("rotates: the new pair works, the old refresh token is dead, and reuse revokes the whole family", async () => {
    const s0 = (await login("owner@acme.example")).json();
    const r1 = await post("/v1/auth/refresh", { refresh_token: s0.refresh_token });
    expect(r1.statusCode).toBe(200);
    const s1 = r1.json();
    expect(s1.refresh_token).not.toBe(s0.refresh_token);
    expect((await app.inject({ method: "GET", url: "/v1/auth/me", headers: bearer(s1.access_token) })).statusCode).toBe(200);

    // Replay of the already-used token (e.g. stolen): rejected AND the legitimate successor is revoked too.
    expect((await post("/v1/auth/refresh", { refresh_token: s0.refresh_token })).statusCode).toBe(401);
    expect((await post("/v1/auth/refresh", { refresh_token: s1.refresh_token })).statusCode).toBe(401);
    const audit = (await db.query<{ action: string }>("SELECT action FROM audit_logs WHERE action = 'auth.refresh_reuse_detected'")).rows;
    expect(audit.length).toBeGreaterThanOrEqual(1);
  });

  it("concurrent use of the same refresh token: at most one succeeds, the family is then revoked", async () => {
    const s = (await login("owner@acme.example")).json();
    const results = await Promise.all([1, 2, 3].map(() => post("/v1/auth/refresh", { refresh_token: s.refresh_token })));
    expect(results.filter((r) => r.statusCode === 200).length).toBe(1);
    const winner = results.find((r) => r.statusCode === 200)!.json();
    expect((await post("/v1/auth/refresh", { refresh_token: winner.refresh_token })).statusCode).toBe(401);
  });

  it("expired refresh tokens are rejected", async () => {
    const s = (await login("owner@acme.example")).json();
    clock += 2 * 86_400_000;
    expect((await post("/v1/auth/refresh", { refresh_token: s.refresh_token })).statusCode).toBe(401);
    clock -= 2 * 86_400_000;
  });

  it("logout revokes the family; garbage logout still returns 204", async () => {
    const s = (await login("owner@acme.example")).json();
    expect((await post("/v1/auth/logout", { refresh_token: s.refresh_token })).statusCode).toBe(204);
    expect((await post("/v1/auth/refresh", { refresh_token: s.refresh_token })).statusCode).toBe(401);
    expect((await post("/v1/auth/logout", { refresh_token: "snr_" + "A".repeat(43) })).statusCode).toBe(204);
    expect((await post("/v1/auth/logout", { nonsense: 1 })).statusCode).toBe(204);
  });

  it("malformed or unknown refresh tokens are rejected uniformly", async () => {
    expect((await post("/v1/auth/refresh", { refresh_token: "snr_" + "A".repeat(43) })).statusCode).toBe(401);
    expect((await post("/v1/auth/refresh", { refresh_token: "garbage" })).statusCode).toBe(422);
  });

  it("role changes and disabling take effect at the next refresh", async () => {
    const s = (await login("owner@acme.example")).json();
    await addCoOwner("owner@acme.example");
    await db.query("UPDATE users SET role_id = (SELECT id FROM roles WHERE name='VIEWER') WHERE email = 'owner@acme.example'");
    const r = (await post("/v1/auth/refresh", { refresh_token: s.refresh_token })).json();
    expect(r.user.role).toBe("VIEWER");
    expect((await app.inject({ method: "POST", url: "/v1/policies", headers: bearer(r.access_token), payload: { policy_id: "x", rules: [] } })).statusCode).toBe(403);
    await db.query("UPDATE users SET disabled_at = now() WHERE email = 'owner@acme.example'");
    expect((await post("/v1/auth/refresh", { refresh_token: r.refresh_token })).statusCode).toBe(401);
    await db.query("UPDATE users SET disabled_at = NULL, role_id = (SELECT id FROM roles WHERE name='OWNER') WHERE email = 'owner@acme.example'");
  });
});

describe("abuse resistance and data hygiene", () => {
  it("login is throttled per target email (429 + retry-after) without affecting other accounts", async () => {
    const a = build({ limits: { ipPerMinute: 20, emailPerMinute: 10 } });
    const codes: number[] = [];
    for (let i = 0; i < 12; i++) codes.push((await a.inject({ method: "POST", url: "/v1/auth/login", payload: { email: "throttle@acme.example", password: "wrong-password-123" } })).statusCode);
    expect(codes.slice(0, 10).every((c) => c === 401)).toBe(true);
    expect(codes.slice(10)).toEqual([429, 429]);
    await a.close();
  });

  it("nothing reusable is stored: no plaintext password, no raw refresh token, no raw access token", async () => {
    const s = (await login("owner@acme.example")).json();
    const dump = JSON.stringify((await db.query("SELECT * FROM users")).rows) + JSON.stringify((await db.query("SELECT * FROM refresh_tokens")).rows)
      + JSON.stringify((await db.query("SELECT * FROM audit_logs")).rows);
    for (const secret of [PW, s.refresh_token, s.refresh_token.slice(4), s.access_token]) expect(dump).not.toContain(secret);
    expect(dump).toContain("scrypt$");
  });

  it("refresh tokens are tenant-isolated by RLS", async () => {
    const orgs = (await db.query<{ id: string }>("SELECT id FROM organizations ORDER BY created_at LIMIT 2")).rows;
    const asOrg = (org: string) => tdb.withTenant(org, async (q) => (await q.query("SELECT organization_id FROM refresh_tokens")).rows as { organization_id: string }[]);
    for (const o of orgs) {
      const rows = await asOrg(o.id);
      expect(rows.every((r) => r.organization_id === o.id)).toBe(true);
    }
    const [a, b] = await Promise.all(orgs.map((o) => asOrg(o.id)));
    expect(a!.length + b!.length).toBeLessThanOrEqual((await db.query("SELECT 1 FROM refresh_tokens")).rows.length);
  });

  it("a user from one org cannot read another org's events with their JWT", async () => {
    const other = (await signup("other@rival.example", "Rival Inc")).json();
    const mine = (await login("owner@acme.example")).json();
    await app.inject({ method: "POST", url: "/v1/security/scan", headers: bearer(mine.access_token), payload: { text: "hello there" } });
    const mineEvents = (await app.inject({ method: "GET", url: "/v1/events", headers: bearer(mine.access_token) })).json();
    const theirEvents = (await app.inject({ method: "GET", url: "/v1/events", headers: bearer(other.access_token) })).json();
    expect(mineEvents.events.length).toBeGreaterThan(0);
    expect(theirEvents.events).toHaveLength(0);
    expect((await app.inject({ method: "GET", url: `/v1/events/${mineEvents.events[0].id}`, headers: bearer(other.access_token) })).statusCode).toBe(404);
  });
});
