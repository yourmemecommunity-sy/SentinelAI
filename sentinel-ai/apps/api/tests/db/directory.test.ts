import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AiRouter } from "@sentinelai/ai-router";
import { buildApp } from "../../src/app.js";
import { PgAuditLogWriter } from "../../src/events/auditLog.js";
import { PgEventSink } from "../../src/events/eventSink.js";
import { PgApiKeyRepository } from "../../src/repositories/apiKeyRepository.js";
import { PgAuthRepository } from "../../src/repositories/authRepository.js";
import { PgDirectoryRepository } from "../../src/repositories/directoryRepository.js";
import { PgPolicyRepository } from "../../src/repositories/policyRepository.js";
import { hashInvitationToken } from "../../src/routes/directoryRoutes.js";
import { DbApiKeyAuthenticator } from "../../src/security/apiKeys.js";
import { CompositeAuthenticator } from "../../src/security/authenticators.js";
import { AccessTokens } from "../../src/security/tokens.js";
import { AuthService } from "../../src/services/authService.js";
import { SecureAiService } from "../../src/services/secureAiService.js";
import { FakeProvider, FakeScanner, PgliteTenantDb, TEST_CONFIG } from "../helpers/fakes.js";
import { asTenant, createMigratedDb, type TestDb } from "../helpers/testDb.js";

const PW = "Tr0ub4dor&3-horse-staple";
const PEPPER = "p".repeat(40);
let db: TestDb; let app: FastifyInstance; let orgA: string; let orgB: string;
const jwt: Record<string, string> = {};
const refresh: Record<string, string> = {};
const ids: Record<string, string> = {};

type Method = "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
const call = (method: Method, url: string, token: string | null, payload?: unknown) =>
  app.inject({ method, url, ...(token ? { headers: { authorization: `Bearer ${token}` } } : {}), ...(payload !== undefined ? { payload: payload as object } : {}) });
const invite = (token: string, email: string, role: string, extra: object = {}) => call("POST", "/v1/invitations", token, { email, role, ...extra });
const accept = (token: string, password = PW) => call("POST", "/v1/invitations/accept", null, { token, password });
async function login(email: string) {
  const r = await app.inject({ method: "POST", url: "/v1/auth/login", payload: { email, password: PW } });
  return r.json() as { access_token: string; refresh_token: string; user: { id: string } };
}
async function onboard(owner: string, email: string, role: string, key: string) {
  const inv = await invite(owner, email, role);
  expect(inv.statusCode, inv.body).toBe(201);
  expect((await accept(inv.json().token)).statusCode).toBe(201);
  const s = await login(email);
  jwt[key] = s.access_token; refresh[key] = s.refresh_token; ids[key] = s.user.id;
}

beforeAll(async () => {
  db = await createMigratedDb({ allowRealServer: true });
  const tdb = new PgliteTenantDb(db);
  const tokens = new AccessTokens({ secret: TEST_CONFIG.jwtAccessSecret!, ttlSeconds: 900 });
  const scanner = new FakeScanner(); const events = new PgEventSink(tdb); const policies = new PgPolicyRepository(tdb); const audit = new PgAuditLogWriter(tdb);
  const directory = new PgDirectoryRepository(tdb);
  app = buildApp({
    config: { ...TEST_CONFIG, apiKeyPepper: PEPPER }, scanner, events, policies, auditLog: audit, ping: async () => true,
    auth: new CompositeAuthenticator(new DbApiKeyAuthenticator(tdb, PEPPER), tokens, directory),
    service: new SecureAiService({ scanner, router: new AiRouter().register(new FakeProvider()), policies, events }),
    authService: new AuthService({ repo: new PgAuthRepository(tdb), tokens, audit, accessTtlSeconds: 900, refreshTtlSeconds: 86_400 }),
    apiKeys: new PgApiKeyRepository(tdb, PEPPER), directory, signupEnabled: true, authLimits: { ipPerMinute: 100_000, emailPerMinute: 100_000 },
  }, { logger: false });
  const signup = async (org: string, email: string) => (await app.inject({ method: "POST", url: "/v1/auth/signup", payload: { organization_name: org, email, password: PW } })).json();
  const a = await signup("Dir A", "owner@dir-a.example"); const b = await signup("Dir B", "owner@dir-b.example");
  orgA = a.user.organization_id; orgB = b.user.organization_id;
  jwt.OWNER = a.access_token; ids.OWNER = a.user.id; jwt.OWNER_B = b.access_token; ids.OWNER_B = b.user.id;
  await onboard(jwt.OWNER!, "admin@dir-a.example", "ADMIN", "ADMIN");
  await onboard(jwt.OWNER!, "dev@dir-a.example", "DEVELOPER", "DEV");
});
afterAll(async () => { await app?.close(); await db?.close(); });

describe("invitations", () => {
  it("the token is returned once, stored only as an HMAC, and never listed", async () => {
    const r = await invite(jwt.OWNER!, "Viewer1@Dir-A.example", "VIEWER");
    expect(r.statusCode).toBe(201);
    expect(r.headers["cache-control"]).toBe("no-store");
    const { token, id, email, status } = r.json();
    expect(token).toMatch(/^sni_[A-Za-z0-9_-]{43}$/);
    expect(email).toBe("viewer1@dir-a.example");
    expect(status).toBe("pending");
    const row = (await db.query<{ token_hash: string }>("SELECT token_hash FROM invitations WHERE id = $1", [id])).rows[0]!;
    expect(row.token_hash).toBe(hashInvitationToken(PEPPER, token));
    expect(row.token_hash).not.toContain(token.slice(4, 20));
    const list = await call("GET", "/v1/invitations", jwt.OWNER!);
    expect(list.body).not.toContain(token);
    expect(list.body).not.toContain(row.token_hash);
  });

  it("accepting creates the user with the invited role; the token is single-use", async () => {
    const { token } = (await invite(jwt.OWNER!, "analyst@dir-a.example", "SECURITY_ANALYST")).json();
    const ok = await accept(token);
    expect(ok.statusCode).toBe(201);
    expect(ok.json()).toMatchObject({ organization_id: orgA, role: "SECURITY_ANALYST" });
    expect((await accept(token)).json()).toEqual({ error: "invalid_invitation" });
    const me = await call("GET", "/v1/auth/me", (await login("analyst@dir-a.example")).access_token);
    expect(me.json()).toMatchObject({ organization_id: orgA, role: "SECURITY_ANALYST" });
  });

  it("expired, revoked, malformed and forged tokens are all the same uniform failure", async () => {
    const exp = (await invite(jwt.OWNER!, "late@dir-a.example", "VIEWER")).json();
    await db.query("UPDATE invitations SET expires_at = now() - interval '1 minute' WHERE id = $1", [exp.id]);
    const rev = (await invite(jwt.OWNER!, "revoked@dir-a.example", "VIEWER")).json();
    expect((await call("DELETE", `/v1/invitations/${rev.id}`, jwt.OWNER!)).statusCode).toBe(204);
    for (const t of [exp.token, rev.token, "sni_" + "A".repeat(43), "not-a-token"]) {
      const r = await accept(t);
      expect(r.statusCode, t).toBe(400);
      expect(r.json()).toEqual({ error: "invalid_invitation" });
    }
    expect((await call("DELETE", `/v1/invitations/${rev.id}`, jwt.OWNER!)).statusCode).toBe(409);   // already revoked
  });

  it("an expired invitation can be re-issued; a live one blocks a duplicate", async () => {
    expect((await invite(jwt.OWNER!, "late@dir-a.example", "VIEWER")).statusCode).toBe(201);
    expect((await invite(jwt.OWNER!, "late@dir-a.example", "VIEWER")).json()).toMatchObject({ error: "invitation_pending" });
    expect((await invite(jwt.OWNER!, "dev@dir-a.example", "VIEWER")).json()).toEqual({ error: "already_member" });
  });

  it("an address that already has an account anywhere cannot accept (one organization per user)", async () => {
    const { token } = (await invite(jwt.OWNER!, "owner@dir-b.example", "VIEWER")).json();
    expect((await accept(token)).json()).toEqual({ error: "account_exists" });
  });

  it("the invitee's password must meet policy; nothing is redeemed on a weak one", async () => {
    const { token } = (await invite(jwt.OWNER!, "weak@dir-a.example", "VIEWER")).json();
    expect((await accept(token, "short")).statusCode).toBe(422);
    expect((await accept(token)).statusCode).toBe(201);
  });
});

describe("privilege escalation and credential type", () => {
  it("ADMIN cannot invite an OWNER; DEVELOPER cannot manage users at all", async () => {
    const r = await invite(jwt.ADMIN!, "boss@dir-a.example", "OWNER");
    expect(r.statusCode).toBe(403);
    expect(r.json()).toMatchObject({ reason: "cannot_grant_role" });
    expect(r.json().grantable).not.toContain("OWNER");
    for (const [m, u] of [["GET", "/v1/users"], ["GET", "/v1/invitations"], ["GET", "/v1/teams"]] as const) {
      expect((await call(m, u, jwt.DEV!)).statusCode, u).toBe(403);
    }
    expect((await invite(jwt.DEV!, "x@dir-a.example", "DEVELOPER")).statusCode).toBe(403);
  });

  it("API keys can never manage users, even an OWNER-role key", async () => {
    const key = (await call("POST", "/v1/api-keys", jwt.OWNER!, { name: "automation", role: "OWNER" })).json().key as string;
    for (const [m, u, body] of [["GET", "/v1/users", undefined], ["POST", "/v1/invitations", { email: "k@dir-a.example", role: "VIEWER" }],
      ["PATCH", `/v1/users/${ids.DEV}`, { role: "VIEWER" }], ["POST", "/v1/teams", { name: "k" }]] as const) {
      const r = await call(m, u, key, body);
      expect(r.statusCode, u).toBe(403);
      expect(r.json()).toMatchObject({ reason: "user_session_required" });
    }
  });

  it("ADMIN cannot modify an OWNER, promote anyone to OWNER, or modify themselves", async () => {
    expect((await call("PATCH", `/v1/users/${ids.OWNER}`, jwt.ADMIN!, { role: "VIEWER" })).json()).toMatchObject({ reason: "user_has_higher_privilege" });
    expect((await call("DELETE", `/v1/users/${ids.OWNER}`, jwt.ADMIN!)).statusCode).toBe(403);
    expect((await call("PATCH", `/v1/users/${ids.DEV}`, jwt.ADMIN!, { role: "OWNER" })).json()).toMatchObject({ reason: "cannot_grant_role" });
    expect((await call("PATCH", `/v1/users/${ids.ADMIN}`, jwt.ADMIN!, { role: "OWNER" })).json()).toMatchObject({ reason: "cannot_modify_self" });
    expect((await call("DELETE", `/v1/users/${ids.OWNER}`, jwt.OWNER!)).json()).toMatchObject({ reason: "cannot_modify_self" });
  });

  it("the database refuses to leave an organization without an active OWNER, whatever the code path", async () => {
    await expect(asTenant(db, orgA, "UPDATE users SET role_id = (SELECT id FROM roles WHERE name = 'ADMIN') WHERE id = $1", [ids.OWNER]))
      .rejects.toThrow(/at least one active OWNER/);
    await expect(asTenant(db, orgA, "UPDATE users SET disabled_at = now() WHERE id = $1", [ids.OWNER])).rejects.toThrow(/at least one active OWNER/);
    await expect(asTenant(db, orgA, "DELETE FROM users WHERE id = $1", [ids.OWNER])).rejects.toThrow(/at least one active OWNER/);
    // With a second OWNER the first may step down.
    await onboard(jwt.OWNER!, "owner2@dir-a.example", "OWNER", "OWNER2");
    const r = await call("PATCH", `/v1/users/${ids.OWNER2}`, jwt.OWNER!, { disabled: true });
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ disabled: true, role: "OWNER" });
  });
});

describe("changes take effect immediately", () => {
  it("disabling a user rejects their existing access token AND their refresh token", async () => {
    await onboard(jwt.OWNER!, "leaver@dir-a.example", "DEVELOPER", "LEAVER");
    expect((await call("GET", "/v1/auth/me", jwt.LEAVER!)).statusCode).toBe(200);
    expect((await call("DELETE", `/v1/users/${ids.LEAVER}`, jwt.ADMIN!)).statusCode).toBe(200);
    expect((await call("GET", "/v1/auth/me", jwt.LEAVER!)).statusCode).toBe(401);
    expect((await app.inject({ method: "POST", url: "/v1/auth/refresh", payload: { refresh_token: refresh.LEAVER } })).statusCode).toBe(401);
    const revoked = (await db.query<{ n: string }>("SELECT count(*) AS n FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL", [ids.LEAVER])).rows[0]!;
    expect(Number(revoked.n)).toBe(0);
    expect((await app.inject({ method: "POST", url: "/v1/auth/login", payload: { email: "leaver@dir-a.example", password: PW } })).statusCode).toBe(401);
    // Re-enabling restores access (with a fresh login).
    expect((await call("PATCH", `/v1/users/${ids.LEAVER}`, jwt.ADMIN!, { disabled: false })).statusCode).toBe(200);
    expect((await call("GET", "/v1/auth/me", (await login("leaver@dir-a.example")).access_token)).statusCode).toBe(200);
  });

  it("a demotion applies to the user's already-issued token on the next request", async () => {
    await onboard(jwt.OWNER!, "admin2@dir-a.example", "ADMIN", "ADMIN2");
    expect((await call("GET", "/v1/users", jwt.ADMIN2!)).statusCode).toBe(200);
    expect((await call("PATCH", `/v1/users/${ids.ADMIN2}`, jwt.OWNER!, { role: "VIEWER" })).json()).toMatchObject({ role: "VIEWER" });
    expect((await call("GET", "/v1/users", jwt.ADMIN2!)).statusCode).toBe(403);
    expect((await call("GET", "/v1/auth/me", jwt.ADMIN2!)).json()).toMatchObject({ role: "VIEWER" });
  });
});

describe("tenant isolation", () => {
  it("another organization's users, invitations and teams are invisible (404, never 403)", async () => {
    const inv = (await invite(jwt.OWNER!, "iso@dir-a.example", "VIEWER")).json();
    const team = (await call("POST", "/v1/teams", jwt.OWNER!, { name: "isolated" })).json();
    expect((await call("PATCH", `/v1/users/${ids.DEV}`, jwt.OWNER_B!, { role: "VIEWER" })).statusCode).toBe(404);
    expect((await call("DELETE", `/v1/users/${ids.DEV}`, jwt.OWNER_B!)).statusCode).toBe(404);
    expect((await call("DELETE", `/v1/invitations/${inv.id}`, jwt.OWNER_B!)).statusCode).toBe(404);
    expect((await call("DELETE", `/v1/teams/${team.id}`, jwt.OWNER_B!)).statusCode).toBe(404);
    const teamB = (await call("POST", "/v1/teams", jwt.OWNER_B!, { name: "b-team" })).json();
    expect((await call("PUT", `/v1/teams/${teamB.id}/members/${ids.DEV}`, jwt.OWNER_B!)).statusCode).toBe(404);   // A's user into B's team
    expect((await call("PUT", `/v1/teams/${team.id}/members/${ids.OWNER_B}`, jwt.OWNER!)).statusCode).toBe(404);  // B's user into A's team
    const listB = (await call("GET", "/v1/users", jwt.OWNER_B!)).json().users as { email: string }[];
    expect(listB.map((u) => u.email)).toEqual(["owner@dir-b.example"]);
    expect((await call("GET", "/v1/invitations", jwt.OWNER_B!)).json().invitations).toEqual([]);
  });
});

describe("teams", () => {
  it("create, add/remove members, duplicate names, delete - all audited", async () => {
    const t = await call("POST", "/v1/teams", jwt.ADMIN!, { name: "payments" });
    expect(t.statusCode).toBe(201);
    expect((await call("POST", "/v1/teams", jwt.ADMIN!, { name: "payments" })).statusCode).toBe(409);
    const id = t.json().id as string;
    expect((await call("PUT", `/v1/teams/${id}/members/${ids.DEV}`, jwt.ADMIN!)).statusCode).toBe(204);
    expect((await call("PUT", `/v1/teams/${id}/members/${ids.DEV}`, jwt.ADMIN!)).statusCode).toBe(204);   // idempotent
    const users = (await call("GET", "/v1/users", jwt.ADMIN!)).json().users as { id: string; teams: string[] }[];
    expect(users.find((u) => u.id === ids.DEV)!.teams).toContain("payments");
    expect((await call("DELETE", `/v1/teams/${id}/members/${ids.DEV}`, jwt.ADMIN!)).statusCode).toBe(204);
    expect((await call("DELETE", `/v1/teams/${id}/members/${ids.DEV}`, jwt.ADMIN!)).statusCode).toBe(404);
    expect((await call("DELETE", `/v1/teams/${id}`, jwt.ADMIN!)).statusCode).toBe(204);
    const actions = (await db.query<{ action: string }>("SELECT action FROM audit_logs WHERE organization_id = $1 AND target = $2 ORDER BY \"timestamp\"", [orgA, id])).rows.map((r) => r.action);
    expect(actions).toEqual(["team.create", "team.member_add", "team.member_add", "team.member_remove", "team.delete"]);
  });

  it("the audit trail records who did what, and never an invitation token", async () => {
    const rows = (await db.query<{ action: string; metadata: unknown }>("SELECT action, metadata FROM audit_logs WHERE organization_id = $1", [orgA])).rows;
    const actions = new Set(rows.map((r) => r.action));
    for (const a of ["invitation.create", "invitation.accept", "invitation.revoke", "user.disable", "user.enable", "user.role_change"]) expect(actions, a).toContain(a);
    expect(JSON.stringify(rows)).not.toMatch(/sni_[A-Za-z0-9_-]{43}/);
  });
});
