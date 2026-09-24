import { randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AiRouter, OpenAIProvider } from "@sentinelai/ai-router";
import { buildApp } from "../../src/app.js";
import { PgAuditLogWriter } from "../../src/events/auditLog.js";
import { PgEventSink } from "../../src/events/eventSink.js";
import { OrgRouterSource } from "../../src/providers/orgRouters.js";
import { PgApiKeyRepository } from "../../src/repositories/apiKeyRepository.js";
import { PgAuthRepository } from "../../src/repositories/authRepository.js";
import { PgDirectoryRepository } from "../../src/repositories/directoryRepository.js";
import { PgPolicyRepository } from "../../src/repositories/policyRepository.js";
import { PgProviderRepository } from "../../src/repositories/providerRepository.js";
import { DbApiKeyAuthenticator } from "../../src/security/apiKeys.js";
import { CompositeAuthenticator } from "../../src/security/authenticators.js";
import { CredentialCipher, CredentialDecryptError, parseCredentialKeys } from "../../src/security/credentialCipher.js";
import { AccessTokens } from "../../src/security/tokens.js";
import { AuthService } from "../../src/services/authService.js";
import { SecureAiService } from "../../src/services/secureAiService.js";
import { SecureStreamService } from "../../src/services/secureStreamService.js";
import { FakeScanner, PgliteTenantDb, TEST_CONFIG } from "../helpers/fakes.js";
import { createMigratedDb, type TestDb } from "../helpers/testDb.js";

// Synthetic, obviously-fake credentials. None of these is a real provider key.
const PLATFORM_KEY = "platform-openai-key-0000000000PLAT";
const ORG_A_KEY = "org-a-openai-key-11111111111111AAAA";
const k = (id: string) => ({ id, key: randomBytes(32) });

describe("CredentialCipher", () => {
  const cipher = new CredentialCipher([k("k1")]);
  it("round-trips, and the ciphertext does not contain the plaintext", () => {
    const s = cipher.seal("org-1", "openai", ORG_A_KEY);
    expect(s.keyId).toBe("k1");
    expect(s.blob.toString("latin1")).not.toContain(ORG_A_KEY);
    expect(cipher.open("org-1", "openai", s.keyId, s.blob)).toBe(ORG_A_KEY);
  });
  it("is bound to organization and provider (a copied row fails, it is never lent to another tenant)", () => {
    const s = cipher.seal("org-1", "openai", ORG_A_KEY);
    expect(() => cipher.open("org-2", "openai", s.keyId, s.blob)).toThrow(CredentialDecryptError);
    expect(() => cipher.open("org-1", "anthropic", s.keyId, s.blob)).toThrow(CredentialDecryptError);
  });
  it("any tampering, truncation or unknown key id fails", () => {
    const s = cipher.seal("org-1", "openai", ORG_A_KEY);
    for (let i = 0; i < s.blob.length; i += 7) {
      const t = Buffer.from(s.blob); t[i] = t[i]! ^ 1;
      expect(() => cipher.open("org-1", "openai", s.keyId, t), `byte ${i}`).toThrow(CredentialDecryptError);
    }
    expect(() => cipher.open("org-1", "openai", s.keyId, s.blob.subarray(0, 20))).toThrow(CredentialDecryptError);
    expect(() => cipher.open("org-1", "openai", "k9", s.blob)).toThrow(/unknown key id/);
  });
  it("rotation: new seals use the first key; credentials sealed with a retired-but-configured key stay readable", () => {
    const old = k("old"); const next = k("new");
    const sealedOld = new CredentialCipher([old]).seal("o", "openai", ORG_A_KEY);
    const rotated = new CredentialCipher([next, old]);
    expect(rotated.open("o", "openai", "old", sealedOld.blob)).toBe(ORG_A_KEY);
    expect(rotated.seal("o", "openai", "x".repeat(20)).keyId).toBe("new");
    expect(() => new CredentialCipher([next]).open("o", "openai", "old", sealedOld.blob)).toThrow(CredentialDecryptError);
  });
  it("config parsing rejects short keys, bad ids and duplicates without echoing key material", () => {
    const good = randomBytes(32).toString("base64");
    expect(parseCredentialKeys(`k1:${good}`)[0]!.id).toBe("k1");
    const short = randomBytes(16).toString("base64");
    expect(() => parseCredentialKeys(`k1:${short}`)).toThrow(/32 bytes/);
    try { parseCredentialKeys(`k1:${short}`); } catch (e) { expect((e as Error).message).not.toContain(short); }
    expect(() => parseCredentialKeys(`bad id:${good}`)).toThrow();
    expect(() => parseCredentialKeys(`k1:${good},k1:${good}`)).toThrow(/duplicate/);
  });
});

// ---------------------------------------------------------------- end to end through the gateway
let db: TestDb; let app: FastifyInstance; let orgA: string; let orgB: string;
const jwt: Record<string, string> = {};
const PW = "Tr0ub4dor&3-horse-staple";
const PEPPER = "p".repeat(40);
const cipher = new CredentialCipher([k("k1")]);
let routers: OrgRouterSource;
let scanner: FakeScanner;
/** Every request the OpenAI adapter makes, whichever key built it. Nothing leaves the process. */
const sent: { url: string; auth: string | null; stream: boolean }[] = [];
const fakeFetch: typeof fetch = async (input, init) => {
  const headers = new Headers(init?.headers);
  const body = JSON.parse(String(init?.body ?? "{}"));
  sent.push({ url: String(input), auth: headers.get("authorization"), stream: !!body.stream });
  if (body.stream) {
    const sse = `data: ${JSON.stringify({ choices: [{ delta: { content: "streamed reply" } }] })}\n\ndata: [DONE]\n\n`;
    return new Response(sse, { status: 200, headers: { "content-type": "text/event-stream" } });
  }
  return new Response(JSON.stringify({ model: "gpt-test", choices: [{ message: { content: "a harmless reply" }, finish_reason: "stop" }] }),
    { status: 200, headers: { "content-type": "application/json" } });
};

type Method = "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
const call = (method: Method, url: string, token: string, payload?: unknown) =>
  app.inject({ method, url, headers: { authorization: `Bearer ${token}` }, ...(payload !== undefined ? { payload: payload as object } : {}) });
const chat = (token: string) => call("POST", "/v1/ai/chat", token, { provider: "openai", messages: [{ role: "user", content: "hello" }] });

beforeAll(async () => {
  db = await createMigratedDb({ allowRealServer: true });
  const tdb = new PgliteTenantDb(db);
  const tokens = new AccessTokens({ secret: TEST_CONFIG.jwtAccessSecret!, ttlSeconds: 900 });
  scanner = new FakeScanner(); const events = new PgEventSink(tdb); const policies = new PgPolicyRepository(tdb); const audit = new PgAuditLogWriter(tdb);
  const directory = new PgDirectoryRepository(tdb); const repo = new PgProviderRepository(tdb);
  const platform = new AiRouter().register(new OpenAIProvider({ apiKey: PLATFORM_KEY, fetch: fakeFetch }));
  routers = new OrgRouterSource({ platform, repo, cipher, fetch: fakeFetch, ttlMs: 60_000 });
  const service = new SecureAiService({ scanner, router: platform, routers, policies, events });
  app = buildApp({
    config: { ...TEST_CONFIG, apiKeyPepper: PEPPER }, scanner, events, policies, auditLog: audit, ping: async () => true,
    auth: new CompositeAuthenticator(new DbApiKeyAuthenticator(tdb, PEPPER), tokens, directory),
    service, streaming: new SecureStreamService({ service }),
    authService: new AuthService({ repo: new PgAuthRepository(tdb), tokens, audit, accessTtlSeconds: 900, refreshTtlSeconds: 86_400 }),
    apiKeys: new PgApiKeyRepository(tdb, PEPPER), directory, providerSettings: { repo, routers, cipher, platformProviders: platform.ids() },
    signupEnabled: true, authLimits: { ipPerMinute: 100_000, emailPerMinute: 100_000 },
  }, { logger: false });
  const signup = async (org: string, email: string) => (await app.inject({ method: "POST", url: "/v1/auth/signup", payload: { organization_name: org, email, password: PW } })).json();
  const a = await signup("Prov A", "owner@prov-a.example"); const b = await signup("Prov B", "owner@prov-b.example");
  orgA = a.user.organization_id; orgB = b.user.organization_id; jwt.A = a.access_token; jwt.B = b.access_token;
  const inv = (await call("POST", "/v1/invitations", jwt.A!, { email: "dev@prov-a.example", role: "DEVELOPER" })).json();
  await app.inject({ method: "POST", url: "/v1/invitations/accept", payload: { token: inv.token, password: PW } });
  jwt.DEV = (await app.inject({ method: "POST", url: "/v1/auth/login", payload: { email: "dev@prov-a.example", password: PW } })).json().access_token;
});
afterAll(async () => { await app?.close(); await db?.close(); });
beforeEach(() => { sent.length = 0; });

describe("managing an organization's provider credential", () => {
  it("only providers:manage holders with a user session may manage credentials", async () => {
    expect((await call("GET", "/v1/providers", jwt.DEV!)).statusCode).toBe(403);
    expect((await call("PUT", "/v1/providers/openai/credential", jwt.DEV!, { api_key: ORG_A_KEY })).statusCode).toBe(403);
    const key = (await call("POST", "/v1/api-keys", jwt.A!, { name: "auto", role: "OWNER" })).json().key as string;
    const r = await call("PUT", "/v1/providers/openai/credential", key, { api_key: ORG_A_KEY });
    expect(r.statusCode).toBe(403);
    expect(r.json()).toMatchObject({ reason: "user_session_required" });
  });

  it("stores ciphertext only; responses show a 4-character hint and never the key", async () => {
    const put = await call("PUT", "/v1/providers/openai/credential", jwt.A!, { api_key: ORG_A_KEY });
    expect(put.statusCode).toBe(204);
    const row = (await db.query<{ credentials_encrypted: Uint8Array; credential_key_id: string; credential_hint: string }>(
      "SELECT credentials_encrypted, credential_key_id, credential_hint FROM providers WHERE organization_id = $1 AND provider_type = 'openai'", [orgA])).rows[0]!;
    expect(Buffer.from(row.credentials_encrypted).toString("latin1")).not.toContain(ORG_A_KEY);
    expect(row.credential_key_id).toBe("k1");
    expect(row.credential_hint).toBe("AAAA");
    const list = await call("GET", "/v1/providers", jwt.A!);
    expect(list.body).not.toContain(ORG_A_KEY);
    expect(list.body).not.toContain(ORG_A_KEY.slice(0, 16));
    expect(list.json().providers.find((p: { provider: string }) => p.provider === "openai")).toMatchObject({
      source: "organization", enabled: true, organization_credential: { hint: "AAAA", key_id: "k1" } });
    const audits = JSON.stringify((await db.query("SELECT * FROM audit_logs WHERE organization_id = $1", [orgA])).rows);
    expect(audits).toContain("provider.credential_set");
    expect(audits).not.toContain(ORG_A_KEY);
  });

  it("rejects malformed keys without echoing them, unknown providers, and tenant base URLs", async () => {
    const bad = await call("PUT", "/v1/providers/openai/credential", jwt.A!, { api_key: "has space in-it-0000000000" });
    expect(bad.statusCode).toBe(422);
    expect(bad.body).not.toContain("has space");
    expect((await call("PUT", "/v1/providers/openai/credential", jwt.A!, { api_key: "k".repeat(20), base_url: "http://169.254.169.254" })).statusCode).toBe(422);
    expect((await call("PUT", "/v1/providers/ollama/credential", jwt.A!, { api_key: "k".repeat(20) })).statusCode).toBe(404);
    expect((await call("PUT", "/v1/providers/../credential", jwt.A!, { api_key: "k".repeat(20) })).statusCode).toBe(404);
    await expect(db.query("UPDATE providers SET base_url = 'http://10.0.0.1' WHERE organization_id = $1", [orgA])).rejects.toThrow(/providers_no_tenant_base_url/);
  });
});

describe("per-organization routing", () => {
  it("organization A's requests use A's key; organization B (no credential) uses the platform key", async () => {
    expect((await chat(jwt.A!)).statusCode).toBe(200);
    expect((await chat(jwt.B!)).statusCode).toBe(200);
    expect(sent.map((s) => s.auth)).toEqual([`Bearer ${ORG_A_KEY}`, `Bearer ${PLATFORM_KEY}`]);
  });

  it("streaming uses the same per-organization key", async () => {
    const r = await call("POST", "/v1/ai/stream", jwt.A!, { provider: "openai", messages: [{ role: "user", content: "hello" }] });
    expect(r.statusCode).toBe(200);
    expect(r.body).toContain("event: done");
    expect(sent).toEqual([expect.objectContaining({ auth: `Bearer ${ORG_A_KEY}`, stream: true })]);
  });

  it("removing the credential falls back to the platform key immediately", async () => {
    expect((await call("DELETE", "/v1/providers/openai/credential", jwt.A!)).statusCode).toBe(204);
    await chat(jwt.A!);
    expect(sent[0]!.auth).toBe(`Bearer ${PLATFORM_KEY}`);
    expect((await call("DELETE", "/v1/providers/openai/credential", jwt.A!)).statusCode).toBe(404);
  });

  it("an organization can disable a provider: its requests are blocked and audited, other organizations are unaffected", async () => {
    expect((await call("PATCH", "/v1/providers/openai", jwt.A!, { enabled: false })).statusCode).toBe(200);
    const r = await chat(jwt.A!);
    expect(r.statusCode).toBe(403);
    expect(r.json()).toMatchObject({ error: "blocked", reason: "unknown_provider", failed_closed: true });
    expect((await chat(jwt.B!)).statusCode).toBe(200);
    expect(sent).toHaveLength(1);
    await call("PATCH", "/v1/providers/openai", jwt.A!, { enabled: true });
  });

  it("an undecryptable credential FAILS CLOSED: no request is sent with any key, and the block is audited", async () => {
    await call("PUT", "/v1/providers/openai/credential", jwt.A!, { api_key: ORG_A_KEY });
    // Move A's ciphertext onto B's row (a DBA error / attack): the AAD binding must refuse it.
    const blob = (await db.query<{ credentials_encrypted: Uint8Array }>("SELECT credentials_encrypted FROM providers WHERE organization_id = $1 AND provider_type='openai'", [orgA])).rows[0]!.credentials_encrypted;
    await db.query(`INSERT INTO providers (organization_id, provider_type, credentials_encrypted, credential_key_id, credential_hint) VALUES ($1,'openai',$2,'k1','AAAA')
                    ON CONFLICT (organization_id, provider_type) DO UPDATE SET credentials_encrypted = EXCLUDED.credentials_encrypted, credential_key_id = 'k1'`, [orgB, blob]);
    routers.invalidate(orgB);
    const r = await chat(jwt.B!);
    expect(r.statusCode).toBe(403);
    expect(r.json()).toMatchObject({ error: "blocked", stage: "input", reason: "provider_config_unavailable", failed_closed: true });
    expect(sent).toEqual([]);                       // neither A's key nor the platform key was used
    const ev = (await db.query<{ action: string }>("SELECT action FROM security_events WHERE organization_id = $1 AND id = $2", [orgB, r.json().event_id])).rows[0];
    expect(ev?.action).toBe("BLOCK");
    const s = await call("POST", "/v1/ai/stream", jwt.B!, { provider: "openai", messages: [{ role: "user", content: "hello" }] });
    expect(s.statusCode).toBe(403);
    expect(sent).toEqual([]);
    // A is unaffected by B's broken row.
    expect((await chat(jwt.A!)).statusCode).toBe(200);
    expect(sent[0]!.auth).toBe(`Bearer ${ORG_A_KEY}`);
  });

  it("no credential storage configured: an organization with a stored credential fails closed rather than falling back", async () => {
    const repo = new PgProviderRepository(new PgliteTenantDb(db));
    const noKeys = new OrgRouterSource({ platform: new AiRouter().register(new OpenAIProvider({ apiKey: PLATFORM_KEY, fetch: fakeFetch })), repo, cipher: undefined });
    await expect(noKeys.routerFor(orgA)).rejects.toThrow(/PROVIDER_CREDENTIAL_KEYS/);
  });
});

describe("credential storage not configured", () => {
  it("PUT answers 503 and stores nothing; GET says storage is not configured", async () => {
    const { default: Fastify } = await import("fastify");
    const { registerProviderRoutes } = await import("../../src/routes/providerRoutes.js");
    const stored: unknown[] = [];
    const f = Fastify();
    registerProviderRoutes(f, {
      auth: { authenticate: async () => ({ organizationId: orgA, role: "OWNER", userId: "00000000-0000-4000-8000-000000000001", apiKeyId: null }) },
      repo: { list: async () => [], setCredential: async (...a: unknown[]) => { stored.push(a); }, clearCredential: async () => false, setEnabled: async () => undefined },
      routers: { routerFor: async () => new AiRouter(), invalidate: () => undefined },
      auditLog: { record: async () => undefined } as never, platformProviders: [], cipher: undefined,
    });
    const put = await f.inject({ method: "PUT", url: "/v1/providers/openai/credential", headers: { authorization: "Bearer x" }, payload: { api_key: ORG_A_KEY } });
    expect(put.statusCode).toBe(503);
    expect(put.json()).toEqual({ error: "credential_storage_not_configured" });
    expect(stored).toEqual([]);
    const get = await f.inject({ method: "GET", url: "/v1/providers", headers: { authorization: "Bearer x" } });
    expect(get.json().credential_storage).toBe("not_configured");
    await f.close();
  });
});
