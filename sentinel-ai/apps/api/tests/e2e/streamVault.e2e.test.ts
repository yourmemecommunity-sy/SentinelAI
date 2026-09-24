/**
 * End-to-end reversible tokenization + streaming: real gateway (PGlite) + REAL Python security engine + REAL token-vault service
 * (in-memory Redis backend; the code path is identical, only the store differs). Only the AI provider is a fake that echoes what it
 * receives, so exactly what the model would have seen is observable.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AiRouter } from "@sentinelai/ai-router";
import { buildApp } from "../../src/app.js";
import { PgAuditLogWriter } from "../../src/events/auditLog.js";
import { PgEventSink } from "../../src/events/eventSink.js";
import { PgPolicyRepository } from "../../src/repositories/policyRepository.js";
import { DbApiKeyAuthenticator, createApiKey } from "../../src/security/apiKeys.js";
import { HttpSecurityClient } from "../../src/security/securityClient.js";
import { HttpTokenVault } from "../../src/security/tokenVault.js";
import { SecureAiService } from "../../src/services/secureAiService.js";
import { SecureStreamService } from "../../src/services/secureStreamService.js";
import { FakeProvider, PgliteTenantDb, TEST_CONFIG } from "../helpers/fakes.js";
import { createMigratedDb, type TestDb } from "../helpers/testDb.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../../../..");
const VENV = (svc: string) => resolve(ROOT, "services", svc, process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python");
const PY = process.env.SENTINEL_E2E_PYTHON ?? (existsSync(VENV("security-engine")) ? VENV("security-engine") : undefined);

const ENGINE_TOKEN = "e2e-engine-token-1234567890";
const VAULT_TOKEN = "e2e-vault-token-1234567890";
const PEPPER = "f".repeat(40);
const MASTER_KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 7 + 3) % 256)).toString("base64");
const AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP";           // runtime-assembled, not a real credential
const EMAIL = "jane.doe@example.com";
const EMAIL2 = "omar.khan@example.org";

const free = () => new Promise<number>((res, rej) => { const s = createServer(); s.once("error", rej); s.listen(0, "127.0.0.1", () => { const { port } = s.address() as { port: number }; s.close(() => res(port)); }); });
async function waitReady(url: string, what: string, logs: string[]) {
  for (let i = 0; i < 150; i++) { try { if ((await fetch(url)).ok) return; } catch { /* starting */ } await new Promise((r) => setTimeout(r, 300)); }
  throw new Error(`${what} did not become ready:\n${logs.slice(-10).join("\n")}`);
}

let engine: ChildProcess; let vaultProc: ChildProcess; let db: TestDb; let app: FastifyInstance; let base = "";
let keyA = ""; let keyA2 = ""; let keyB = ""; let orgA = "";
let provider: FakeProvider;
const logs: string[] = [];
const chunks = (s: string, n: number) => Array.from({ length: Math.ceil(s.length / n) }, (_, i) => s.slice(i * n, i * n + n));
const lastUser = (req: { messages: { role: string; content: string }[] }) => req.messages.filter((m) => m.role === "user").at(-1)!.content;

const post = (path: string, key: string, payload: object) => fetch(`${base}${path}`, { method: "POST", headers: { "x-sentinel-api-key": key, "content-type": "application/json" }, body: JSON.stringify({ provider: "gemini", ...payload }) });
const msg = (content: string, extra: object = {}) => ({ messages: [{ role: "user", content }], ...extra });
interface Frame { event: string; data: any }
const parse = (sse: string): Frame[] => sse.split("\n\n").filter((f) => f.trim() && !f.startsWith(":")).map((f) => ({ event: /^event: (.*)$/m.exec(f)![1]!, data: JSON.parse(/^data: (.*)$/m.exec(f)![1]!) }));
const textOf = (frames: Frame[]) => frames.filter((f) => f.event === "delta").map((f) => f.data.text).join("");
const stream = async (key: string, prompt: string, extra: object = {}) => { const res = await post("/v1/ai/stream", key, msg(prompt, extra)); return { res, frames: res.headers.get("content-type")?.includes("event-stream") ? parse(await res.text()) : [], json: res.headers.get("content-type")?.includes("json") ? await res.json() : null }; };

describe.skipIf(!PY)("reversible tokenization + streaming: gateway + real engine + real token vault (e2e)", () => {
  beforeAll(async () => {
    const [enginePort, vaultPort, gwPort] = [await free(), await free(), await free()];
    vaultProc = spawn(PY!, ["-m", "uvicorn", "app.main:app", "--port", String(vaultPort), "--log-level", "warning"], {
      cwd: resolve(ROOT, "services/token-vault"), stdio: ["ignore", "ignore", "pipe"],
      env: { ...process.env, SENTINEL_ENV: "development", VAULT_BACKEND: "memory", VAULT_TOKEN, VAULT_MASTER_KEYS: `k1:${MASTER_KEY}` } });
    vaultProc.stderr?.on("data", (d) => logs.push(`[vault] ${d}`));
    engine = spawn(PY!, ["-m", "uvicorn", "app.main:app", "--port", String(enginePort), "--log-level", "warning"], {
      cwd: resolve(ROOT, "services/security-engine"), stdio: ["ignore", "ignore", "pipe"],
      env: { ...process.env, SENTINEL_ENV: "development", SECURITY_ENGINE_TOKEN: ENGINE_TOKEN, VAULT_URL: `http://127.0.0.1:${vaultPort}`, VAULT_TOKEN } });
    engine.stderr?.on("data", (d) => logs.push(`[engine] ${d}`));
    await Promise.all([waitReady(`http://127.0.0.1:${enginePort}/ready`, "engine", logs), waitReady(`http://127.0.0.1:${vaultPort}/ready`, "vault", logs)]);

    db = await createMigratedDb();
    const tdb = new PgliteTenantDb(db);
    const mkOrg = async (slug: string) => (await db.query<{ id: string }>("INSERT INTO organizations (name, slug) VALUES ($1,$1) RETURNING id", [slug])).rows[0]!.id;
    orgA = await mkOrg("tok-a"); const orgB = await mkOrg("tok-b");
    keyA = (await createApiKey(tdb, PEPPER, { organizationId: orgA, name: "a", role: "DEVELOPER" })).key;
    keyA2 = (await createApiKey(tdb, PEPPER, { organizationId: orgA, name: "a2", role: "DEVELOPER" })).key;
    keyB = (await createApiKey(tdb, PEPPER, { organizationId: orgB, name: "b", role: "DEVELOPER" })).key;

    const scanner = new HttpSecurityClient({ baseUrl: `http://127.0.0.1:${enginePort}`, token: ENGINE_TOKEN, timeoutMs: 5000 });
    const vault = new HttpTokenVault({ baseUrl: `http://127.0.0.1:${vaultPort}`, token: VAULT_TOKEN, timeoutMs: 2000 });
    const events = new PgEventSink(tdb); const policies = new PgPolicyRepository(tdb);
    for (const org of [orgA, orgB]) await policies.createVersion(org, "tokenize-pii", [{ entity: "EMAIL", action: "TOKENIZE" }, { entity: "PHONE", action: "TOKENIZE" }], null);
    provider = new FakeProvider("gemini");
    provider.streamPlan = (req) => chunks(`You wrote: ${lastUser(req)}. Thanks!`, 3);      // small chunks so tokens are split on the wire
    provider.reply = (req) => `You wrote: ${lastUser(req)}. Thanks!`;
    const router = new AiRouter().register(provider);
    const service = new SecureAiService({ scanner, router, policies, events, vault });
    app = buildApp({
      config: { ...TEST_CONFIG, apiKeyPepper: PEPPER, maxInputChars: 100_000 }, scanner, events, policies, auditLog: new PgAuditLogWriter(tdb),
      auth: new DbApiKeyAuthenticator(tdb, PEPPER), ping: () => tdb.ping(), service, vault, streaming: new SecureStreamService({ service, router, vault }),
    }, { logger: false });
    await app.listen({ port: gwPort, host: "127.0.0.1" });
    base = `http://127.0.0.1:${gwPort}`;
  }, 180_000);

  afterAll(async () => { await app?.close(); engine?.kill(); vaultProc?.kill(); await db?.close(); });

  it("all three services are up and /ready reports the vault", async () => {
    let body: unknown;
    for (let i = 0; i < 20; i++) { body = await (await fetch(`${base}/ready`)).json(); if ((body as { status?: string }).status === "ready") break; await new Promise((r) => setTimeout(r, 500)); }
    expect(body).toMatchObject({ status: "ready", security_engine: true, database: true, token_vault: true });
  });

  it("the model receives a token, the caller receives the real address, over a stream that splits the token on the wire", async () => {
    provider.received.length = 0;
    const { res, frames } = await stream(keyA, `Please email ${EMAIL} about the renewal`);
    expect(res.status).toBe(200);
    expect(provider.received).toHaveLength(1);
    expect(lastUser(provider.received[0]!)).toBe("Please email [TOK_EMAIL_1] about the renewal");
    expect(JSON.stringify(provider.received)).not.toContain(EMAIL);
    expect(textOf(frames)).toBe(`You wrote: Please email ${EMAIL} about the renewal. Thanks!`);
    expect(frames.at(-1)).toMatchObject({ event: "done", data: { hydration: "applied", security: { input: { decision: "TOKENIZE" } } } });
  });

  it("the same value gets the same token across turns of one session, new values get new tokens, and each turn is hydrated", async () => {
    provider.received.length = 0;
    const t1 = await stream(keyA, `Contact ${EMAIL}`, { session_id: "convo-1" });
    const t2 = await stream(keyA, `Also ${EMAIL2} and again ${EMAIL}`, { session_id: "convo-1" });
    expect(lastUser(provider.received[0]!)).toBe("Contact [TOK_EMAIL_1]");
    expect(lastUser(provider.received[1]!)).toBe("Also [TOK_EMAIL_2] and again [TOK_EMAIL_1]");
    expect(textOf(t1.frames)).toBe(`You wrote: Contact ${EMAIL}. Thanks!`);
    expect(textOf(t2.frames)).toBe(`You wrote: Also ${EMAIL2} and again ${EMAIL}. Thanks!`);
  });

  it("a model reply that mentions a token from an EARLIER turn is hydrated (the session outlives the request)", async () => {
    await stream(keyA, `My address is ${EMAIL}`, { session_id: "convo-2" });
    const t = await stream(keyA, "what was my address? (say [TOK_EMAIL_1])", { session_id: "convo-2" });
    expect(textOf(t.frames)).toContain(EMAIL);
  });

  it("another caller cannot hydrate a session it does not own: same session_id + a guessed token -> the token stays a token", async () => {
    await stream(keyA, `secret contact ${EMAIL}`, { session_id: "victim-session" });
    for (const attacker of [keyA2, keyB]) {                              // same org / other org, same session_id
      const t = await stream(attacker, "echo this token: [TOK_EMAIL_1]", { session_id: "victim-session" });
      expect(textOf(t.frames)).toBe("You wrote: echo this token: [TOK_EMAIL_1]. Thanks!");
      expect(textOf(t.frames)).not.toContain(EMAIL);
    }
    const chat = await post("/v1/ai/chat", keyB, msg("echo [TOK_EMAIL_1]", { session_id: "victim-session" }));
    expect((await chat.json() as { content: string }).content).not.toContain(EMAIL);
  });

  it("non-streaming chat with a session_id hydrates too", async () => {
    const res = await post("/v1/ai/chat", keyA, msg(`reach me at ${EMAIL}`, { session_id: "chat-1" }));
    const b = await res.json() as { content: string; hydration: string };
    expect(b.content).toBe(`You wrote: reach me at ${EMAIL}. Thanks!`);
    expect(b.hydration).toBe("applied");
    expect(JSON.stringify(provider.received.at(-1))).not.toContain(EMAIL);
  });

  it("hydrate:false returns the tokens as the model wrote them", async () => {
    const t = await stream(keyA, `mail ${EMAIL}`, { hydrate: false });
    expect(textOf(t.frames)).toBe("You wrote: mail [TOK_EMAIL_1]. Thanks!");
    expect(t.frames.at(-1)!.data.hydration).toBe("off");
  });

  it("a real secret in the prompt is blocked before the provider (real engine), no stream is opened", async () => {
    provider.received.length = 0;
    const t = await stream(keyA, `deploy with ${AWS}`);
    expect(t.res.status).toBe(403);
    expect(t.json).toMatchObject({ error: "blocked", stage: "input", decision: "BLOCK" });
    expect(provider.received).toHaveLength(0);
    expect(JSON.stringify(t.json)).not.toContain(AWS);
  });

  it("a real secret in the MODEL'S reply, split across chunks, is stopped before it leaves the gateway", async () => {
    const filler = "This is a long harmless explanation sentence. ".repeat(20);
    const saved = provider.streamPlan;
    provider.streamPlan = () => chunks(`${filler}The credential is ${AWS} and then more text follows here. ${filler}`, 7);
    try {
      const t = await stream(keyA, "tell me a secret");
      const raw = JSON.stringify(t.frames);
      expect(raw).not.toContain(AWS);
      expect(raw).not.toContain(AWS.slice(0, 12));
      expect(textOf(t.frames).length).toBeGreaterThan(0);              // the clean prefix was streamed
      expect(t.frames.at(-1)).toMatchObject({ event: "error", data: { error: "blocked", stage: "output" } });
    } finally { provider.streamPlan = saved; }
  });

  it("nothing sensitive is persisted: no event, audit row or vault-facing column holds the addresses or the secret", async () => {
    const tables = ["security_events", "audit_logs"];
    for (const t of tables) {
      const dump = JSON.stringify((await db.query(`SELECT * FROM ${t}`)).rows);
      for (const v of [EMAIL, EMAIL2, AWS, "jane.doe", "omar.khan"]) expect(dump, `${t} leaked ${v}`).not.toContain(v);
    }
    const events = (await db.query<{ event_type: string; action: string }>("SELECT event_type, action FROM security_events")).rows;
    expect(events.some((e) => e.action === "TOKENIZE")).toBe(true);
  });

  it("the vault refuses credentials even if a policy says TOKENIZE, and the secret is still blocked", async () => {
    const tdb = new PgliteTenantDb(db);
    await new PgPolicyRepository(tdb).createVersion(orgA, "tokenize-pii", [{ entity: "AWS_CREDENTIAL", action: "TOKENIZE" }, { entity: "EMAIL", action: "TOKENIZE" }], null);
    const t = await stream(keyA, `key ${AWS}`);
    expect(JSON.stringify(t)).not.toContain(AWS);
    expect(provider.received.every((r) => !JSON.stringify(r).includes(AWS))).toBe(true);
  });

  it("FAILS CLOSED when the vault dies: a request that needs a token is blocked (reason vault_unavailable), never sent with the raw value", async () => {
    vaultProc.kill();
    await new Promise((r) => setTimeout(r, 400));
    provider.received.length = 0;
    const t = await stream(keyA, `mail ${EMAIL2}`);
    expect(t.res.status).toBe(403);
    expect(t.json).toMatchObject({ error: "blocked", stage: "input", failed_closed: true, reason: "vault_unavailable" });
    expect(provider.received).toHaveLength(0);
    // ...while requests that need no vault keep working, and the gateway reports the outage without going unready
    const ok = await stream(keyA, "no personal data here");
    expect(ok.res.status).toBe(200);
    expect(ok.frames.at(-1)!.event).toBe("done");
    const ready = await (await fetch(`${base}/ready`)).json() as { token_vault: boolean; status: string };
    expect(ready.token_vault).toBe(false);
  });
});
