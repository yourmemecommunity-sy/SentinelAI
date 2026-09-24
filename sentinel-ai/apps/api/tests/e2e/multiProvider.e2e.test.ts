/**
 * End-to-end across ALL provider adapters: real gateway + REAL Python engine + Postgres (PGlite) + the real
 * Gemini/OpenAI/Anthropic/Ollama adapter classes. Only the outbound network is mocked (each mock speaks that
 * provider's real wire format). Proves the security pipeline is provider-independent.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AiRouter, AnthropicProvider, GeminiProvider, OpenAIProvider } from "@sentinelai/ai-router";
import { buildApp } from "../../src/app.js";
import { PgAuditLogWriter } from "../../src/events/auditLog.js";
import { PgEventSink } from "../../src/events/eventSink.js";
import { registerConfiguredProviders } from "../../src/providers/registry.js";
import { PgPolicyRepository } from "../../src/repositories/policyRepository.js";
import { DbApiKeyAuthenticator, createApiKey } from "../../src/security/apiKeys.js";
import { HttpSecurityClient } from "../../src/security/securityClient.js";
import { SecureAiService } from "../../src/services/secureAiService.js";
import { PgliteTenantDb, TEST_CONFIG } from "../helpers/fakes.js";
import { createMigratedDb, type TestDb } from "../helpers/testDb.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE_DIR = resolve(HERE, "../../../../services/security-engine");
const VENV_PY = resolve(ENGINE_DIR, process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python");
const PYTHON = process.env.SENTINEL_E2E_PYTHON ?? (existsSync(VENV_PY) ? VENV_PY : undefined);
const TOKEN = "e2e-multi-internal-token-1234567890";
const PEPPER = "m".repeat(40);
const AWS_KEY = "AK" + "IA" + "MULTIPROVIDER012"; // runtime-assembled, not a real credential
const EMAIL = "jane.doe@example.com";

type Reply = { url: string; body: string };
const seen: Record<string, Reply[]> = { gemini: [], openai: [], anthropic: [], ollama: [] };
let replyText = "Provider says hello.";

/** One mock network that answers in each provider's genuine response format and records what was sent. */
const network = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = String(input);
  const body = String(init?.body ?? "");
  const j = (o: unknown) => new Response(JSON.stringify(o), { status: 200 });
  if (url.includes("openai.example")) { seen.openai!.push({ url, body }); return j({ model: "gpt-mock", choices: [{ message: { content: replyText }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1 } }); }
  if (url.includes("anthropic.example")) { seen.anthropic!.push({ url, body }); return j({ model: "claude-mock", content: [{ type: "text", text: replyText }], stop_reason: "end_turn", usage: { input_tokens: 1, output_tokens: 1 } }); }
  if (url.includes("ollama.example")) { seen.ollama!.push({ url, body }); return j({ model: "llama-mock", message: { role: "assistant", content: replyText }, done: true, done_reason: "stop" }); }
  if (url.includes("gemini.example")) { seen.gemini!.push({ url, body }); return j({ candidates: [{ content: { parts: [{ text: replyText }] }, finishReason: "STOP" }] }); }
  return new Response("unexpected host", { status: 599 });
}) as unknown as typeof fetch;

function freePort(): Promise<number> {
  return new Promise((res, rej) => { const s = createServer(); s.once("error", rej); s.listen(0, "127.0.0.1", () => { const { port } = s.address() as { port: number }; s.close(() => res(port)); }); });
}

let engine: ChildProcess; let db: TestDb; let app: FastifyInstance; let key: string; let port = 0;
const chat = (provider: string, content: string) => app.inject({ method: "POST", url: "/v1/ai/chat", headers: { "x-sentinel-api-key": key }, payload: { provider, messages: [{ role: "user", content }] } });
const PROVIDERS = ["gemini", "openai", "anthropic", "ollama"] as const;

describe.skipIf(!PYTHON)("all providers behind the gateway + real security engine (e2e)", () => {
  beforeAll(async () => {
    port = await freePort();
    engine = spawn(PYTHON!, ["-m", "uvicorn", "app.main:app", "--port", String(port), "--log-level", "warning"], {
      cwd: ENGINE_DIR, env: { ...process.env, SECURITY_ENGINE_TOKEN: TOKEN, SENTINEL_ENV: "development" }, stdio: ["ignore", "ignore", "pipe"] });
    let err = ""; engine.stderr?.on("data", (d) => { err = (err + String(d)).slice(-1500); });
    for (let i = 0; ; i++) {
      try { if ((await fetch(`http://127.0.0.1:${port}/ready`)).ok) break; } catch { /* starting */ }
      if (i > 100) throw new Error(`engine did not start: ${err}`);
      await new Promise((r) => setTimeout(r, 300));
    }
    db = await createMigratedDb();
    const tdb = new PgliteTenantDb(db);
    const org = (await db.query<{ id: string }>("INSERT INTO organizations (name, slug) VALUES ('mp','mp') RETURNING id")).rows[0]!.id;
    key = (await createApiKey(tdb, PEPPER, { organizationId: org, name: "k", role: "DEVELOPER" })).key;
    const scanner = new HttpSecurityClient({ baseUrl: `http://127.0.0.1:${port}`, token: TOKEN, timeoutMs: 3000 });
    // Real adapters. Gemini/OpenAI/Anthropic are pointed at distinct fake hosts so the mock can tell them apart; Ollama goes
    // through the production registry (it is configured by base URL + model).
    const router = new AiRouter({ sleep: async () => {} })
      .register(new GeminiProvider({ apiKey: "k-gem", baseUrl: "https://gemini.example/v1beta", fetch: network }))
      .register(new OpenAIProvider({ apiKey: "k-oai", baseUrl: "https://openai.example/v1", fetch: network }))
      .register(new AnthropicProvider({ apiKey: "k-ant", baseUrl: "https://anthropic.example", fetch: network }));
    registerConfiguredProviders(router, { geminiApiKey: undefined, openaiApiKey: undefined, anthropicApiKey: undefined,
      ollama: { baseUrl: "http://ollama.example:11434", model: "llama-mock" } }, network);
    const events = new PgEventSink(tdb); const policies = new PgPolicyRepository(tdb);
    app = buildApp({ config: { ...TEST_CONFIG, apiKeyPepper: PEPPER }, scanner, events, policies, auditLog: new PgAuditLogWriter(tdb),
      auth: new DbApiKeyAuthenticator(tdb, PEPPER), service: new SecureAiService({ scanner, router, policies, events }), ping: () => tdb.ping() }, { logger: false });
  }, 90_000);

  afterAll(async () => { await app?.close(); engine?.kill(); await db?.close(); });

  it("the registry only registers configured providers", () => {
    const r = registerConfiguredProviders(new AiRouter(), { geminiApiKey: undefined, openaiApiKey: "x", anthropicApiKey: undefined, ollama: undefined });
    expect(r.ids()).toEqual(["openai"]);
    expect(registerConfiguredProviders(new AiRouter(), { geminiApiKey: undefined, openaiApiKey: undefined, anthropicApiKey: undefined, ollama: undefined }).ids()).toEqual([]);
  });

  it.each(PROVIDERS)("%s: clean prompt round-trips through the real adapter", async (p) => {
    seen[p]!.length = 0;
    const res = await chat(p, "Explain DNS caching briefly.");
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ provider: p, content: "Provider says hello.", security: { input: { decision: "ALLOW" }, output: { decision: "ALLOW" } } });
    expect(seen[p]).toHaveLength(1);
  });

  it.each(PROVIDERS)("%s: PII is masked BEFORE the provider receives it (provider-specific request format)", async (p) => {
    seen[p]!.length = 0;
    const res = await chat(p, `Please email ${EMAIL} about the invoice.`);
    expect(res.statusCode).toBe(200);
    expect(res.json().security.input.decision).toBe("MASK");
    const sent = seen[p]!.map((s) => s.body).join("\n");
    expect(sent).toContain("j***@example.com");
    expect(sent).not.toContain(EMAIL);
    expect(sent).not.toContain("jane.doe");
  });

  it.each(PROVIDERS)("%s: a secret is blocked and the provider is never contacted", async (p) => {
    seen[p]!.length = 0;
    const res = await chat(p, `deploy with ${AWS_KEY} now`);
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ error: "blocked", stage: "input" });
    expect(seen[p]).toHaveLength(0);
    expect(res.body).not.toContain(AWS_KEY);
  });

  it.each(PROVIDERS)("%s: a model response that leaks a secret is withheld from the caller", async (p) => {
    replyText = `Sure, the key is ${AWS_KEY}`;
    const res = await chat(p, "give me an example key");
    replyText = "Provider says hello.";
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ error: "blocked", stage: "output" });
    expect(res.body).not.toContain(AWS_KEY);
  });

  it("unconfigured providers are blocked as unknown_provider and nothing is sent anywhere", async () => {
    const before = PROVIDERS.reduce((n, p) => n + seen[p]!.length, 0);
    const res = await chat("cohere", "hello");
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ failed_closed: true, reason: "unknown_provider" });
    expect(PROVIDERS.reduce((n, p) => n + seen[p]!.length, 0)).toBe(before);
  });

  it("local models are scored lower risk than external providers for identical content (data stays in-network)", async () => {
    const prompt = `contact ${EMAIL}`;
    await chat("openai", prompt); await chat("ollama", prompt);
    const rows = (await db.query<{ provider: string; risk_score: number }>(
      "SELECT provider, risk_score FROM security_events WHERE direction = 'INPUT' AND provider IN ('openai','ollama') AND action = 'MASK' ORDER BY \"timestamp\" DESC LIMIT 2")).rows;
    const score = (p: string) => rows.find((r) => r.provider === p)!.risk_score;
    expect(score("ollama")).toBeLessThan(score("openai"));
  });

  it("no provider traffic left any sensitive content in the database, and usage is tracked per provider", async () => {
    const tables = (await db.query<{ table_name: string }>("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'")).rows;
    let dump = "";
    for (const t of tables) dump += JSON.stringify((await db.query(`SELECT * FROM ${t.table_name}`)).rows);
    for (const s of [AWS_KEY, EMAIL, "jane.doe", "Explain DNS", "Provider says hello"]) expect(dump, s).not.toContain(s);
    const usage = (await db.query<{ provider: string }>("SELECT DISTINCT provider FROM usage")).rows.map((r) => r.provider).sort();
    expect(usage).toEqual([...PROVIDERS].sort());
  });
});
