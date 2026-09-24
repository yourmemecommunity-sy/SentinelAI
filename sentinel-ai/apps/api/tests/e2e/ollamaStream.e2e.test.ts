/**
 * REAL provider streaming, end to end: gateway SSE -> real AI router -> REAL Ollama server -> real Python security engine ->
 * real token-vault process -> Postgres (PGlite).
 *
 * Nothing is mocked except the database engine. A recording proxy sits between the router and Ollama so tests can assert on the exact
 * bytes the real model server received, and can also rewrite the real NDJSON stream to inject content at genuine chunk boundaries
 * (the only deterministic way to test output blocking, since a 0.5B model cannot be relied on to emit a chosen string).
 *
 * Skipped unless a local Ollama with at least one model is reachable. Nothing is downloaded here.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer as createHttpServer, type Server } from "node:http";
import { createServer } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AiRouter, OllamaProvider } from "@sentinelai/ai-router";
import { buildApp } from "../../src/app.js";
import { PgAuditLogWriter } from "../../src/events/auditLog.js";
import { PgEventSink } from "../../src/events/eventSink.js";
import { PgPolicyRepository } from "../../src/repositories/policyRepository.js";
import { DbApiKeyAuthenticator, createApiKey } from "../../src/security/apiKeys.js";
import { HttpSecurityClient } from "../../src/security/securityClient.js";
import { HttpTokenVault } from "../../src/security/tokenVault.js";
import { SecureAiService } from "../../src/services/secureAiService.js";
import { SecureStreamService } from "../../src/services/secureStreamService.js";
import { PgliteTenantDb, TEST_CONFIG } from "../helpers/fakes.js";
import { createMigratedDb, type TestDb } from "../helpers/testDb.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../../../..");
const VENV = resolve(ROOT, "services/security-engine", process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python");
const PY = process.env.SENTINEL_E2E_PYTHON ?? (existsSync(VENV) ? VENV : undefined);
const OLLAMA = process.env.OLLAMA_URL ?? "http://127.0.0.1:11434";

const MODELS: string[] | null = await fetch(`${OLLAMA}/api/tags`, { signal: AbortSignal.timeout(2000) })
  .then(async (r) => ((await r.json()) as { models: { name: string }[] }).models.map((m) => m.name).sort((a, b) => a.length - b.length))
  .catch(() => null);
const MODEL = MODELS?.[0];
const READY = !!PY && !!MODEL;

const ENGINE_TOKEN = "e2e-ollama-engine-token-1234";
const VAULT_TOKEN = "e2e-ollama-vault-token-1234";
const PEPPER = "c".repeat(40);
const AWS = "AK" + "IA" + "ABCDEFGHIJKLMNOP";         // runtime-assembled, not a real credential
const EMAIL = "jane.doe@example.com";

const free = () => new Promise<number>((res, rej) => { const s = createServer(); s.once("error", rej); s.listen(0, "127.0.0.1", () => { const { port } = s.address() as { port: number }; s.close(() => res(port)); }); });
async function waitReady(url: string, what: string, logs: string[]) {
  for (let i = 0; i < 150; i++) { try { if ((await fetch(url)).ok) return; } catch { /* starting */ } await new Promise((r) => setTimeout(r, 300)); }
  throw new Error(`${what} did not become ready:\n${logs.slice(-8).join("\n")}`);
}

/** Records every request body sent to the real Ollama, and can rewrite the real NDJSON response stream. */
interface Proxy { url: string; seen: string[]; rewrite: ((line: string, index: number) => string | string[]) | null; close: () => void }
async function startProxy(): Promise<Proxy> {
  const p: Proxy = { url: "", seen: [], rewrite: null, close: () => undefined };
  const server: Server = createHttpServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const body = Buffer.concat(chunks);
      if (req.url?.startsWith("/api/chat")) p.seen.push(body.toString());
      try {
        const upstream = await fetch(`${OLLAMA}${req.url}`, { method: req.method ?? "GET", headers: { "content-type": "application/json" }, ...(req.method === "GET" ? {} : { body }) });
        res.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "application/json" });
        if (!upstream.body) { res.end(); return; }
        const reader = upstream.body.getReader();
        const decoder = new TextDecoder();
        let buf = ""; let index = 0;
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          let nl: number;
          while ((nl = buf.indexOf("\n")) !== -1) {
            const line = buf.slice(0, nl);
            buf = buf.slice(nl + 1);
            if (!line.trim()) continue;
            const out = p.rewrite ? p.rewrite(line, index++) : line;
            for (const l of Array.isArray(out) ? out : [out]) res.write(`${l}\n`);
          }
        }
        if (buf.trim()) res.write(`${p.rewrite ? p.rewrite(buf, index++) : buf}\n`);
        res.end();
      } catch { res.writeHead(502); res.end(); }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  p.url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  p.close = () => server.close();
  return p;
}

/** One NDJSON line carrying a piece of assistant text, in Ollama's real shape. */
const ndjson = (content: string) => JSON.stringify({ model: MODEL, message: { role: "assistant", content }, done: false });

let engine: ChildProcess; let vaultProc: ChildProcess; let db: TestDb; let app: FastifyInstance; let base = ""; let proxy: Proxy; let key = "";

interface Frame { event: string; data: any }
const parse = (sse: string): Frame[] => sse.split("\n\n").filter((f) => f.trim() && !f.startsWith(":")).map((f) => ({ event: /^event: (.*)$/m.exec(f)![1]!, data: JSON.parse(/^data: (.*)$/m.exec(f)![1]!) }));
const textOf = (f: Frame[]) => f.filter((x) => x.event === "delta").map((x) => x.data.text).join("");
const post = (path: string, payload: object) => fetch(`${base}${path}`, { method: "POST", headers: { "x-sentinel-api-key": key, "content-type": "application/json" }, body: JSON.stringify({ provider: "ollama", ...payload }) });
const streamIt = async (prompt: string, extra: object = {}) => {
  const res = await post("/v1/ai/stream", { messages: [{ role: "user", content: prompt }], max_output_tokens: 48, ...extra });
  const ct = res.headers.get("content-type") ?? "";
  return { res, frames: ct.includes("event-stream") ? parse(await res.text()) : [], json: ct.includes("json") ? await res.json() as any : null };
};

describe.skipIf(!READY)(`REAL Ollama streaming through the gateway (model: ${MODEL ?? "none"})`, () => {
  beforeAll(async () => {
    const logs: string[] = [];
    const [enginePort, vaultPort, gwPort] = [await free(), await free(), await free()];
    proxy = await startProxy();

    vaultProc = spawn(PY!, ["-m", "uvicorn", "app.main:app", "--port", String(vaultPort), "--log-level", "warning"], {
      cwd: resolve(ROOT, "services/token-vault"), stdio: ["ignore", "ignore", "pipe"],
      env: { ...process.env, SENTINEL_ENV: "development", VAULT_BACKEND: "memory", VAULT_TOKEN } });
    vaultProc.stderr?.on("data", (d) => logs.push(`[vault] ${d}`));
    engine = spawn(PY!, ["-m", "uvicorn", "app.main:app", "--port", String(enginePort), "--log-level", "warning"], {
      cwd: resolve(ROOT, "services/security-engine"), stdio: ["ignore", "ignore", "pipe"],
      env: { ...process.env, SENTINEL_ENV: "development", SECURITY_ENGINE_TOKEN: ENGINE_TOKEN, VAULT_URL: `http://127.0.0.1:${vaultPort}`, VAULT_TOKEN } });
    engine.stderr?.on("data", (d) => logs.push(`[engine] ${d}`));
    await Promise.all([waitReady(`http://127.0.0.1:${enginePort}/ready`, "engine", logs), waitReady(`http://127.0.0.1:${vaultPort}/ready`, "vault", logs)]);

    db = await createMigratedDb();
    const tdb = new PgliteTenantDb(db);
    const org = (await db.query<{ id: string }>("INSERT INTO organizations (name, slug) VALUES ($1,$1) RETURNING id", ["ollama-e2e"])).rows[0]!.id;
    key = (await createApiKey(tdb, PEPPER, { organizationId: org, name: "k", role: "DEVELOPER" })).key;

    const scanner = new HttpSecurityClient({ baseUrl: `http://127.0.0.1:${enginePort}`, token: ENGINE_TOKEN, timeoutMs: 8000 });
    const vault = new HttpTokenVault({ baseUrl: `http://127.0.0.1:${vaultPort}`, token: VAULT_TOKEN, timeoutMs: 2000 });
    const events = new PgEventSink(tdb); const policies = new PgPolicyRepository(tdb);
    await policies.createVersion(org, "tokenize-email", [{ entity: "EMAIL", action: "TOKENIZE" }], null);
    // The router talks to the recording proxy, which forwards to the real Ollama.
    const router = new AiRouter().register(new OllamaProvider({ defaultModel: MODEL!, baseUrl: proxy.url, timeoutMs: 180_000 }));
    const service = new SecureAiService({ scanner, router, policies, events, vault });
    app = buildApp({
      config: { ...TEST_CONFIG, apiKeyPepper: PEPPER, maxInputChars: 100_000, stream: { ...TEST_CONFIG.stream, idleTimeoutMs: 120_000, maxDurationMs: 240_000 } },
      scanner, events, policies, auditLog: new PgAuditLogWriter(tdb), auth: new DbApiKeyAuthenticator(tdb, PEPPER), ping: () => tdb.ping(),
      service, vault, streaming: new SecureStreamService({ service, router, vault, limits: { idleTimeoutMs: 120_000, maxDurationMs: 240_000 } }),
    }, { logger: false });
    await app.listen({ port: gwPort, host: "127.0.0.1" });
    base = `http://127.0.0.1:${gwPort}`;
  }, 240_000);

  afterAll(async () => { await app?.close(); engine?.kill(); vaultProc?.kill(); proxy?.close(); await db?.close(); });

  it("a clean prompt streams REAL model output and ends with an audited done event", async () => {
    proxy.seen.length = 0;
    const { res, frames } = await streamIt("Reply with one short sentence about the sea.");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/event-stream; charset=utf-8");
    expect(textOf(frames).length).toBeGreaterThan(0);
    const done = frames.at(-1)!;
    expect(done.event).toBe("done");
    expect(done.data.provider).toBe("ollama");
    expect(done.data.model).toBe(MODEL);                 // the REAL model that served it, not a placeholder
    expect(done.data.security.input.event_id).toBeTruthy();
    expect(done.data.security.output.event_id).not.toBe(done.data.security.input.event_id);
    // the real server was actually contacted, in streaming mode
    expect(proxy.seen).toHaveLength(1);
    expect(JSON.parse(proxy.seen[0]!).stream).toBe(true);
    const rows = (await db.query<{ n: number }>("SELECT count(*)::int AS n FROM security_events WHERE provider = 'ollama'")).rows[0]!;
    expect(rows.n).toBeGreaterThanOrEqual(2);
  }, 240_000);

  it("a reply longer than the hold-back window is served incrementally, not in one lump", async () => {
    // With a 256-character look-ahead a SHORT reply legitimately arrives as a single delta: nothing may be released until the
    // scan has covered it plus the look-ahead. Only once the reply exceeds that window can incremental delivery be observed.
    const { frames } = await streamIt("List the numbers one to forty, spelled out as words, one per line.", { max_output_tokens: 400 });
    const text = textOf(frames);
    const deltas = frames.filter((f) => f.event === "delta").length;
    if (text.length > TEST_CONFIG.stream.holdBackChars + TEST_CONFIG.stream.minSegmentChars) {
      expect(deltas).toBeGreaterThan(1);
    } else {
      expect(deltas).toBe(1);                              // correct behaviour for a reply shorter than the window
    }
    expect(frames.at(-1)!.event).toBe("done");
  }, 240_000);

  it("a SECRET in the prompt is blocked and the REAL Ollama server is never contacted", async () => {
    proxy.seen.length = 0;
    const { res, json } = await streamIt(`deploy using ${AWS} please`);
    expect(res.status).toBe(403);
    expect(json).toMatchObject({ error: "blocked", stage: "input", decision: "BLOCK" });
    expect(proxy.seen).toEqual([]);                       // ground truth: nothing reached the model server
    expect(JSON.stringify(json)).not.toContain(AWS);
  }, 240_000);

  it("PII is tokenized before the REAL server sees it, and the caller gets the real value back", async () => {
    proxy.seen.length = 0;
    const { frames } = await streamIt(`Write one short line thanking ${EMAIL}. Include [TOK_EMAIL_1] verbatim in your reply.`, { session_id: "ollama-convo" });
    expect(proxy.seen).toHaveLength(1);
    expect(proxy.seen[0]).toContain("[TOK_EMAIL_1]");
    expect(proxy.seen[0]).not.toContain(EMAIL);           // ground truth: the real bytes sent to Ollama
    expect(proxy.seen[0]).not.toContain("jane.doe");
    const done = frames.at(-1)!;
    expect(done.event).toBe("done");
    expect(done.data.security.input.decision).toBe("TOKENIZE");
    // A 0.5B model may or may not echo the token; when it does, the caller must see the real address, never the token.
    if (textOf(frames).includes("[TOK_EMAIL_1]")) throw new Error("token reached the client un-hydrated");
    expect(["applied", "degraded"]).toContain(done.data.hydration);
  }, 240_000);

  it("a secret the REAL model emits is blocked before it leaves the gateway (injected at genuine NDJSON boundaries)", async () => {
    proxy.rewrite = (line, i) => (i === 3 ? [ndjson("The key is "), ndjson(AWS), ndjson(" - use it.")] : line);
    try {
      const { frames } = await streamIt("Say a few words about the weather.");
      const raw = JSON.stringify(frames);
      expect(raw).not.toContain(AWS);
      expect(frames.at(-1)).toMatchObject({ event: "error", data: { error: "blocked", stage: "output" } });
    } finally { proxy.rewrite = null; }
  }, 240_000);

  it("a secret SPLIT across real stream chunks is still detected (this is what the look-ahead is for)", async () => {
    const half = Math.ceil(AWS.length / 2);
    proxy.rewrite = (line, i) => (i === 3 ? [ndjson(`credential: ${AWS.slice(0, half)}`), ndjson(`${AWS.slice(half)} done`)] : line);
    try {
      const { frames } = await streamIt("Say a few words about mountains.");
      const raw = JSON.stringify(frames);
      expect(raw).not.toContain(AWS);
      expect(raw).not.toContain(AWS.slice(0, half));       // not even the first half escaped
      expect(frames.at(-1)).toMatchObject({ event: "error", data: { error: "blocked", stage: "output" } });
    } finally { proxy.rewrite = null; }
  }, 240_000);

  it("PII the REAL model emits is masked by the OUTPUT policy rather than passed through", async () => {
    proxy.rewrite = (line, i) => (i === 3 ? [ndjson(`contact ${EMAIL} for more`)] : line);
    try {
      const { frames } = await streamIt("Say a few words about rivers.");
      const text = textOf(frames);
      expect(text).not.toContain(EMAIL);
      expect(frames.at(-1)!.event).toBe("done");
      expect(["MASK", "REDACT", "TOKENIZE"]).toContain(frames.at(-1)!.data.security.output.decision);
    } finally { proxy.rewrite = null; }
  }, 240_000);

  it("disconnecting mid-stream aborts the REAL upstream request and still audits what was scanned", async () => {
    const before = (await db.query<{ n: number }>("SELECT count(*)::int AS n FROM security_events WHERE direction = 'OUTPUT'")).rows[0]!.n;
    const ctl = new AbortController();
    const res = await fetch(`${base}/v1/ai/stream`, {
      method: "POST", headers: { "x-sentinel-api-key": key, "content-type": "application/json" }, signal: ctl.signal,
      body: JSON.stringify({ provider: "ollama", messages: [{ role: "user", content: "Write a long detailed essay about the history of shipping." }], max_output_tokens: 400 }),
    });
    const reader = res.body!.getReader();
    await reader.read();                                   // wait for real bytes, then hang up
    ctl.abort();
    await reader.read().catch(() => undefined);
    let after = before;
    for (let i = 0; i < 100 && after === before; i++) {
      await new Promise((r) => setTimeout(r, 100));
      after = (await db.query<{ n: number }>("SELECT count(*)::int AS n FROM security_events WHERE direction = 'OUTPUT'")).rows[0]!.n;
    }
    expect(after).toBe(before + 1);                        // the partial reply was scanned and audited exactly once
  }, 240_000);

  it("no prompt, reply or secret text is persisted anywhere in the database", async () => {
    for (const t of ["security_events", "audit_logs"]) {
      const dump = JSON.stringify((await db.query(`SELECT * FROM ${t}`)).rows);
      for (const v of [AWS, EMAIL, "jane.doe", "shipping"]) expect(dump, `${t} leaked ${v}`).not.toContain(v);
    }
  }, 60_000);
});
