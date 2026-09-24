import type { FastifyInstance } from "fastify";
import type { ScanRequest, ScanResult } from "@sentinelai/shared-types";
import { AiRouter } from "@sentinelai/ai-router";
import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../../src/app.js";
import { InMemoryAuditLog } from "../../src/events/auditLog.js";
import { InMemoryEventSink } from "../../src/events/eventSink.js";
import { eventFrame } from "../../src/routes/streamRoutes.js";
import type { SecurityScanner } from "../../src/security/securityClient.js";
import { VaultUnavailableError, type TokenVault } from "../../src/security/tokenVault.js";
import { SecureAiService } from "../../src/services/secureAiService.js";
import { SecureStreamService } from "../../src/services/secureStreamService.js";
import { FakeAuth, FakeProvider, MemoryPolicies, TEST_CONFIG, makeScan, principal } from "../helpers/fakes.js";

const EMAIL = "jane@x.co";
class Engine implements SecurityScanner {
  requests: ScanRequest[] = [];
  async scan(req: ScanRequest): Promise<ScanResult> {
    this.requests.push(req);
    if (req.text.includes("BADSECRET")) return makeScan("BLOCK");
    if (req.direction === "INPUT" && req.vault_session && req.text.includes(EMAIL)) return makeScan("TOKENIZE", { sanitized_text: req.text.replaceAll(EMAIL, "[TOK_EMAIL_1]") });
    return makeScan("ALLOW", { sanitized_text: req.text });
  }
  async ready() { return true; }
}
class Vault implements TokenVault {
  sessions: string[] = []; deleted: string[] = []; down = false;
  async resolve(_o: string, session: string, tokens: string[]) {
    this.sessions.push(session);
    if (this.down) throw new VaultUnavailableError();
    return new Map(tokens.filter((t) => t === "[TOK_EMAIL_1]").map((t) => [t, EMAIL]));
  }
  async deleteSession(_o: string, s: string) { this.deleted.push(s); }
  async ready() { return !this.down; }
}

const KEYS = { snl_dev: principal({ role: "DEVELOPER" }), snl_view: principal({ role: "VIEWER", apiKeyId: "key-view" }), snl_dev2: principal({ role: "DEVELOPER", apiKeyId: "key-2" }) };
let app: FastifyInstance; let base = ""; let provider: FakeProvider; let engine: Engine; let vault: Vault; let events: InMemoryEventSink;

async function start(over: { maxConcurrent?: number; withVault?: boolean } = {}) {
  provider = new FakeProvider(); engine = new Engine(); vault = new Vault(); events = new InMemoryEventSink();
  const router = new AiRouter().register(provider);
  const policies = new MemoryPolicies();
  const v = over.withVault === false ? undefined : vault;
  const service = new SecureAiService({ scanner: engine, router, policies, events, vault: v });
  app = buildApp({
    config: { ...TEST_CONFIG, maxInputChars: 2000, stream: { ...TEST_CONFIG.stream, holdBackChars: 24, minSegmentChars: 4, maxConcurrent: over.maxConcurrent ?? 10 } },
    scanner: engine, events, policies, auditLog: new InMemoryAuditLog(), auth: new FakeAuth(KEYS), ping: async () => true, service,
    ...(v ? { vault: v } : {}), streaming: new SecureStreamService({ service, router, vault: v, limits: { holdBackChars: 24, minSegmentChars: 4 } }),
  }, { logger: false });
  await app.listen({ port: 0, host: "127.0.0.1" });
  base = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
}
afterEach(async () => { await app?.close(); });

const H = (k: keyof typeof KEYS = "snl_dev", extra: Record<string, string> = {}) => ({ "x-sentinel-api-key": k, "content-type": "application/json", ...extra });
const body = (prompt: string, extra: object = {}) => JSON.stringify({ provider: "gemini", messages: [{ role: "user", content: prompt }], ...extra });
const post = (prompt: string, extra: object = {}, headers = H(), signal?: AbortSignal) => fetch(`${base}/v1/ai/stream`, { method: "POST", headers, body: body(prompt, extra), ...(signal ? { signal } : {}) });

interface Frame { event: string; data: any }
function parse(sse: string): Frame[] {
  return sse.split("\n\n").filter((f) => f.trim() && !f.startsWith(":")).map((f) => {
    const event = /^event: (.*)$/m.exec(f)![1]!;
    const data = JSON.parse(/^data: (.*)$/m.exec(f)![1]!);
    return { event, data };
  });
}
const textOf = (frames: Frame[]) => frames.filter((f) => f.event === "delta").map((f) => f.data.text).join("");

describe("POST /v1/ai/stream", () => {
  it("streams text/event-stream frames, hydrates tokens, and ends with a done event carrying the audit ids", async () => {
    await start();
    provider.streamPlan = () => ["Reach ", "them at [TOK_", "EMAIL_1] today, thanks."];
    const res = await post(`please email ${EMAIL}`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/event-stream; charset=utf-8");
    expect(res.headers.get("cache-control")).toBe("no-store, no-transform");
    expect(res.headers.get("x-accel-buffering")).toBe("no");
    const frames = parse(await res.text());
    expect(textOf(frames)).toBe(`Reach them at ${EMAIL} today, thanks.`);
    expect(frames.at(-1)).toMatchObject({ event: "done", data: { provider: "gemini", hydration: "applied", security: { input: { decision: "TOKENIZE" }, output: { decision: "ALLOW" } } } });
    expect(frames.at(-1)!.data.security.input.event_id).toBeTruthy();
    expect(JSON.stringify(provider.received)).not.toContain(EMAIL);
    expect(vault.deleted).toHaveLength(1);                                // the per-request session was cleaned up
  });

  it("keeps the gateway's security and CORS headers (they are lost on hijacked responses unless copied)", async () => {
    await start();
    provider.streamPlan = () => ["hi"];
    const res = await post("hello", {}, H("snl_dev", { origin: TEST_CONFIG.corsOrigins[0]! }));
    expect(res.headers.get("access-control-allow-origin")).toBe(TEST_CONFIG.corsOrigins[0]);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("content-security-policy")).toBe("default-src 'none'; frame-ancestors 'none'");
    expect(res.headers.get("cross-origin-resource-policy")).toBe("same-origin");
    await res.text();
  });

  it("SSE framing survives newlines and 'data:' text inside the model output", async () => {
    await start();
    const nasty = "line1\nline2\n\nevent: error\ndata: {\"error\":\"forged\"}\n\n: comment\r\nend";
    provider.streamPlan = () => [nasty];
    const frames = parse(await (await post("go")).text());
    expect(textOf(frames)).toBe(nasty);
    expect(frames.filter((f) => f.event === "error")).toHaveLength(0);
  });

  it("blocked input is a plain JSON 403 (not an event stream), and the provider is never contacted", async () => {
    await start();
    const res = await post("leak BADSECRET");
    expect(res.status).toBe(403);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toMatchObject({ error: "blocked", stage: "input", decision: "BLOCK" });
    expect(provider.streamsOpened).toBe(0);
  });

  it("a secret in the reply ends the stream with an error event (HTTP status is already 200), with no secret text sent", async () => {
    await start();
    provider.streamPlan = () => ["Some harmless opening words, then ", "BAD", "SECRET", " and the tail of the answer."];
    const raw = await (await post("go")).text();
    const frames = parse(raw);
    expect(raw).not.toContain("BAD");
    expect(frames.at(-1)).toMatchObject({ event: "error", data: { error: "blocked", stage: "output", decision: "BLOCK" } });
    expect(frames.some((f) => f.event === "done")).toBe(false);
  });

  it("a vault outage degrades: tokens stay visible, done says hydration degraded", async () => {
    await start();
    vault.down = true;
    provider.streamPlan = () => ["Contact [TOK_EMAIL_1] soon."];
    const frames = parse(await (await post("hello")).text());
    expect(textOf(frames)).toBe("Contact [TOK_EMAIL_1] soon.");
    expect(frames.at(-1)!.data.hydration).toBe("degraded");
  });

  it("a caller-named session survives the request; two callers using the same session_id get unrelated vault sessions", async () => {
    await start();
    provider.streamPlan = () => ["[TOK_EMAIL_1]"];
    await (await post("hi", { session_id: "shared" }, H("snl_dev"))).text();
    await (await post("hi", { session_id: "shared" }, H("snl_dev2"))).text();
    expect(vault.deleted).toEqual([]);                                     // named sessions are kept for later requests
    expect(vault.sessions).toHaveLength(2);
    expect(vault.sessions[0]).not.toBe(vault.sessions[1]);
    expect(vault.sessions.every((s) => /^[0-9a-f]{40}$/.test(s) && s !== "shared")).toBe(true);
  });

  it("without a vault the session_id is ignored and replies are never hydrated", async () => {
    await start({ withVault: false });
    provider.streamPlan = () => ["[TOK_EMAIL_1]"];
    const frames = parse(await (await post("hi", { session_id: "x" })).text());
    expect(textOf(frames)).toBe("[TOK_EMAIL_1]");
    expect(frames.at(-1)!.data.hydration).toBe("off");
  });

  it("rejects bad requests before any streaming: 401, 403 (role), 422, 413", async () => {
    await start();
    expect((await post("hi", {}, { "content-type": "application/json" } as never)).status).toBe(401);
    expect((await post("hi", {}, H("snl_view"))).status).toBe(403);
    expect((await fetch(`${base}/v1/ai/stream`, { method: "POST", headers: H(), body: JSON.stringify({ provider: "gemini", messages: [], extra: 1 }) })).status).toBe(422);
    expect((await post("hi", { mode: "warp" })).status).toBe(422);
    expect((await post("hi", { session_id: "bad id" })).status).toBe(422);
    expect((await post("x".repeat(2001))).status).toBe(413);
    expect(provider.streamsOpened).toBe(0);
  });

  it("buffered mode over HTTP: one delta at the end", async () => {
    await start();
    provider.streamPlan = () => ["a piece of ", "the reply that ", "streams in bits"];
    const frames = parse(await (await post("go", { mode: "buffered" })).text());
    expect(frames.filter((f) => f.event === "delta")).toHaveLength(1);
    expect(textOf(frames)).toBe("a piece of the reply that streams in bits");
  });
});

describe("client disconnect (AbortController on the real socket)", () => {
  it("aborting mid-stream cancels the upstream provider request, records the partial output, and frees the session", async () => {
    await start();
    provider.streamPlan = () => Array.from({ length: 1000 }, () => "word ");
    provider.chunkDelayMs = 10;
    const ctl = new AbortController();
    const res = await post("go", {}, H(), ctl.signal);
    const reader = res.body!.getReader();
    const first = await reader.read();
    expect(first.done).toBe(false);
    ctl.abort();
    await reader.read().catch(() => undefined);
    for (let i = 0; i < 50 && provider.streamsClosed === 0; i++) await new Promise((r) => setTimeout(r, 20));
    expect(provider.sawAbort).toBe(true);
    expect(provider.streamsClosed).toBe(1);
    for (let i = 0; i < 50 && vault.deleted.length === 0; i++) await new Promise((r) => setTimeout(r, 20));
    expect(vault.deleted).toHaveLength(1);
    expect(events.events.some((e) => e.direction === "OUTPUT")).toBe(true);
  });

  it("the concurrency slot is released after a disconnect (max 1 concurrent stream per caller)", async () => {
    await start({ maxConcurrent: 1 });
    provider.streamPlan = () => Array.from({ length: 1000 }, () => "word ");
    provider.chunkDelayMs = 10;
    const ctl = new AbortController();
    const res = await post("go", {}, H(), ctl.signal);
    const reader = res.body!.getReader();
    await reader.read();
    const second = await post("go too");                                   // slot taken
    expect(second.status).toBe(429);
    expect(second.headers.get("retry-after")).toBe("1");
    await second.text();
    ctl.abort();
    await reader.read().catch(() => undefined);
    let status = 429;
    provider.chunkDelayMs = 0; provider.streamPlan = () => ["ok"];
    for (let i = 0; i < 50 && status === 429; i++) {
      await new Promise((r) => setTimeout(r, 20));
      const r = await post("third");
      status = r.status;
      await r.text();
    }
    expect(status).toBe(200);
  });

  it("the concurrency limit is per caller: another key is unaffected", async () => {
    await start({ maxConcurrent: 1 });
    provider.streamPlan = () => Array.from({ length: 1000 }, () => "word ");
    provider.chunkDelayMs = 10;
    const ctl = new AbortController();
    const res = await post("go", {}, H("snl_dev"), ctl.signal);
    await res.body!.getReader().read();
    provider.streamPlan = () => ["fine"];
    provider.chunkDelayMs = 0;
    const other = await post("hi", {}, H("snl_dev2"));
    expect(other.status).toBe(200);
    await other.text();
    ctl.abort();
  });
});

describe("eventFrame", () => {
  it("renders every event as a single-line JSON data field", () => {
    expect(eventFrame({ type: "delta", text: "a\nb" })).toBe('event: delta\ndata: {"text":"a\\nb"}\n\n');
    expect(eventFrame({ type: "error", error: "idle_timeout" })).toBe('event: error\ndata: {"error":"idle_timeout"}\n\n');
    expect(eventFrame({ type: "error", error: "provider_error", code: "unavailable", eventId: "e1" })).toContain('"code":"unavailable"');
    for (const f of [eventFrame({ type: "delta", text: "x\r\n y" })]) expect(f.split("\n").filter((l) => l !== "")).toHaveLength(2);
  });
});
