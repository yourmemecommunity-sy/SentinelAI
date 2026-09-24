import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  SentinelAI, SentinelAuthenticationError, SentinelBlockedError, SentinelError, SentinelProviderError, SentinelRateLimitError,
  SentinelUnavailableError,
} from "../src/index.js";

const KEY = "snl_" + "abcd1234" + "_" + "A".repeat(43);             // shaped like a key, not a real credential
const DONE = { provider: "gemini", model: "m1", hydration: "applied", security: {
  input: { decision: "TOKENIZE", risk_level: "LOW", event_id: "e-in" }, output: { decision: "ALLOW", risk_level: "LOW", event_id: "e-out" } } };
const ev = (event: string, data: unknown) => `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;

interface Seen { method: string | undefined; url: string | undefined; headers: IncomingMessage["headers"]; body: string; closed: boolean }
const servers: Server[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => { s.closeAllConnections(); s.close(() => r()); }))); });

async function serve(handler: (res: ServerResponse, seen: Seen) => void | Promise<void>) {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const s: Seen = { method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString(), closed: false };
      res.on("close", () => { s.closed = true; });
      seen.push(s);
      void handler(res, s);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  servers.push(server);
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen };
}
const sse = (res: ServerResponse) => res.writeHead(200, { "content-type": "text/event-stream; charset=utf-8" });
const client = (baseUrl: string, extra: object = {}) => new SentinelAI({ apiKey: KEY, baseUrl, ...extra });
const messages = [{ role: "user" as const, content: "hi" }];

describe("stream(): happy path", () => {
  it("yields deltas in order, resolves the summary, and sends the right request", async () => {
    const gw = await serve((res) => { sse(res); res.write(ev("delta", { text: "Hello " })); res.write(ev("delta", { text: "world" })); res.end(ev("done", DONE)); });
    const s = client(gw.url).stream({ provider: "gemini", messages, sessionId: "conv-1", hydrate: true, mode: "buffered", model: "m1" });
    const parts: string[] = [];
    for await (const t of s) parts.push(t);
    expect(parts).toEqual(["Hello ", "world"]);
    expect(await s.summary).toEqual({ provider: "gemini", model: "m1", hydration: "applied",
      security: { input: { decision: "TOKENIZE", riskLevel: "LOW", eventId: "e-in" }, output: { decision: "ALLOW", riskLevel: "LOW", eventId: "e-out" } } });
    const r = gw.seen[0]!;
    expect(r.url).toBe("/v1/ai/stream");
    expect(r.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(r.headers.accept).toBe("text/event-stream");
    expect(JSON.parse(r.body)).toMatchObject({ provider: "gemini", model: "m1", session_id: "conv-1", hydrate: true, mode: "buffered", messages });
  });

  it("reassembles events split across arbitrary network chunks, and ignores heartbeats", async () => {
    const payload = ": ping\n\n" + ev("delta", { text: "a\nb" }) + ": ping\n\n" + ev("delta", { text: "ç🙂" }) + ev("done", DONE);
    const gw = await serve(async (res) => {
      sse(res);
      for (const ch of Buffer.from(payload)) { res.write(Buffer.from([ch])); await new Promise((r) => setImmediate(r)); }
      res.end();
    });
    expect(await client(gw.url).stream({ provider: "gemini", messages }).text()).toBe("a\nbç🙂");
  });

  it("accepts CRLF-framed events", async () => {
    const gw = await serve((res) => { sse(res); res.end("event: delta\r\ndata: {\"text\":\"x\"}\r\n\r\nevent: done\r\ndata: " + JSON.stringify(DONE) + "\r\n\r\n"); });
    expect(await client(gw.url).stream({ provider: "gemini", messages }).text()).toBe("x");
  });
});

describe("stream(): fail-closed", () => {
  it("a blocked OUTPUT ends the stream with SentinelBlockedError; text already released was delivered first", async () => {
    const gw = await serve((res) => { sse(res); res.write(ev("delta", { text: "safe start " })); res.end(ev("error", { error: "blocked", stage: "output", decision: "BLOCK", failed_closed: false, reason: null, event_id: "e9" })); });
    const s = client(gw.url).stream({ provider: "gemini", messages });
    const got: string[] = [];
    const err = await (async () => { try { for await (const t of s) got.push(t); } catch (e) { return e; } return null; })();
    expect(got).toEqual(["safe start "]);
    expect(err).toBeInstanceOf(SentinelBlockedError);
    expect(err).toMatchObject({ stage: "output", decision: "BLOCK", eventId: "e9" });
    await expect(s.summary).rejects.toBe(err);
  });

  it("a connection that drops before `done` is NOT a complete reply", async () => {
    const gw = await serve((res) => { sse(res); res.write(ev("delta", { text: "partial" })); res.socket?.destroy(); });
    const s = client(gw.url).stream({ provider: "gemini", messages });
    await expect(s.text()).rejects.toBeInstanceOf(SentinelUnavailableError);
    await expect(s.summary).rejects.toBeInstanceOf(SentinelUnavailableError);
  });

  it("a clean end-of-body without `done` is also incomplete", async () => {
    const gw = await serve((res) => { sse(res); res.end(ev("delta", { text: "partial" })); });
    await expect(client(gw.url).stream({ provider: "gemini", messages }).text()).rejects.toThrow(/before the gateway completed/);
  });

  it.each([
    [{ error: "provider_error", code: "rate_limit", event_id: "e1" }, SentinelProviderError],
    [{ error: "idle_timeout" }, SentinelUnavailableError],
    [{ error: "max_duration" }, SentinelUnavailableError],
    [{ error: "audit_unavailable" }, SentinelUnavailableError],
  ])("gateway error event %o -> typed error", async (data, cls) => {
    const gw = await serve((res) => { sse(res); res.end(ev("error", data)); });
    await expect(client(gw.url).stream({ provider: "gemini", messages }).text()).rejects.toBeInstanceOf(cls);
  });

  it("errors before the stream starts map exactly like chat()", async () => {
    const cases: [number, object, unknown][] = [
      [403, { error: "blocked", stage: "input", decision: "BLOCK", failed_closed: true, reason: "unknown_provider", event_id: "x" }, SentinelBlockedError],
      [401, { error: "unauthorized" }, SentinelAuthenticationError],
      [429, { error: "too_many_streams" }, SentinelRateLimitError],
      [503, { error: "audit_unavailable" }, SentinelUnavailableError],
    ];
    for (const [status, body, cls] of cases) {
      const gw = await serve((res) => { res.writeHead(status, { "content-type": "application/json", "retry-after": "1" }); res.end(JSON.stringify(body)); });
      await expect(client(gw.url).stream({ provider: "gemini", messages }).text(), String(status)).rejects.toBeInstanceOf(cls as typeof SentinelError);
    }
  });

  it("a 200 that is not an event stream is refused", async () => {
    const gw = await serve((res) => { res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); });
    await expect(client(gw.url).stream({ provider: "gemini", messages }).text()).rejects.toBeInstanceOf(SentinelUnavailableError);
  });

  it.each([
    ["non-JSON data", "event: delta\ndata: not json\n\n"],
    ["delta without text", ev("delta", { nope: 1 })],
    ["done without security", ev("done", { provider: "g", model: "m" })],
  ])("malformed stream (%s) is refused", async (_n, body) => {
    const gw = await serve((res) => { sse(res); res.end(body); });
    await expect(client(gw.url).stream({ provider: "gemini", messages }).text()).rejects.toBeInstanceOf(SentinelError);
  });

  it("a stalled gateway trips the idle timeout", async () => {
    const gw = await serve((res) => { sse(res); res.write(ev("delta", { text: "x" })); /* then silence */ });
    const t0 = Date.now();
    await expect(client(gw.url, { timeoutMs: 300 }).stream({ provider: "gemini", messages }).text()).rejects.toThrow(/stalled/);
    expect(Date.now() - t0).toBeLessThan(3000);
  });

  it("never follows a redirect (the key is not forwarded)", async () => {
    const target = await serve((res) => { sse(res); res.end(ev("done", DONE)); });
    const gw = await serve((res) => { res.writeHead(307, { location: `${target.url}/v1/ai/stream` }); res.end(); });
    await expect(client(gw.url).stream({ provider: "gemini", messages }).text()).rejects.toBeInstanceOf(SentinelUnavailableError);
    expect(target.seen).toHaveLength(0);
  });
});

describe("stream(): cancellation", () => {
  const endless = () => serve(async (res) => {
    sse(res);
    for (let i = 0; i < 2000 && !res.destroyed; i++) { res.write(ev("delta", { text: `${i} ` })); await new Promise((r) => setTimeout(r, 5)); }
  });

  it("breaking out of the loop aborts the upstream request", async () => {
    const gw = await endless();
    const s = client(gw.url).stream({ provider: "gemini", messages });
    let n = 0;
    for await (const _t of s) { if (++n === 3) break; }
    await expect(s.summary).rejects.toBeInstanceOf(SentinelUnavailableError);
    for (let i = 0; i < 50 && !gw.seen[0]!.closed; i++) await new Promise((r) => setTimeout(r, 20));
    expect(gw.seen[0]!.closed).toBe(true);
  });

  it("the caller's AbortSignal stops the stream with SentinelUnavailableError", async () => {
    const gw = await endless();
    const ctl = new AbortController();
    const s = client(gw.url).stream({ provider: "gemini", messages, signal: ctl.signal });
    const err = await (async () => { try { let n = 0; for await (const _t of s) { if (++n === 2) ctl.abort(); } } catch (e) { return e; } return null; })();
    expect(err).toBeInstanceOf(SentinelUnavailableError);
    expect((err as Error).message).toMatch(/aborted/);
  });

  it("a stream can only be consumed once", async () => {
    const gw = await serve((res) => { sse(res); res.end(ev("done", DONE)); });
    const s = client(gw.url).stream({ provider: "gemini", messages });
    await s.text();
    await expect(s.text()).rejects.toThrow(/only be iterated once/);
  });
});

describe("chat(): session options", () => {
  it("sends session_id/hydrate and surfaces hydration", async () => {
    const gw = await serve((res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ provider: "gemini", model: "m1", content: "hi jane@x.co", hydration: "applied", security: DONE.security }));
    });
    const r = await client(gw.url).chat({ provider: "gemini", messages, sessionId: "s1", hydrate: true });
    expect(r.hydration).toBe("applied");
    expect(JSON.parse(gw.seen[0]!.body)).toMatchObject({ session_id: "s1", hydrate: true });
  });
});
