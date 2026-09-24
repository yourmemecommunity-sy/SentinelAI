import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  SentinelAI, SentinelAuthenticationError, SentinelBlockedError, SentinelConfigError, SentinelError, SentinelPermissionError,
  SentinelProviderError, SentinelRateLimitError, SentinelUnavailableError, SentinelValidationError,
} from "../src/index.js";

// Assembled at runtime: a correctly *shaped* key, not a real credential.
const KEY = "snl_" + "abcd1234" + "_" + "A".repeat(43);
interface Seen { method: string | undefined; url: string | undefined; headers: IncomingMessage["headers"]; body: string }

const servers: Server[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => { s.closeAllConnections(); s.close(() => r()); }))); });

/** A real HTTP server standing in for the gateway. */
async function serve(handler: (req: Seen, res: ServerResponse) => void | Promise<void>): Promise<{ url: string; seen: Seen[] }> {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => { const s = { method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() }; seen.push(s); void handler(s, res); });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  servers.push(server);
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen };
}
const json = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => { res.writeHead(status, { "content-type": "application/json", ...headers }); res.end(JSON.stringify(body)); };
const client = (baseUrl: string, extra: object = {}) => new SentinelAI({ apiKey: KEY, baseUrl, ...extra });

const CHAT_OK = { provider: "gemini", model: "m1", content: "hello back", security: { input: { decision: "MASK", risk_level: "LOW", event_id: "e1" }, output: { decision: "ALLOW", risk_level: "LOW", event_id: "e2" } } };
const SCAN_OK = { request_id: "r1", event_id: "e1", decision: "MASK", failed_closed: false, fail_closed_reason: null, sanitized_text: "mail j***@x.co",
  risk: { risk_score: 20, risk_level: "LOW", decision: "MASK", factors: [{ name: "data_sensitivity", contribution: 15, detail: "EMAIL" }] },
  detections: [{ entity: "EMAIL", confidence: 0.95, severity: "MEDIUM", location: { start: 5, end: 12 }, detector: "pii" }], entity_actions: [], policy_id: "p" };

describe("secure() / chat()", () => {
  it("sends bearer auth + JSON to /v1/ai/chat and maps the response to camelCase", async () => {
    const gw = await serve((_r, res) => json(res, 200, CHAT_OK));
    const r = await client(gw.url).secure({ provider: "gemini", prompt: "hi", system: "be brief", model: "m1", application: "app", environment: "prod", maxOutputTokens: 50, temperature: 0.2 });
    expect(r).toEqual({ content: "hello back", provider: "gemini", model: "m1",
      security: { input: { decision: "MASK", riskLevel: "LOW", eventId: "e1" }, output: { decision: "ALLOW", riskLevel: "LOW", eventId: "e2" } } });
    const s = gw.seen[0]!;
    expect(s.method).toBe("POST"); expect(s.url).toBe("/v1/ai/chat");
    expect(s.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(s.headers["user-agent"]).toMatch(/^sentinelai-js\//);
    expect(JSON.parse(s.body)).toEqual({ provider: "gemini", model: "m1", max_output_tokens: 50, temperature: 0.2, application: "app", environment: "prod",
      messages: [{ role: "system", content: "be brief" }, { role: "user", content: "hi" }] });
  });

  it("throws SentinelBlockedError (with stage/decision/eventId and NO content) when the gateway blocks", async () => {
    const gw = await serve((_r, res) => json(res, 403, { error: "blocked", stage: "output", decision: "BLOCK", failed_closed: true, reason: "engine_timeout", event_id: "ev9" }));
    const err = await client(gw.url).secure({ provider: "openai", prompt: "SECRET-PROMPT-TEXT" }).catch((e) => e);
    expect(err).toBeInstanceOf(SentinelBlockedError);
    expect(err).toMatchObject({ stage: "output", decision: "BLOCK", failedClosed: true, reason: "engine_timeout", eventId: "ev9", status: 403 });
    expect(JSON.stringify({ m: err.message, ...err })).not.toContain("SECRET-PROMPT-TEXT");
  });

  it("never returns content from a malformed 200: missing fields and wrong types throw", async () => {
    for (const bad of [{}, { content: 5 }, { ...CHAT_OK, security: undefined }, { ...CHAT_OK, content: undefined }, { ...CHAT_OK, security: { input: {}, output: {} } }, "not-an-object", [1]]) {
      const gw = await serve((_r, res) => json(res, 200, bad));
      await expect(client(gw.url).secure({ provider: "gemini", prompt: "x" }), JSON.stringify(bad)).rejects.toBeInstanceOf(SentinelError);
    }
  });

  it("chat() forwards a full conversation", async () => {
    const gw = await serve((_r, res) => json(res, 200, CHAT_OK));
    await client(gw.url).chat({ provider: "gemini", messages: [{ role: "user", content: "a" }, { role: "assistant", content: "b" }, { role: "user", content: "c" }] });
    expect(JSON.parse(gw.seen[0]!.body).messages).toHaveLength(3);
  });
});

describe("scan() / check()", () => {
  it("scan returns evidence and sanitized text", async () => {
    const gw = await serve((_r, res) => json(res, 200, SCAN_OK));
    const r = await client(gw.url).scan({ text: "mail a@b.co", team: "eng" });
    expect(r).toMatchObject({ decision: "MASK", blocked: false, sanitizedText: "mail j***@x.co", riskLevel: "LOW", riskScore: 20, policyId: "p", eventId: "e1" });
    expect(r.detections[0]).toMatchObject({ entity: "EMAIL", location: { start: 5, end: 12 } });
    expect(JSON.parse(gw.seen[0]!.body)).toEqual({ text: "mail a@b.co", direction: "INPUT", context: { team: "eng" } });
  });

  it("a blocked scan is RETURNED (not thrown) with blocked=true and no text", async () => {
    const gw = await serve((_r, res) => json(res, 200, { ...SCAN_OK, decision: "BLOCK", sanitized_text: null }));
    const r = await client(gw.url).scan({ text: "x" });
    expect(r).toMatchObject({ blocked: true, sanitizedText: null, decision: "BLOCK" });
  });

  it("rejects inconsistent scan results (blocked with text / allowed without text) as untrustworthy", async () => {
    for (const bad of [{ ...SCAN_OK, decision: "BLOCK", sanitized_text: "leak" }, { ...SCAN_OK, decision: "ALLOW", sanitized_text: null }]) {
      const gw = await serve((_r, res) => json(res, 200, bad));
      await expect(client(gw.url).scan({ text: "x" })).rejects.toThrow(/inconsistent decision/);
    }
  });

  it("check: allowed only for an unmodified ALLOW", async () => {
    const mk = async (body: object) => client((await serve((_r, res) => json(res, 200, body))).url).check({ text: "x" });
    expect((await mk({ allowed: true, decision: "ALLOW", risk_level: "LOW", failed_closed: false, event_id: "e" })).allowed).toBe(true);
    expect((await mk({ allowed: true, decision: "MASK", risk_level: "LOW", failed_closed: false, event_id: "e" })).allowed).toBe(false);   // contradictory server data -> not allowed
    expect((await mk({ allowed: false, decision: "BLOCK", risk_level: "CRITICAL", failed_closed: true, event_id: null })).allowed).toBe(false);
  });
});

const FILE_OK = { event_id: "f1", decision: "REDACT", failed_closed: false, reason: null, sanitized_text: "name: [REDACTED]",
  file: { sha256: "a".repeat(64), size: 12, detected_type: "txt", mime: "text/plain", pages: null, ocr_used: false },
  findings: [{ type: "hidden_text", severity: "MEDIUM", detail: "vanish run" }],
  risk: { risk_score: 45, risk_level: "MEDIUM" }, detections: [{ entity: "EMAIL", confidence: 0.9, severity: "MEDIUM", location: { start: 6, end: 9 }, detector: "pii" }], policy_id: "p" };
const FILE_BLOCKED = { ...FILE_OK, decision: "BLOCK", reason: "macros_present", sanitized_text: null, detections: [], findings: [{ type: "macros", severity: "CRITICAL", detail: "vbaProject.bin" }] };

/** Raw-byte capture (the shared helper decodes as UTF-8, which would corrupt binary payloads). */
async function serveRaw(reply: unknown): Promise<{ url: string; got: { headers: IncomingMessage["headers"]; bytes: Buffer }[] }> {
  const got: { headers: IncomingMessage["headers"]; bytes: Buffer }[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => { got.push({ headers: req.headers, bytes: Buffer.concat(chunks) }); json(res, 200, reply); });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  servers.push(server);
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, got };
}

describe("scanFile()", () => {
  it("sends the exact bytes as octet-stream with only a synthetic extension-only filename", async () => {
    const gw = await serveRaw(FILE_OK);
    const data = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x00, 0xff, 0xfe, 0x80]);
    const r = await client(gw.url).scanFile({ data, filename: "Q3 board minutes - CONFIDENTIAL.PDF", application: "app", team: "t", environment: "prod" });
    const g = gw.got[0]!;
    expect(Buffer.compare(g.bytes, Buffer.from(data))).toBe(0);
    expect(g.headers["content-type"]).toBe("application/octet-stream");
    expect(g.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(decodeURIComponent(String(g.headers["x-filename"]))).toBe("upload.PDF");
    expect(String(g.headers["x-filename"])).not.toContain("CONFIDENTIAL");
    expect(g.headers["x-application"]).toBe("app"); expect(g.headers["x-team"]).toBe("t"); expect(g.headers["x-environment"]).toBe("prod");
    expect(r).toMatchObject({ decision: "REDACT", blocked: false, failedClosed: false, reason: null, sanitizedText: "name: [REDACTED]", riskScore: 45, riskLevel: "MEDIUM", policyId: "p", eventId: "f1" });
    expect(r.file).toEqual({ sha256: "a".repeat(64), size: 12, detectedType: "txt", mime: "text/plain", pages: null, ocrUsed: false });
    expect(r.findings).toEqual([{ type: "hidden_text", severity: "MEDIUM", detail: "vanish run" }]);
    expect(r.detections[0]).toMatchObject({ entity: "EMAIL", location: { start: 6, end: 9 } });
  });

  it("accepts an ArrayBuffer and omits x-filename when there is no usable extension", async () => {
    const gw = await serveRaw(FILE_OK);
    await client(gw.url).scanFile({ data: new TextEncoder().encode("hello").buffer as ArrayBuffer, filename: "no-extension" });
    expect(gw.got[0]!.bytes.toString()).toBe("hello");
    expect(gw.got[0]!.headers["x-filename"]).toBeUndefined();
  });

  it("a blocked file is RETURNED (not thrown) with blocked=true, a reason, and no text", async () => {
    const gw = await serveRaw(FILE_BLOCKED);
    const r = await client(gw.url).scanFile({ data: new Uint8Array([1, 2, 3]), filename: "a.docx" });
    expect(r).toMatchObject({ decision: "BLOCK", blocked: true, reason: "macros_present", sanitizedText: null });
  });

  it("rejects inconsistent results (blocked with text / allowed without text) and missing evidence as untrustworthy", async () => {
    for (const bad of [{ ...FILE_BLOCKED, sanitized_text: "leak" }, { ...FILE_OK, sanitized_text: null }, { ...FILE_OK, file: undefined }, { ...FILE_OK, findings: undefined }, { ...FILE_OK, risk: undefined }, { ...FILE_OK, decision: 5 }]) {
      const gw = await serveRaw(bad);
      await expect(client(gw.url).scanFile({ data: new Uint8Array([1]) })).rejects.toBeInstanceOf(SentinelError);
    }
  });

  it("fails closed on gateway errors: 413, 429, 503 and unreachable all throw", async () => {
    const codes: [number, unknown][] = [[413, SentinelValidationError], [429, SentinelRateLimitError], [503, SentinelUnavailableError]];
    for (const [status, cls] of codes) {
      const gw = await serve((_r, res) => json(res, status, { error: "x" }));
      await expect(client(gw.url).scanFile({ data: new Uint8Array([1]) })).rejects.toBeInstanceOf(cls as typeof SentinelError);
    }
    await expect(client("http://127.0.0.1:1").scanFile({ data: new Uint8Array([1]) })).rejects.toBeInstanceOf(SentinelUnavailableError);
  });

  it("never follows redirects: the file and the key are not forwarded", async () => {
    const target = await serveRaw(FILE_OK);
    const gw = await serve((_r, res) => { res.writeHead(307, { location: `${target.url}/steal` }); res.end(); });
    await expect(client(gw.url).scanFile({ data: new Uint8Array([1]) })).rejects.toBeInstanceOf(SentinelUnavailableError);
    expect(target.got).toHaveLength(0);
  });
});

describe("error mapping (all fail closed, none leak)", () => {
  const cases: [number, object, new (...a: never[]) => Error][] = [
    [401, { error: "unauthorized" }, SentinelAuthenticationError],
    [403, { error: "forbidden" }, SentinelPermissionError],
    [413, { error: "payload_too_large" }, SentinelValidationError],
    [422, { error: "invalid_request", issues: [{ path: "rules.0", message: "bad" }] }, SentinelValidationError],
    [502, { error: "provider_error", code: "rate_limit", event_id: "e" }, SentinelProviderError],
    [503, { error: "audit_unavailable" }, SentinelUnavailableError],
    [500, { error: "internal_error" }, SentinelUnavailableError],
    [418, {}, SentinelError],
  ];
  it.each(cases)("HTTP %i -> typed error", async (status, body, Cls) => {
    const gw = await serve((_r, res) => json(res, status, body));
    const err = await client(gw.url).secure({ provider: "gemini", prompt: "x" }).catch((e) => e);
    expect(err).toBeInstanceOf(Cls);
    expect(err.status).toBe(status);
    expect(err.message).not.toContain(KEY);
  });

  it("429 carries Retry-After; 422 carries issue paths", async () => {
    const gw = await serve((_r, res) => json(res, 429, { error: "rate_limited" }, { "retry-after": "7" }));
    expect(await client(gw.url).scan({ text: "x" }).catch((e) => e)).toMatchObject({ retryAfterSeconds: 7 });
    const gw2 = await serve((_r, res) => json(res, 422, { issues: [{ path: "provider", message: "bad" }] }));
    expect((await client(gw2.url).scan({ text: "x" }).catch((e) => e)).issues).toEqual([{ path: "provider", message: "bad" }]);
    expect(SentinelRateLimitError).toBeDefined();
  });

  it("network failure, timeout and non-JSON responses throw SentinelUnavailableError", async () => {
    const dead = await serve((_r, res) => { res.end(); }); servers.pop()!.close();
    expect(await client(dead.url).scan({ text: "x" }).catch((e) => e)).toBeInstanceOf(SentinelUnavailableError);
    const slow = await serve(() => { /* never answers */ });
    expect((await client(slow.url, { timeoutMs: 150 }).scan({ text: "x" }).catch((e) => e)).message).toBe("request timed out");
    const html = await serve((_r, res) => { res.writeHead(200); res.end("<html>oops</html>"); });
    expect(await client(html.url).scan({ text: "x" }).catch((e) => e)).toBeInstanceOf(SentinelUnavailableError);
  });

  it("the caller can abort a request", async () => {
    const slow = await serve(() => { /* never answers */ });
    const ac = new AbortController();
    const p = client(slow.url).scan({ text: "x", signal: ac.signal }).catch((e) => e);
    setTimeout(() => ac.abort(), 50);
    expect((await p).message).toBe("request aborted by caller");
  });
});

describe("credential safety", () => {
  it("never follows redirects: the key is not forwarded to the redirect target", async () => {
    const target = await serve((_r, res) => json(res, 200, CHAT_OK));
    const evil = await serve((_r, res) => { res.writeHead(307, { location: `${target.url}/steal` }); res.end(); });
    const err = await client(evil.url).secure({ provider: "gemini", prompt: "x" }).catch((e) => e);
    expect(err).toBeInstanceOf(SentinelUnavailableError);
    expect(target.seen).toHaveLength(0);
  });

  it("requires a well-formed key and never echoes it in configuration errors", () => {
    for (const bad of ["", "snl_short", "sk-1234", KEY + "x", KEY.replace("snl_", "xxx_")]) {
      try { new SentinelAI({ apiKey: bad, baseUrl: "https://gw.example.test" }); throw new Error("should have thrown"); }
      catch (e) { expect(e).toBeInstanceOf(SentinelConfigError); if (bad) expect((e as Error).message).not.toContain(bad); }
    }
  });

  it("requires https except for localhost, and refuses credentials in the URL", () => {
    expect(() => new SentinelAI({ apiKey: KEY, baseUrl: "http://gw.example.test" })).toThrow(/https/);
    expect(() => new SentinelAI({ apiKey: KEY, baseUrl: "ftp://gw.example.test" })).toThrow(SentinelConfigError);
    expect(() => new SentinelAI({ apiKey: KEY, baseUrl: "https://user:pw@gw.example.test" })).toThrow(/credentials/);
    expect(() => new SentinelAI({ apiKey: KEY, baseUrl: "not a url" })).toThrow(SentinelConfigError);
    expect(() => new SentinelAI({ apiKey: KEY, baseUrl: "https://gw.example.test" })).not.toThrow();
    expect(() => new SentinelAI({ apiKey: KEY, baseUrl: "http://localhost:4000" })).not.toThrow();
    expect(() => new SentinelAI({ apiKey: KEY, baseUrl: "http://127.0.0.1:4000" })).not.toThrow();
    expect(() => new SentinelAI({ apiKey: KEY, baseUrl: "http://10.0.0.5", allowInsecureHttp: true })).not.toThrow();
    expect(() => new SentinelAI({ apiKey: KEY, baseUrl: "https://gw.example.test", timeoutMs: 0 })).toThrow(SentinelConfigError);
  });

  it("reads SENTINEL_API_KEY / SENTINEL_BASE_URL from the environment", async () => {
    const gw = await serve((_r, res) => json(res, 200, CHAT_OK));
    process.env.SENTINEL_API_KEY = KEY; process.env.SENTINEL_BASE_URL = gw.url;
    try { await new SentinelAI().secure({ provider: "gemini", prompt: "x" }); } finally { delete process.env.SENTINEL_API_KEY; delete process.env.SENTINEL_BASE_URL; }
    expect(gw.seen).toHaveLength(1);
    expect(() => new SentinelAI()).toThrow(SentinelConfigError);
  });

  it("the key does not appear when the client is logged, inspected or serialized", async () => {
    const { inspect } = await import("node:util");
    const c = client("https://gw.example.test");
    for (const out of [inspect(c), JSON.stringify(c), String(inspect(c, { depth: 5, showHidden: true })).replace(/\[Symbol[^\]]*\]/g, "")]) {
      expect(out).not.toContain(KEY);
      expect(out).not.toContain("A".repeat(43));
    }
  });

  it("a base URL path prefix is preserved and trailing slashes are normalised", async () => {
    const gw = await serve((_r, res) => json(res, 200, CHAT_OK));
    await new SentinelAI({ apiKey: KEY, baseUrl: `${gw.url}/gateway//` }).secure({ provider: "gemini", prompt: "x" });
    expect(gw.seen[0]!.url).toBe("/gateway/v1/ai/chat");
  });
});
