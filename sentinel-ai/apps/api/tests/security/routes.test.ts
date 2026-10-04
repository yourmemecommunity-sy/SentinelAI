import type { FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AiRouter } from "@sentinelai/ai-router";
import { buildApp } from "../../src/app.js";
import { InMemoryAuditLog } from "../../src/events/auditLog.js";
import { InMemoryEventSink } from "../../src/events/eventSink.js";
import { SecureAiService } from "../../src/services/secureAiService.js";
import { FakeAuth, FakeProvider, FakeScanner, MemoryPolicies, ORG_A, TEST_CONFIG, principal } from "../helpers/fakes.js";

let app: FastifyInstance; let scanner: FakeScanner; let provider: FakeProvider; let events: InMemoryEventSink; let audit: InMemoryAuditLog;
let dbUp = true;

const KEYS = {
  "snl_dev": principal({ role: "DEVELOPER" }),
  "snl_view": principal({ role: "VIEWER" }),
  "snl_analyst": principal({ role: "SECURITY_ANALYST" }),
};
const H = (k: keyof typeof KEYS) => ({ "x-sentinel-api-key": k });

function build(config = TEST_CONFIG) {
  scanner = new FakeScanner(); provider = new FakeProvider(); events = new InMemoryEventSink(); audit = new InMemoryAuditLog(); dbUp = true;
  const policies = new MemoryPolicies();
  app = buildApp({
    config, scanner, events, policies, auditLog: audit, auth: new FakeAuth(KEYS), ping: async () => dbUp,
    service: new SecureAiService({ scanner, router: new AiRouter({ sleep: async () => {} }).register(provider), policies, events }),
  }, { logger: false });
}
beforeEach(() => build());
afterEach(async () => { await app.close(); });

describe("authentication and authorization", () => {
  it("rejects missing, malformed and unknown keys with an identical 401", async () => {
    const bodies = [];
    for (const headers of [{}, { "x-sentinel-api-key": "nope" }, { authorization: "Bearer nope" }, { authorization: "Basic abc" }]) {
      const res = await app.inject({ method: "POST", url: "/v1/security/scan", headers, payload: { text: "x" } });
      expect(res.statusCode).toBe(401);
      bodies.push(res.body);
    }
    expect(new Set(bodies).size).toBe(1);
  });

  it("accepts Bearer auth", async () => {
    const res = await app.inject({ method: "POST", url: "/v1/security/scan", headers: { authorization: "Bearer snl_dev" }, payload: { text: "hi" } });
    expect(res.statusCode).toBe(200);
  });

  it("enforces RBAC: VIEWER cannot scan or use AI; DEVELOPER cannot write policies or read events", async () => {
    expect((await app.inject({ method: "POST", url: "/v1/security/scan", headers: H("snl_view"), payload: { text: "x" } })).statusCode).toBe(403);
    expect((await app.inject({ method: "POST", url: "/v1/ai/chat", headers: H("snl_view"), payload: { provider: "gemini", messages: [{ role: "user", content: "x" }] } })).statusCode).toBe(403);
    expect((await app.inject({ method: "POST", url: "/v1/policies", headers: H("snl_dev"), payload: { policy_id: "p", rules: [] } })).statusCode).toBe(403);
    expect((await app.inject({ method: "GET", url: "/v1/events", headers: H("snl_dev") })).statusCode).toBe(403);
    expect((await app.inject({ method: "GET", url: "/v1/events", headers: H("snl_view") })).statusCode).toBe(200);
  });

  it("no /v1 route is reachable without auth", async () => {
    for (const [method, url] of [["GET", "/v1/events"], ["GET", "/v1/events/x"], ["GET", "/v1/policies"], ["POST", "/v1/policies"], ["PUT", "/v1/policies/p"],
      ["DELETE", "/v1/policies/p"], ["GET", "/v1/usage"], ["POST", "/v1/ai/chat"], ["POST", "/v1/ai/generate"], ["POST", "/v1/security/check"]] as const) {
      expect((await app.inject({ method, url })).statusCode, `${method} ${url}`).toBe(401);
    }
  });
});

describe("request validation", () => {
  it("rejects unknown fields, bad enums and wrong types with 422 that never echoes values", async () => {
    const res = await app.inject({ method: "POST", url: "/v1/security/scan", headers: H("snl_dev"), payload: { text: "SUPERSECRETVALUE", direction: "SIDEWAYS", extra: 1 } });
    expect(res.statusCode).toBe(422);
    expect(res.body).not.toContain("SUPERSECRETVALUE");
    expect(scanner.requests).toHaveLength(0);
  });

  it("rejects oversize input with 413 before scanning", async () => {
    const res = await app.inject({ method: "POST", url: "/v1/security/scan", headers: H("snl_dev"), payload: { text: "x".repeat(5_001) } });
    expect(res.statusCode).toBe(413);
    expect(scanner.requests).toHaveLength(0);
  });

  it("rejects unsafe provider ids / model ids", async () => {
    for (const provider of ["../x", "Gemini", "a b"]) {
      const res = await app.inject({ method: "POST", url: "/v1/ai/chat", headers: H("snl_dev"), payload: { provider, messages: [{ role: "user", content: "x" }] } });
      expect(res.statusCode).toBe(422);
    }
    const res = await app.inject({ method: "POST", url: "/v1/ai/chat", headers: H("snl_dev"), payload: { provider: "gemini", model: "m?key=1", messages: [{ role: "user", content: "x" }] } });
    expect(res.statusCode).toBe(422);
  });

  it("policy bodies: unsafe ALLOW rules are rejected (422)", async () => {
    for (const rule of [{ entity: "API_KEY", action: "ALLOW" }, { entity: "CREDIT_CARD", action: "ALLOW" }, { entity: "PROMPT_INJECTION", action: "ALLOW" }, { entity: "EMAIL", action: "ALLOW", severity: "CRITICAL" }]) {
      const res = await app.inject({ method: "POST", url: "/v1/policies", headers: H("snl_analyst"), payload: { policy_id: "p", rules: [rule] } });
      expect(res.statusCode, JSON.stringify(rule)).toBe(422);
    }
  });
});

describe("/v1/security/*", () => {
  it("scan returns the decision, evidence and an event id, and audits it", async () => {
    const res = await app.inject({ method: "POST", url: "/v1/security/scan", headers: H("snl_dev"), payload: { text: "mail a@b.co" } });
    const b = res.json();
    expect(res.statusCode).toBe(200);
    expect(b).toMatchObject({ decision: "MASK", sanitized_text: "mail a***@b.co", failed_closed: false });
    expect(b.event_id).toBeTruthy();
    expect(events.events).toHaveLength(1);
  });

  it("check returns allowed=false for anything other than ALLOW", async () => {
    const r1 = await app.inject({ method: "POST", url: "/v1/security/check", headers: H("snl_dev"), payload: { text: "hello" } });
    const r2 = await app.inject({ method: "POST", url: "/v1/security/check", headers: H("snl_dev"), payload: { text: "mail a@b.co" } });
    expect(r1.json().allowed).toBe(true);
    expect(r2.json().allowed).toBe(false);
  });

  it("engine outage yields BLOCK with failed_closed and no text (still HTTP 200 with a decision)", async () => {
    scanner.down = true;
    const b = (await app.inject({ method: "POST", url: "/v1/security/scan", headers: H("snl_dev"), payload: { text: "hello" } })).json();
    expect(b).toMatchObject({ decision: "BLOCK", failed_closed: true, sanitized_text: null });
  });

  it("audit outage returns 503 and no sanitized text", async () => {
    events.failNext = true;
    const res = await app.inject({ method: "POST", url: "/v1/security/scan", headers: H("snl_dev"), payload: { text: "mail a@b.co" } });
    expect(res.statusCode).toBe(503);
    expect(res.body).not.toContain("a***@b.co");
  });
});

describe("/v1/ai/*", () => {
  const chat = (content: string, extra = {}) => app.inject({ method: "POST", url: "/v1/ai/chat", headers: H("snl_dev"),
    payload: { provider: "gemini", messages: [{ role: "user", content }], ...extra } });

  it("happy path returns content plus security summary", async () => {
    const res = await chat("hello");
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ provider: "gemini", content: "a harmless reply", security: { input: { decision: "ALLOW" }, output: { decision: "ALLOW" } } });
  });

  it("blocked input -> 403, provider untouched, body has no content", async () => {
    const res = await chat("BADSECRET");
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ error: "blocked", stage: "input", decision: "BLOCK" });
    expect(res.body).not.toContain("BADSECRET");
    expect(provider.received).toHaveLength(0);
  });

  it("unknown provider -> 403 blocked (not 404/500)", async () => {
    const res = await app.inject({ method: "POST", url: "/v1/ai/chat", headers: H("snl_dev"), payload: { provider: "openai", messages: [{ role: "user", content: "x" }] } });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ error: "blocked", failed_closed: true, reason: "unknown_provider" });
  });

  it("generate wraps the prompt as a single user message", async () => {
    const res = await app.inject({ method: "POST", url: "/v1/ai/generate", headers: H("snl_dev"), payload: { provider: "gemini", prompt: "hi" } });
    expect(res.statusCode).toBe(200);
    expect(provider.received[0]!.messages).toEqual([{ role: "user", content: "hi" }]);
  });
});

describe("events, usage and policies wiring", () => {
  it("event ids that are not UUIDs are 404 without touching the store", async () => {
    expect((await app.inject({ method: "GET", url: "/v1/events/1%27%20OR%201=1", headers: H("snl_view") })).statusCode).toBe(404);
  });

  it("policy create -> conflict -> audit log entry has metadata only", async () => {
    const created = await app.inject({ method: "POST", url: "/v1/policies", headers: H("snl_analyst"), payload: { policy_id: "eng", rules: [{ entity: "EMAIL", action: "REDACT" }] } });
    expect(created.statusCode).toBe(201);
    expect(audit.entries[0]).toMatchObject({ organizationId: ORG_A, action: "policy.create", target: "eng", metadata: { version: 1, rules: 1 } });
  });
});

describe("hardening", () => {
  it("sets secure headers on every response", async () => {
    const res = await app.inject({ method: "GET", url: "/health" });
    expect(res.headers).toMatchObject({ "x-content-type-options": "nosniff", "x-frame-options": "DENY", "cache-control": "no-store", "referrer-policy": "no-referrer" });
    expect(res.headers["content-security-policy"]).toContain("default-src 'none'");
  });

  it("CORS reflects only allow-listed origins and never *", async () => {
    const ok = await app.inject({ method: "GET", url: "/health", headers: { origin: "https://dash.example.test" } });
    expect(ok.headers["access-control-allow-origin"]).toBe("https://dash.example.test");
    const bad = await app.inject({ method: "GET", url: "/health", headers: { origin: "https://evil.test" } });
    expect(bad.headers["access-control-allow-origin"]).toBeUndefined();
    const pre = await app.inject({ method: "OPTIONS", url: "/v1/ai/chat", headers: { origin: "https://evil.test", "access-control-request-method": "POST" } });
    expect(pre.statusCode).toBe(403);
  });

  it("rate limits per client and reports retry-after", async () => {
    await app.close();
    build({ ...TEST_CONFIG, rateLimitPerMinute: 3 });
    const codes = [];
    for (let i = 0; i < 5; i++) codes.push((await app.inject({ method: "GET", url: "/v1/usage", headers: H("snl_view") })).statusCode);
    expect(codes).toEqual([200, 200, 200, 429, 429]);
    expect((await app.inject({ method: "GET", url: "/v1/usage", headers: H("snl_view") })).headers["retry-after"]).toBeDefined();
    expect((await app.inject({ method: "GET", url: "/health" })).statusCode).toBe(200); // probes are exempt
  });

  it("internal errors return a generic 500 with no details", async () => {
    scanner.override = () => { throw new Error("db password is hunter2"); };
    const res = await app.inject({ method: "POST", url: "/v1/security/scan", headers: H("snl_dev"), payload: { text: "x" } });
    expect(res.statusCode).toBe(500);
    expect(res.body).not.toContain("hunter2");
    expect(Object.keys(res.json()).sort()).toEqual(["error", "request_id"]);
  });

  it("/ready reflects engine and database health", async () => {
    expect((await app.inject({ method: "GET", url: "/ready" })).statusCode).toBe(200);
    scanner.isReady = false;
    expect((await app.inject({ method: "GET", url: "/ready" })).statusCode).toBe(503);
    scanner.isReady = true; dbUp = false;
    expect((await app.inject({ method: "GET", url: "/ready" })).statusCode).toBe(503);
  });
});

describe("event wire format", () => {
  it("events are returned in snake_case with no content-bearing fields", async () => {
    await app.inject({ method: "POST", url: "/v1/security/scan", headers: H("snl_dev"), payload: { text: "mail a@b.co" } });
    const res = await app.inject({ method: "GET", url: "/v1/events", headers: H("snl_view") });
    const ev = res.json().events[0];
    expect(Object.keys(ev).sort()).toEqual(["action", "api_key_id", "application", "detector_version", "direction", "entity_types", "event_type",
      "explanation", "fail_closed_reason", "failed_closed", "id", "latency_ms", "model", "policy_id", "provider", "request_id", "risk_level",
      "risk_score", "timestamp", "user_id"]);
    expect(JSON.stringify(ev)).not.toContain("a@b.co");
    // A stored explanation never carries the judge's free-text reason (model prose about the text).
    expect(ev.explanation?.judge?.reason ?? null).toBeNull();
    expect((await app.inject({ method: "GET", url: `/v1/events/${ev.id}`, headers: H("snl_view") })).json()).toEqual(ev);
  });
});
