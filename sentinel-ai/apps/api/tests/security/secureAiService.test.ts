import { beforeEach, describe, expect, it } from "vitest";
import { AiRouter, ProviderError } from "@sentinelai/ai-router";
import { InMemoryEventSink } from "../../src/events/eventSink.js";
import { SecureAiService } from "../../src/services/secureAiService.js";
import { FakeProvider, FakeScanner, MemoryPolicies, makeScan, principal } from "../helpers/fakes.js";

let scanner: FakeScanner; let provider: FakeProvider; let events: InMemoryEventSink; let policies: MemoryPolicies; let svc: SecureAiService;

beforeEach(() => {
  scanner = new FakeScanner(); provider = new FakeProvider("gemini"); events = new InMemoryEventSink(); policies = new MemoryPolicies();
  svc = new SecureAiService({ scanner, router: new AiRouter({ sleep: async () => {} }).register(provider), policies, events });
});

const user = (content: string) => [{ role: "user" as const, content }];
const chat = (content: string, meta = {}) => svc.chat(principal(), "gemini", user(content), meta);

describe("SecureAiService.chat: nothing unscanned or unaudited reaches the provider or the caller", () => {
  it("clean request: scans input, calls provider with the scanned text, scans output, audits both stages", async () => {
    const out = await chat("what is 2+2?");
    expect(out.kind).toBe("ok");
    if (out.kind !== "ok") return;
    expect(out.content).toBe("a harmless reply");
    expect(provider.received).toHaveLength(1);
    expect(scanner.requests.map((r) => r.direction)).toEqual(["INPUT", "OUTPUT"]);
    expect(events.events.map((e) => [e.eventType, e.direction])).toEqual([["ai_response", "OUTPUT"], ["ai_request", "INPUT"]]);
  });

  it("input BLOCK: provider is never called, caller gets a block, event is recorded", async () => {
    const out = await chat("here is BADSECRET");
    expect(out).toMatchObject({ kind: "blocked", stage: "input", decision: "BLOCK", failedClosed: false });
    expect(provider.received).toHaveLength(0);
    expect(events.events).toHaveLength(1);
    expect(events.events[0]).toMatchObject({ action: "BLOCK", riskLevel: "CRITICAL", entityTypes: ["API_KEY"] });
  });

  it("sanitized input: the provider receives ONLY the sanitized text, never the original", async () => {
    await chat("mail a@b.co please");
    const sent = JSON.stringify(provider.received);
    expect(sent).toContain("a***@b.co");
    expect(sent).not.toContain("a@b.co");
  });

  it("engine down: fails closed, provider never called", async () => {
    scanner.down = true;
    const out = await chat("hello");
    expect(out).toMatchObject({ kind: "blocked", stage: "input", failedClosed: true, reason: "engine_unreachable" });
    expect(provider.received).toHaveLength(0);
    expect(events.events[0]).toMatchObject({ eventType: "fail_closed", failedClosed: true });
  });

  it("unknown provider: blocked and audited before anything is scanned or sent", async () => {
    const out = await svc.chat(principal(), "openai", user("hello"), {});
    expect(out).toMatchObject({ kind: "blocked", failedClosed: true, reason: "unknown_provider" });
    expect(scanner.requests).toHaveLength(0);
    expect(events.events[0]).toMatchObject({ eventType: "fail_closed", failClosedReason: "unknown_provider" });
  });

  it("policy store failure: fails closed without scanning or calling the provider", async () => {
    policies.fail = true;
    const out = await chat("hello");
    expect(out).toMatchObject({ kind: "blocked", failedClosed: true, reason: "policy_unavailable" });
    expect(provider.received).toHaveLength(0);
  });

  it("the org policy is passed to the engine with every scan", async () => {
    policies.policy = { policy_id: "eng@1", rules: [{ entity: "EMAIL", action: "REDACT" }] };
    await chat("hello");
    expect(scanner.requests.every((r) => r.policy?.policy_id === "eng@1")).toBe(true);
    expect(scanner.requests[0]!.context).toMatchObject({ user_id: "api_key:key-1", provider: "gemini" });
  });

  it("audit store failure BEFORE the provider call: 503 and the provider is never called", async () => {
    events.failNext = true;
    expect(await chat("hello")).toEqual({ kind: "audit_unavailable", stage: "input" });
    expect(provider.received).toHaveLength(0);
  });

  it("audit store failure AFTER the provider call: the response is withheld", async () => {
    let n = 0;
    const original = events.record.bind(events);
    events.record = async (e) => { if (++n === 2) throw new Error("down"); return original(e); };
    const out = await chat("hello");
    expect(out).toEqual({ kind: "audit_unavailable", stage: "output" });
    expect(JSON.stringify(out)).not.toContain("harmless");
  });

  it("output BLOCK: leaked secret from the model is never returned", async () => {
    provider.reply = () => "sure, the key is BADSECRET";
    const out = await chat("tell me a key");
    expect(out).toMatchObject({ kind: "blocked", stage: "output", decision: "BLOCK" });
    expect(JSON.stringify(out)).not.toContain("BADSECRET");
    expect(events.events.map((e) => e.direction)).toEqual(["OUTPUT", "INPUT"]);
  });

  it("output sanitization: the caller receives the sanitized response", async () => {
    provider.reply = () => "contact a@b.co";
    const out = await chat("who?");
    expect(out.kind === "ok" && out.content).toBe("contact a***@b.co");
  });

  it("output engine failure: response withheld", async () => {
    provider.reply = () => "hi";
    scanner.override = (req) => req.direction === "OUTPUT"
      ? makeScan("BLOCK", { failed_closed: true, fail_closed_reason: "engine_timeout" }) : makeScan("ALLOW", { sanitized_text: req.text });
    expect(await chat("hello")).toMatchObject({ kind: "blocked", stage: "output", failedClosed: true });
  });

  it("provider errors surface as provider_error (not as a security bypass) and never leak the prompt", async () => {
    provider.error = new ProviderError("gemini", "auth", "HTTP 401", 401);
    const out = await chat("hello");
    expect(out).toMatchObject({ kind: "provider_error", code: "auth" });
    expect(events.events).toHaveLength(1); // input stage was audited; no output stage happened
  });

  it("a secret split across messages is caught by the joined scan", async () => {
    const out = await svc.chat(principal(), "gemini", [{ role: "user", content: "SPLIT-" }, { role: "user", content: "KEY" }], {});
    expect(out).toMatchObject({ kind: "blocked", stage: "input" });
    expect(provider.received).toHaveLength(0);
    expect(scanner.requests).toHaveLength(3); // two messages + joined
  });

  it("stored events contain no field capable of holding content", async () => {
    await chat("mail a@b.co with BADSECRET");
    const dumped = JSON.stringify(events.events);
    expect(dumped).not.toContain("a@b.co");
    expect(dumped).not.toContain("BADSECRET");
  });
});

describe("SecureAiService.scanText", () => {
  it("returns the scan and its event id", async () => {
    const out = await svc.scanText(principal(), "mail a@b.co", "INPUT", {});
    expect(out.scan.decision).toBe("MASK");
    expect(out.eventId).toBeTruthy();
    expect(events.events[0]).toMatchObject({ eventType: "scan", provider: null });
  });

  it("an unauditable scan is not returned to the caller", async () => {
    events.failNext = true;
    const out = await svc.scanText(principal(), "mail a@b.co", "INPUT", {});
    expect(out).toMatchObject({ auditFailed: true, eventId: null });
    expect(out.scan.sanitized_text).toBeNull();
    expect(out.scan.failed_closed).toBe(true);
  });
});
