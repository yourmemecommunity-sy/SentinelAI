import { describe, expect, it, vi } from "vitest";
import type { ScanResult } from "@sentinelai/shared-types";
import { HttpSecurityClient, failClosedResult } from "../../src/security/securityClient.js";
import { makeScan } from "../helpers/fakes.js";

const REQ = { text: "hello", organization_id: "org", direction: "INPUT" as const };
// Classifier and judge allowances off unless a test is about them (they add seconds to every timeout).
const NO_TIER23 = { classifierMsPerWindow: 0, judgeAllowanceMs: 0 } as const;
const client = (f: typeof fetch, timeoutMs = 200) => new HttpSecurityClient({ baseUrl: "http://engine.test", timeoutMs, fetch: f, token: "internal-token", ...NO_TIER23 });
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const expectFailClosed = (r: ScanResult, reason: string | RegExp) => {
  expect(r.decision).toBe("BLOCK");
  expect(r.failed_closed).toBe(true);
  expect(r.sanitized_text).toBeNull();
  expect(r.fail_closed_reason).toMatch(reason);
  expect(r.risk.risk_level).toBe("CRITICAL");
};

describe("HttpSecurityClient fails closed", () => {
  it("passes a valid engine response through and sends the internal token", async () => {
    const f = vi.fn(async () => json(makeScan("ALLOW", { sanitized_text: "hello" })));
    const r = await client(f as unknown as typeof fetch).scan(REQ);
    expect(r.decision).toBe("ALLOW");
    expect(r.sanitized_text).toBe("hello");
    const init = (f.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect((init.headers as Record<string, string>)["x-internal-token"]).toBe("internal-token");
  });

  it("network error -> engine_unreachable", async () => {
    expectFailClosed(await client((async () => { throw new TypeError("ECONNREFUSED"); }) as unknown as typeof fetch).scan(REQ), "engine_unreachable");
  });

  it("timeout -> engine_timeout", async () => {
    const hang = ((_u: string, init: RequestInit) => new Promise((_r, rej) => {
      init.signal!.addEventListener("abort", () => rej(new DOMException("t", "TimeoutError")));
    })) as unknown as typeof fetch;
    expectFailClosed(await client(hang, 30).scan(REQ), "engine_timeout");
  });

  it("the timeout grows with text length (NER cost is proportional to length), and still fails closed when exceeded", async () => {
    // an engine that answers after 200 ms, and a 10,000-character text
    const slow = ((_u: string, init: RequestInit) => new Promise((resolve, rej) => {
      const t = setTimeout(() => resolve(json(makeScan("ALLOW", { sanitized_text: "x" }))), 200);
      init.signal!.addEventListener("abort", () => { clearTimeout(t); rej(new DOMException("t", "TimeoutError")); });
    })) as unknown as typeof fetch;
    const long = { ...REQ, text: "x".repeat(10_000) };
    const noAllowance = new HttpSecurityClient({ baseUrl: "http://engine.test", timeoutMs: 50, timeoutPerKcharMs: 0, fetch: slow, ...NO_TIER23 });
    expectFailClosed(await noAllowance.scan(long), "engine_timeout");
    const withAllowance = new HttpSecurityClient({ baseUrl: "http://engine.test", timeoutMs: 50, timeoutPerKcharMs: 60, fetch: slow, ...NO_TIER23 });
    expect((await withAllowance.scan(long)).decision).toBe("ALLOW");            // 50 + 60 x 10 = 650 ms > 200 ms
    expectFailClosed(await withAllowance.scan({ ...REQ, text: "short" }), "engine_timeout"); // 50 + 60 x 1 = 110 ms < 200 ms
  });

  it("allows for the engine's classifier (per window, capped at 4) and its AI judge", () => {
    const c = new HttpSecurityClient({ baseUrl: "http://engine.test", timeoutMs: 2000, timeoutPerKcharMs: 60, fetch: fetch });
    expect(c.timeoutFor(100)).toBe(2000 + 60 + 1800 + 4500);                 // 1 window
    expect(c.timeoutFor(3000)).toBe(2000 + 180 + 1800 * 2 + 4500);           // 2 windows
    expect(c.timeoutFor(100_000)).toBe(2000 + 6000 + 1800 * 4 + 4500);       // capped: the engine scores at most 4 windows
  });

  it.each([401, 422, 500, 503])("HTTP %i -> engine_http_%i", async (status) => {
    expectFailClosed(await client((async () => json({ detail: "x" }, status)) as unknown as typeof fetch).scan(REQ), `engine_http_${status}`);
  });

  it("non-JSON, wrong-shape and unknown-enum responses are rejected as invalid", async () => {
    const bodies: unknown[] = ["not json", { decision: "ALLOW" }, { ...makeScan("ALLOW", { sanitized_text: "x" }), decision: "MAYBE" },
      { ...makeScan("ALLOW", { sanitized_text: "x" }), risk: { risk_score: 500, risk_level: "LOW", decision: "ALLOW", factors: [] } }];
    for (const b of bodies) {
      const f = (async () => (typeof b === "string" ? new Response(b, { status: 200 }) : json(b))) as unknown as typeof fetch;
      expectFailClosed(await client(f).scan(REQ), "engine_invalid_response");
    }
  });

  it("rejects responses that violate engine invariants (a withheld decision must not carry text, and vice versa)", async () => {
    const leaky = makeScan("BLOCK", { sanitized_text: "the secret is still here" });
    expectFailClosed(await client((async () => json(leaky)) as unknown as typeof fetch).scan(REQ), "engine_invariant_violation");
    const empty = makeScan("MASK", { sanitized_text: null });
    expectFailClosed(await client((async () => json(empty)) as unknown as typeof fetch).scan(REQ), "engine_invariant_violation");
    const lying = makeScan("ALLOW", { failed_closed: true, sanitized_text: "x" });
    expectFailClosed(await client((async () => json(lying)) as unknown as typeof fetch).scan(REQ), "engine_invariant_violation");
  });

  it("ready() is false when the engine is down or not ready", async () => {
    expect(await client((async () => new Response("", { status: 503 })) as unknown as typeof fetch).ready()).toBe(false);
    expect(await client((async () => { throw new Error("x"); }) as unknown as typeof fetch).ready()).toBe(false);
    expect(await client((async () => json({ status: "ready" })) as unknown as typeof fetch).ready()).toBe(true);
  });

  it("failClosedResult is always a CRITICAL BLOCK without text", () => {
    expectFailClosed(failClosedResult("whatever"), "whatever");
  });
});
