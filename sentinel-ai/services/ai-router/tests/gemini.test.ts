import { describe, expect, it, vi } from "vitest";
import { AiRouter, GeminiProvider, ProviderError, UnknownProviderError, assertValidModelId, withRetry } from "../src/index.js";

const KEY = "test-key-not-real";
const ok = (body: unknown, init: ResponseInit = {}) => new Response(JSON.stringify(body), { status: 200, ...init });
const reply = (text: string) => ({ candidates: [{ content: { parts: [{ text }] }, finishReason: "STOP" }], usageMetadata: { promptTokenCount: 3, candidatesTokenCount: 5 } });

function provider(fetchImpl: typeof fetch, extra = {}) {
  return new GeminiProvider({ apiKey: KEY, fetch: fetchImpl, baseUrl: "https://example.test/v1beta", ...extra });
}

describe("GeminiProvider", () => {
  it("chat maps roles/system prompt, sends the key in a header only, and parses the reply", async () => {
    const f = vi.fn(async () => ok(reply("hello there")));
    const res = await provider(f as unknown as typeof fetch).chat({
      messages: [{ role: "system", content: "be brief" }, { role: "user", content: "hi" }, { role: "assistant", content: "yo" }, { role: "user", content: "again" }],
      maxOutputTokens: 50, temperature: 0.2,
    });
    expect(res).toEqual({ model: "gemini-2.0-flash", content: "hello there", finishReason: "STOP", usage: { inputTokens: 3, outputTokens: 5 } });
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://example.test/v1beta/models/gemini-2.0-flash:generateContent");
    expect(url).not.toContain(KEY);
    expect((init.headers as Record<string, string>)["x-goog-api-key"]).toBe(KEY);
    const body = JSON.parse(init.body as string);
    expect(body.systemInstruction.parts[0].text).toBe("be brief");
    expect(body.contents.map((c: { role: string }) => c.role)).toEqual(["user", "model", "user"]);
    expect(body.generationConfig).toEqual({ maxOutputTokens: 50, temperature: 0.2 });
  });

  it("maps HTTP failures to typed, non-leaky errors", async () => {
    for (const [status, code] of [[401, "auth"], [403, "auth"], [429, "rate_limit"], [500, "unavailable"], [400, "bad_request"]] as const) {
      const f = vi.fn(async () => new Response(`secret prompt echoed ${KEY}`, { status }));
      const err = await provider(f as unknown as typeof fetch).chat({ messages: [{ role: "user", content: "x" }] }).catch((e) => e);
      expect(err).toBeInstanceOf(ProviderError);
      expect(err.code).toBe(code);
      expect(err.message).not.toContain(KEY);
      expect(err.message).not.toContain("secret prompt");
    }
  });

  it("network failure and timeout are typed and retryable", async () => {
    const down = provider((async () => { throw new TypeError("fetch failed"); }) as unknown as typeof fetch);
    const e1 = await down.chat({ messages: [{ role: "user", content: "x" }] }).catch((e) => e);
    expect(e1.code).toBe("unavailable");
    expect(e1.retryable).toBe(true);
    const slow = provider(((_u: string, init: RequestInit) => new Promise((_r, rej) => {
      init.signal!.addEventListener("abort", () => rej(new DOMException("t", "TimeoutError")));
    })) as unknown as typeof fetch, { timeoutMs: 20 });
    const e2 = await slow.chat({ messages: [{ role: "user", content: "x" }] }).catch((e) => e);
    expect(e2.code).toBe("timeout");
  });

  it("surfaces provider-side prompt blocks and empty candidate lists as errors (never as empty success)", async () => {
    const blocked = provider((async () => ok({ promptFeedback: { blockReason: "SAFETY" } })) as unknown as typeof fetch);
    expect((await blocked.chat({ messages: [{ role: "user", content: "x" }] }).catch((e) => e)).code).toBe("blocked_by_provider");
    const empty = provider((async () => ok({})) as unknown as typeof fetch);
    expect((await empty.chat({ messages: [{ role: "user", content: "x" }] }).catch((e) => e)).code).toBe("invalid_response");
  });

  it("rejects model ids that could alter the request URL", async () => {
    const p = provider((async () => ok(reply("x"))) as unknown as typeof fetch);
    for (const bad of ["../admin", "a/b", "m?key=1", "", "x".repeat(101), "a b"]) {
      await expect(p.chat({ model: bad, messages: [{ role: "user", content: "x" }] })).rejects.toThrow(RangeError);
      expect(() => assertValidModelId(bad)).toThrow();
    }
  });

  it("stream yields deltas from SSE events, including events split across chunks, then done", async () => {
    const enc = new TextEncoder();
    const e1 = `data: ${JSON.stringify(reply("Hel"))}\n\n`;
    const e2 = `data: ${JSON.stringify(reply("lo"))}\n\n`;
    const parts = [e1.slice(0, 10), e1.slice(10) + e2.slice(0, 5), e2.slice(5)];
    const body = new ReadableStream<Uint8Array>({ start(c) { parts.forEach((p) => c.enqueue(enc.encode(p))); c.close(); } });
    const p = provider((async () => new Response(body, { status: 200 })) as unknown as typeof fetch);
    const chunks = [];
    for await (const c of p.stream({ messages: [{ role: "user", content: "hi" }] })) chunks.push(c);
    // Every chunk reports the model that served it, so the gateway can audit and report the real model on a stream.
    const m = chunks[0]!.model;
    expect(typeof m).toBe("string");
    expect(chunks).toEqual([{ delta: "Hel", done: false, model: m }, { delta: "lo", done: false, model: m }, { delta: "", done: true, model: m }]);
  });

  it("getModels filters to generateContent models; validate never throws", async () => {
    const list = { models: [
      { name: "models/gemini-2.0-flash", displayName: "Flash", supportedGenerationMethods: ["generateContent"] },
      { name: "models/embedding-001", supportedGenerationMethods: ["embedContent"] }] };
    expect(await provider((async () => ok(list)) as unknown as typeof fetch).getModels())
      .toEqual([{ id: "gemini-2.0-flash", provider: "gemini", displayName: "Flash" }]);
    expect(await provider((async () => new Response("", { status: 403 })) as unknown as typeof fetch).validate()).toBe(false);
  });

  it("requires an API key", () => {
    expect(() => new GeminiProvider({ apiKey: "" })).toThrow();
  });
});

describe("retry + router", () => {
  const sleep = async () => {};
  it("retries only retryable provider errors, with a bounded attempt count", async () => {
    let n = 0;
    const flaky = async () => { if (++n < 3) throw new ProviderError("x", "unavailable", "down"); return "ok"; };
    expect(await withRetry(flaky, { sleep })).toBe("ok");
    expect(n).toBe(3);
    let m = 0;
    await expect(withRetry(async () => { m++; throw new ProviderError("x", "auth", "no"); }, { sleep })).rejects.toThrow();
    expect(m).toBe(1);
    let k = 0;
    await expect(withRetry(async () => { k++; throw new ProviderError("x", "unavailable", "no"); }, { attempts: 2, sleep })).rejects.toThrow();
    expect(k).toBe(2);
  });

  it("unknown provider throws and there is no implicit fallback", async () => {
    const router = new AiRouter({ sleep });
    const p = provider((async () => ok(reply("x"))) as unknown as typeof fetch);
    router.register(p);
    expect(router.ids()).toEqual(["gemini"]);
    expect(() => router.register(p)).toThrow();
    await expect(router.chat("openai", { messages: [{ role: "user", content: "x" }] })).rejects.toBeInstanceOf(UnknownProviderError);
    expect((await router.chat("gemini", { messages: [{ role: "user", content: "x" }] })).content).toBe("x");
  });
});
