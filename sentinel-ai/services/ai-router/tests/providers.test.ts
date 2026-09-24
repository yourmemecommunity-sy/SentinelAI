import { describe, expect, it, vi } from "vitest";
import {
  AnthropicProvider, GeminiProvider, OllamaProvider, OpenAIProvider, ProviderError, normalizeBaseUrl, parseNdjson,
  type AIProvider, type ChatRequest,
} from "../src/index.js";

const KEY = "test-secret-key-not-real";
const res = (body: unknown, status = 200) => new Response(typeof body === "string" ? body : JSON.stringify(body), { status });
const sse = (events: string[]) => new Response(new ReadableStream<Uint8Array>({ start(c) { events.forEach((e) => c.enqueue(new TextEncoder().encode(e))); c.close(); } }), { status: 200 });
const REQ: ChatRequest = { messages: [{ role: "system", content: "be brief" }, { role: "user", content: "hi there" }] };

interface Case {
  name: string;
  make: (f: typeof fetch, extra?: { timeoutMs?: number }) => AIProvider;
  hasKey: boolean;
  ok: unknown;                 // a valid non-streaming success body
  expectedText: string;
  streamBody: string[];        // SSE / NDJSON chunks producing "Hel" + "lo"
  models: unknown;
  expectedModels: string[];
  urlPart: string;             // path fragment of the chat endpoint
}

const CASES: Case[] = [
  {
    name: "openai", hasKey: true, urlPart: "/chat/completions",
    make: (f, x) => new OpenAIProvider({ apiKey: KEY, fetch: f, baseUrl: "https://api.example.test/v1", ...x }),
    ok: { model: "gpt-x", choices: [{ message: { content: "hello" }, finish_reason: "stop" }], usage: { prompt_tokens: 3, completion_tokens: 5 } }, expectedText: "hello",
    streamBody: ['data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n', 'data: {"choices":[{"delta":{"content":"lo"}}]}\n\ndata: [DONE]\n\n'],
    models: { data: [{ id: "gpt-x" }, { id: "gpt-y" }] }, expectedModels: ["gpt-x", "gpt-y"],
  },
  {
    name: "anthropic", hasKey: true, urlPart: "/v1/messages",
    make: (f, x) => new AnthropicProvider({ apiKey: KEY, fetch: f, baseUrl: "https://api.example.test", ...x }),
    ok: { model: "claude-x", content: [{ type: "text", text: "hel" }, { type: "text", text: "lo" }], stop_reason: "end_turn", usage: { input_tokens: 3, output_tokens: 5 } }, expectedText: "hello",
    streamBody: ['event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hel"}}\n\n', 'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"lo"}}\n\ndata: {"type":"message_stop"}\n\n'],
    models: { data: [{ id: "claude-x", display_name: "Claude X" }] }, expectedModels: ["claude-x"],
  },
  {
    name: "ollama", hasKey: false, urlPart: "/api/chat",
    make: (f, x) => new OllamaProvider({ defaultModel: "llama3", fetch: f, baseUrl: "http://ollama.example.test:11434", ...x }),
    ok: { model: "llama3", message: { role: "assistant", content: "hello" }, done: true, done_reason: "stop", prompt_eval_count: 3, eval_count: 5 }, expectedText: "hello",
    streamBody: ['{"message":{"content":"Hel"},"done":false}\n{"message":{"content":"lo"},"done":false}\n', '{"message":{"content":""},"done":true}\n'],
    models: { models: [{ name: "llama3:latest" }] }, expectedModels: ["llama3:latest"],
  },
  {
    name: "gemini", hasKey: true, urlPart: ":generateContent",
    make: (f, x) => new GeminiProvider({ apiKey: KEY, fetch: f, baseUrl: "https://api.example.test/v1beta", ...x }),
    ok: { candidates: [{ content: { parts: [{ text: "hel" }, { text: "lo" }] }, finishReason: "STOP" }], usageMetadata: { promptTokenCount: 3, candidatesTokenCount: 5 } }, expectedText: "hello",
    streamBody: ['data: {"candidates":[{"content":{"parts":[{"text":"Hel"}]}}]}\n\n', 'data: {"candidates":[{"content":{"parts":[{"text":"lo"}]}}]}\n\n'],
    models: { models: [{ name: "models/gem-x", supportedGenerationMethods: ["generateContent"] }] }, expectedModels: ["gem-x"],
  },
];

describe.each(CASES)("provider contract: $name", (c) => {
  it("chat returns content, model and usage", async () => {
    const r = await c.make((async () => res(c.ok)) as unknown as typeof fetch).chat(REQ);
    expect(r.content).toBe(c.expectedText);
    expect(r.model).toBeTruthy();
    expect(r.usage).toEqual({ inputTokens: 3, outputTokens: 5 });
  });

  it("generate wraps the prompt as one user message", async () => {
    const f = vi.fn(async () => res(c.ok));
    await c.make(f as unknown as typeof fetch).generate({ prompt: "only prompt" });
    const body = String((f.mock.calls[0] as unknown as [string, RequestInit])[1].body);
    expect(body).toContain("only prompt");
    expect(body).not.toContain("be brief");
  });

  it("credentials travel only in headers: never in the URL, body or any error message", async () => {
    const f = vi.fn(async () => res(c.ok));
    await c.make(f as unknown as typeof fetch).chat(REQ);
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toContain(c.urlPart);
    expect(url).not.toContain(KEY);
    expect(String(init.body)).not.toContain(KEY);
    if (c.hasKey) expect(JSON.stringify(init.headers)).toContain(KEY);

    for (const status of [400, 401, 403, 404, 429, 500, 503, 529]) {
      const err = await c.make((async () => res(`echoed prompt "hi there" and key ${KEY}`, status)) as unknown as typeof fetch).chat(REQ).catch((e) => e);
      expect(err).toBeInstanceOf(ProviderError);
      expect(err.message).not.toContain(KEY);
      expect(err.message).not.toContain("hi there");
    }
  });

  it("maps HTTP statuses to typed errors and marks only transient ones retryable", async () => {
    const expected: [number, string, boolean][] = [[401, "auth", false], [403, "auth", false], [429, "rate_limit", true], [500, "unavailable", true], [400, "bad_request", false]];
    for (const [status, code, retryable] of expected) {
      const err = await c.make((async () => res("x", status)) as unknown as typeof fetch).chat(REQ).catch((e) => e);
      expect([err.code, err.retryable, err.status]).toEqual([code, retryable, status]);
    }
  });

  it("network failure and timeout are typed and retryable; garbage bodies are invalid_response", async () => {
    const down = await c.make((async () => { throw new TypeError("fetch failed"); }) as unknown as typeof fetch).chat(REQ).catch((e) => e);
    expect([down.code, down.retryable]).toEqual(["unavailable", true]);
    const hang = ((_u: string, init: RequestInit) => new Promise((_r, rej) => init.signal!.addEventListener("abort", () => rej(new DOMException("t", "TimeoutError"))))) as unknown as typeof fetch;
    expect((await c.make(hang, { timeoutMs: 20 }).chat(REQ).catch((e) => e)).code).toBe("timeout");
    expect((await c.make((async () => res("not json")) as unknown as typeof fetch).chat(REQ).catch((e) => e)).code).toBe("invalid_response");
  });

  it("rejects model ids that could alter the request URL, before any request is made", async () => {
    const f = vi.fn(async () => res(c.ok));
    const p = c.make(f as unknown as typeof fetch);
    for (const bad of ["../admin", "a/b", "m?key=1", "", "x".repeat(101)]) await expect(p.chat({ ...REQ, model: bad })).rejects.toThrow(RangeError);
    expect(f).not.toHaveBeenCalled();
  });

  it("refuses an empty conversation", async () => {
    const err = await c.make((async () => res(c.ok)) as unknown as typeof fetch).chat({ messages: [] }).catch((e) => e);
    expect(err).toBeInstanceOf(ProviderError);
    expect(err.code).toBe("bad_request");
  });

  it("stream yields deltas (including events split across chunks) and finishes with done", async () => {
    const whole = c.streamBody.join("");
    const cut = Math.floor(whole.length / 3);
    const chunks: string[] = [];
    for await (const ch of c.make((async () => sse([whole.slice(0, cut), whole.slice(cut)])) as unknown as typeof fetch).stream(REQ)) chunks.push(ch.done ? "<done>" : ch.delta);
    expect(chunks.join("")).toBe("Hello<done>");
  });

  it("stream rejects malformed events with a typed error", async () => {
    const bad = c.name === "ollama" ? ["{not json}\n"] : ["data: {not json}\n\n"];
    const it = c.make((async () => sse(bad)) as unknown as typeof fetch).stream(REQ);
    await expect((async () => { for await (const _ of it) { /* drain */ } })()).rejects.toBeInstanceOf(ProviderError);
  });

  it("getModels lists models; validate() is true when reachable and false (never throws) on auth/network failure", async () => {
    const p = c.make((async () => res(c.models)) as unknown as typeof fetch);
    expect((await p.getModels()).map((m) => m.id)).toEqual(c.expectedModels);
    expect(await p.validate()).toBe(true);
    expect(await c.make((async () => res("no", 401)) as unknown as typeof fetch).validate()).toBe(false);
    expect(await c.make((async () => { throw new Error("x"); }) as unknown as typeof fetch).validate()).toBe(false);
  });
});

describe("wire formats", () => {
  const capture = async (make: (f: typeof fetch) => AIProvider, ok: unknown, req: ChatRequest = REQ) => {
    const f = vi.fn(async () => res(ok));
    await make(f as unknown as typeof fetch).chat(req);
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    return { url, headers: init.headers as Record<string, string>, body: JSON.parse(String(init.body)) };
  };
  const C = CASES.find((x) => x.name === "openai")!; const A = CASES.find((x) => x.name === "anthropic")!; const O = CASES.find((x) => x.name === "ollama")!;

  it("openai: bearer auth, system message kept in-line, max_completion_tokens/temperature mapped", async () => {
    const r = await capture((f) => C.make(f), C.ok, { ...REQ, maxOutputTokens: 50, temperature: 0.3, model: "gpt-z" });
    expect(r.url).toBe("https://api.example.test/v1/chat/completions");
    expect(r.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(r.body).toMatchObject({ model: "gpt-z", stream: false, max_completion_tokens: 50, temperature: 0.3, messages: [{ role: "system" }, { role: "user" }] });
  });

  it("openai: a refusal is surfaced as blocked_by_provider, not as empty success", async () => {
    const err = await C.make((async () => res({ choices: [{ message: { content: null, refusal: "no" } }] })) as unknown as typeof fetch).chat(REQ).catch((e) => e);
    expect(err.code).toBe("blocked_by_provider");
  });

  it("anthropic: x-api-key + version header, system lifted to top level, max_tokens always present", async () => {
    const r = await capture((f) => A.make(f), A.ok);
    expect(r.url).toBe("https://api.example.test/v1/messages");
    expect(r.headers).toMatchObject({ "x-api-key": KEY, "anthropic-version": "2023-06-01" });
    expect(r.body).toMatchObject({ system: "be brief", max_tokens: 1024, messages: [{ role: "user", content: "hi there" }] });
    expect(r.body.messages).toHaveLength(1);
    expect((await capture((f) => A.make(f), A.ok, { ...REQ, maxOutputTokens: 77 })).body.max_tokens).toBe(77);
  });

  it("anthropic: a system-only conversation is rejected; refusals and overloaded streams are typed", async () => {
    expect((await A.make((async () => res(A.ok)) as unknown as typeof fetch).chat({ messages: [{ role: "system", content: "x" }] }).catch((e) => e).then((e) => e.code))).toBe("bad_request");
    const refusal = await A.make((async () => res({ content: [], stop_reason: "refusal" })) as unknown as typeof fetch).chat(REQ).catch((e) => e);
    expect(refusal.code).toBe("blocked_by_provider");
    const overloaded = A.make((async () => sse(['data: {"type":"error","error":{"type":"overloaded_error"}}\n\n'])) as unknown as typeof fetch).stream(REQ);
    const e = await (async () => { try { for await (const _ of overloaded) { /* drain */ } } catch (x) { return x as ProviderError; } })();
    expect([e?.code, e?.retryable]).toEqual(["unavailable", true]);
  });

  it("ollama: no auth header, options carry temperature/num_predict, error payloads are typed", async () => {
    const r = await capture((f) => O.make(f), O.ok, { ...REQ, maxOutputTokens: 20, temperature: 0.1 });
    expect(r.url).toBe("http://ollama.example.test:11434/api/chat");
    expect(r.headers.authorization).toBeUndefined();
    expect(r.body).toMatchObject({ model: "llama3", stream: false, options: { temperature: 0.1, num_predict: 20 } });
    const err = await O.make((async () => res({ error: "model 'x' not found" })) as unknown as typeof fetch).chat(REQ).catch((e) => e);
    expect(err.code).toBe("bad_request");
    expect(err.message).not.toContain("not found");   // provider error text is never echoed
  });
});

describe("base URL and key hygiene", () => {
  it("normalizeBaseUrl accepts http(s) only, refuses embedded credentials, strips trailing slashes", () => {
    expect(normalizeBaseUrl("https://x.test/v1///")).toBe("https://x.test/v1");
    for (const bad of ["ftp://x.test", "file:///etc/passwd", "javascript:alert(1)", "https://user:pw@x.test", "not a url"]) expect(() => normalizeBaseUrl(bad), bad).toThrow();
  });

  it("providers refuse to be constructed without required credentials/config", () => {
    expect(() => new OpenAIProvider({ apiKey: "" })).toThrow();
    expect(() => new AnthropicProvider({ apiKey: "" })).toThrow();
    expect(() => new OllamaProvider({ defaultModel: "../x" })).toThrow(RangeError);
    expect(() => new OllamaProvider({ defaultModel: "m", baseUrl: "file:///x" })).toThrow();
  });

  it("parseNdjson handles split lines, blank lines and a trailing line without newline", async () => {
    const body = new ReadableStream<Uint8Array>({ start(c) { for (const p of ['{"a":1}\n\n{"b"', ':2}\n{"c":3}']) c.enqueue(new TextEncoder().encode(p)); c.close(); } });
    const lines: string[] = [];
    for await (const l of parseNdjson(body)) lines.push(l);
    expect(lines).toEqual(['{"a":1}', '{"b":2}', '{"c":3}']);
  });
});

// ---- Real Ollama: only runs if a local server is up; the chat test additionally needs a pulled model.
const OLLAMA = process.env.OLLAMA_URL ?? "http://127.0.0.1:11434";
const models: string[] | null = await fetch(`${OLLAMA}/api/tags`, { signal: AbortSignal.timeout(1500) })
  .then(async (r) => ((await r.json()) as { models: { name: string }[] }).models.map((m) => m.name)).catch(() => null);

describe.skipIf(models === null)("REAL local Ollama server", () => {
  it("validate() and getModels() work against the real API", async () => {
    const p = new OllamaProvider({ defaultModel: "placeholder", baseUrl: OLLAMA });
    expect(await p.validate()).toBe(true);
    expect((await p.getModels()).map((m) => m.id).sort()).toEqual([...models!].sort());
  });

  it("a model that is not pulled yields a typed bad_request (real server error path), not a crash or leak", async () => {
    const p = new OllamaProvider({ defaultModel: "sentinel-nonexistent-model", baseUrl: OLLAMA });
    const err = await p.chat({ messages: [{ role: "user", content: "hi" }] }).catch((e) => e);
    expect(err).toBeInstanceOf(ProviderError);
    expect(err.code).toBe("bad_request");
    expect(err.message).not.toMatch(/not found/i);
  });

  it.skipIf(!models?.length)("real chat and streaming with the first installed model", async () => {
    const p = new OllamaProvider({ defaultModel: models![0]!, baseUrl: OLLAMA, timeoutMs: 120_000 });
    const r = await p.chat({ messages: [{ role: "user", content: "Reply with the single word: ok" }], maxOutputTokens: 16 });
    expect(r.content.length).toBeGreaterThan(0);
    let streamed = "";
    for await (const c of p.stream({ messages: [{ role: "user", content: "Say hi" }], maxOutputTokens: 16 })) streamed += c.delta;
    expect(streamed.length).toBeGreaterThan(0);
  }, 180_000);
});
