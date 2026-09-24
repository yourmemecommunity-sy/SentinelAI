import {
  ProviderError,
  type AIProvider, type ChatRequest, type ChatResponse, type GenerateRequest, type ModelInfo, type StreamChunk,
} from "../../interfaces/AIProvider.js";
import { parseSse } from "../../streaming/sse.js";
import { assertValidModelId } from "../../validation/modelId.js";
import { providerRequest } from "../http.js";

export interface GeminiConfig {
  apiKey: string;
  baseUrl?: string;
  defaultModel?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

interface GeminiPart { text?: string }
interface GeminiCandidate { content?: { parts?: GeminiPart[] }; finishReason?: string }
interface GeminiResponse {
  candidates?: GeminiCandidate[];
  promptFeedback?: { blockReason?: string };
  usageMetadata?: { promptTokenCount?: number; candidatesTokenCount?: number };
}

export class GeminiProvider implements AIProvider {
  readonly id = "gemini";
  private readonly baseUrl: string;
  private readonly model: string;
  private readonly http: Parameters<typeof providerRequest>[0];

  constructor(private readonly cfg: GeminiConfig) {
    if (!cfg.apiKey) throw new Error("GeminiProvider requires an apiKey");
    this.baseUrl = (cfg.baseUrl ?? "https://generativelanguage.googleapis.com/v1beta").replace(/\/+$/, "");
    this.model = assertValidModelId(cfg.defaultModel ?? "gemini-2.0-flash");
    this.http = { provider: this.id, fetchImpl: cfg.fetch ?? fetch, timeoutMs: cfg.timeoutMs ?? 30_000, headers: { "x-goog-api-key": cfg.apiKey } };
  }

  /** The API key travels in a header, never in the URL, so it cannot leak into access logs. */
  private call(path: string, init: RequestInit, external?: AbortSignal): Promise<Response> {
    return providerRequest(this.http, `${this.baseUrl}${path}`, init, external);
  }

  private body(req: ChatRequest): string {
    const system = req.messages.filter((m) => m.role === "system").map((m) => m.content).join("\n");
    const contents = req.messages.filter((m) => m.role !== "system")
      .map((m) => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] }));
    if (contents.length === 0) throw new ProviderError(this.id, "bad_request", "no user content");
    return JSON.stringify({
      contents,
      ...(system ? { systemInstruction: { parts: [{ text: system }] } } : {}),
      generationConfig: {
        ...(req.maxOutputTokens !== undefined ? { maxOutputTokens: req.maxOutputTokens } : {}),
        ...(req.temperature !== undefined ? { temperature: req.temperature } : {}),
      },
    });
  }

  private text(r: GeminiResponse): string {
    return (r.candidates?.[0]?.content?.parts ?? []).map((p) => p.text ?? "").join("");
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const model = assertValidModelId(req.model ?? this.model);
    const res = await this.call(`/models/${model}:generateContent`, { method: "POST", body: this.body(req) }, req.signal);
    let json: GeminiResponse;
    try { json = (await res.json()) as GeminiResponse; } catch { throw new ProviderError(this.id, "invalid_response", "non-JSON response"); }
    if (json.promptFeedback?.blockReason) {
      throw new ProviderError(this.id, "blocked_by_provider", `prompt blocked: ${json.promptFeedback.blockReason}`);
    }
    const cand = json.candidates?.[0];
    if (!cand) throw new ProviderError(this.id, "invalid_response", "no candidates");
    const usage: NonNullable<ChatResponse["usage"]> = {};
    if (json.usageMetadata?.promptTokenCount !== undefined) usage.inputTokens = json.usageMetadata.promptTokenCount;
    if (json.usageMetadata?.candidatesTokenCount !== undefined) usage.outputTokens = json.usageMetadata.candidatesTokenCount;
    return { model, content: this.text(json), ...(cand.finishReason ? { finishReason: cand.finishReason } : {}), usage };
  }

  generate(req: GenerateRequest): Promise<ChatResponse> {
    return this.chat({
      messages: [{ role: "user", content: req.prompt }],
      ...(req.model ? { model: req.model } : {}),
      ...(req.maxOutputTokens !== undefined ? { maxOutputTokens: req.maxOutputTokens } : {}),
      ...(req.temperature !== undefined ? { temperature: req.temperature } : {}),
      ...(req.signal ? { signal: req.signal } : {}),
    });
  }

  async *stream(req: ChatRequest): AsyncGenerator<StreamChunk> {
    const model = assertValidModelId(req.model ?? this.model);
    const res = await this.call(`/models/${model}:streamGenerateContent?alt=sse`, { method: "POST", body: this.body(req) }, req.signal);
    if (!res.body) throw new ProviderError(this.id, "invalid_response", "empty stream");
    for await (const data of parseSse(res.body)) {
      let json: GeminiResponse;
      try { json = JSON.parse(data) as GeminiResponse; } catch { throw new ProviderError(this.id, "invalid_response", "malformed stream event"); }
      if (json.promptFeedback?.blockReason) throw new ProviderError(this.id, "blocked_by_provider", "prompt blocked");
      const delta = this.text(json);
      if (delta) yield { delta, done: false, model };
    }
    yield { delta: "", done: true, model };
  }

  async validate(): Promise<boolean> {
    try { await this.getModels(); return true; } catch { return false; }
  }

  async getModels(): Promise<ModelInfo[]> {
    const res = await this.call("/models", { method: "GET" });
    const json = (await res.json()) as { models?: { name?: string; displayName?: string; supportedGenerationMethods?: string[] }[] };
    return (json.models ?? [])
      .filter((m) => m.name && (m.supportedGenerationMethods ?? []).includes("generateContent"))
      .map((m) => ({ id: m.name!.replace(/^models\//, ""), provider: this.id, displayName: m.displayName ?? m.name! }));
  }
}
