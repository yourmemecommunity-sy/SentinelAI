import {
  ProviderError,
  type AIProvider, type ChatRequest, type ChatResponse, type GenerateRequest, type ModelInfo, type StreamChunk,
} from "../../interfaces/AIProvider.js";
import { parseSse } from "../../streaming/sse.js";
import { assertValidModelId } from "../../validation/modelId.js";
import { normalizeBaseUrl, providerRequest, readJson } from "../http.js";

export interface OpenAIConfig {
  apiKey: string;
  /** Override for OpenAI-compatible endpoints (Azure OpenAI gateways, vLLM, ...). */
  baseUrl?: string;
  defaultModel?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

interface Completion {
  model?: string;
  choices?: { message?: { content?: string | null; refusal?: string | null }; delta?: { content?: string | null }; finish_reason?: string | null }[];
  usage?: { prompt_tokens?: number; completion_tokens?: number };
}

export class OpenAIProvider implements AIProvider {
  readonly id = "openai";
  private readonly base: string;
  private readonly model: string;
  private readonly http: Parameters<typeof providerRequest>[0];

  constructor(cfg: OpenAIConfig) {
    if (!cfg.apiKey) throw new Error("OpenAIProvider requires an apiKey");
    this.base = normalizeBaseUrl(cfg.baseUrl ?? "https://api.openai.com/v1");
    this.model = assertValidModelId(cfg.defaultModel ?? "gpt-4o-mini");
    this.http = { provider: this.id, fetchImpl: cfg.fetch ?? fetch, timeoutMs: cfg.timeoutMs ?? 30_000, headers: { authorization: `Bearer ${cfg.apiKey}` } };
  }

  private body(req: ChatRequest, model: string, stream: boolean): string {
    if (req.messages.length === 0) throw new ProviderError(this.id, "bad_request", "no messages");
    return JSON.stringify({
      model, messages: req.messages.map((m) => ({ role: m.role, content: m.content })), stream,
      ...(req.maxOutputTokens !== undefined ? { max_completion_tokens: req.maxOutputTokens } : {}),
      ...(req.temperature !== undefined ? { temperature: req.temperature } : {}),
    });
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const model = assertValidModelId(req.model ?? this.model);
    const res = await providerRequest(this.http, `${this.base}/chat/completions`, { method: "POST", body: this.body(req, model, false) }, req.signal);
    const json = await readJson<Completion>(this.id, res);
    const choice = json.choices?.[0];
    if (!choice) throw new ProviderError(this.id, "invalid_response", "no choices");
    if (choice.message?.refusal) throw new ProviderError(this.id, "blocked_by_provider", "request refused by provider");
    const usage: NonNullable<ChatResponse["usage"]> = {};
    if (json.usage?.prompt_tokens !== undefined) usage.inputTokens = json.usage.prompt_tokens;
    if (json.usage?.completion_tokens !== undefined) usage.outputTokens = json.usage.completion_tokens;
    return { model: json.model ?? model, content: choice.message?.content ?? "", ...(choice.finish_reason ? { finishReason: choice.finish_reason } : {}), usage };
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
    const res = await providerRequest(this.http, `${this.base}/chat/completions`, { method: "POST", body: this.body(req, model, true) }, req.signal);
    if (!res.body) throw new ProviderError(this.id, "invalid_response", "empty stream");
    for await (const data of parseSse(res.body)) {
      if (data === "[DONE]") break;
      let json: Completion;
      try { json = JSON.parse(data) as Completion; } catch { throw new ProviderError(this.id, "invalid_response", "malformed stream event"); }
      const delta = json.choices?.[0]?.delta?.content;
      if (delta) yield { delta, done: false, model };
    }
    yield { delta: "", done: true, model };
  }

  async validate(): Promise<boolean> {
    try { await this.getModels(); return true; } catch { return false; }
  }

  async getModels(): Promise<ModelInfo[]> {
    const res = await providerRequest(this.http, `${this.base}/models`, { method: "GET" });
    const json = await readJson<{ data?: { id?: string }[] }>(this.id, res);
    return (json.data ?? []).filter((m): m is { id: string } => typeof m.id === "string").map((m) => ({ id: m.id, provider: this.id, displayName: m.id }));
  }
}
