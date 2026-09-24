import {
  ProviderError,
  type AIProvider, type ChatRequest, type ChatResponse, type GenerateRequest, type ModelInfo, type StreamChunk,
} from "../../interfaces/AIProvider.js";
import { parseSse } from "../../streaming/sse.js";
import { assertValidModelId } from "../../validation/modelId.js";
import { normalizeBaseUrl, providerRequest, readJson, splitSystem } from "../http.js";

export interface AnthropicConfig {
  apiKey: string;
  baseUrl?: string;
  defaultModel?: string;
  /** The Messages API requires max_tokens; used when the caller does not set one. */
  defaultMaxTokens?: number;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

interface MessageResponse {
  model?: string;
  content?: { type: string; text?: string }[];
  stop_reason?: string | null;
  usage?: { input_tokens?: number; output_tokens?: number };
}
interface StreamEvent { type: string; delta?: { type?: string; text?: string }; error?: { type?: string } }

export class AnthropicProvider implements AIProvider {
  readonly id = "anthropic";
  private readonly base: string;
  private readonly model: string;
  private readonly maxTokens: number;
  private readonly http: Parameters<typeof providerRequest>[0];

  constructor(cfg: AnthropicConfig) {
    if (!cfg.apiKey) throw new Error("AnthropicProvider requires an apiKey");
    this.base = normalizeBaseUrl(cfg.baseUrl ?? "https://api.anthropic.com");
    this.model = assertValidModelId(cfg.defaultModel ?? "claude-sonnet-5");
    this.maxTokens = cfg.defaultMaxTokens ?? 1024;
    this.http = {
      provider: this.id, fetchImpl: cfg.fetch ?? fetch, timeoutMs: cfg.timeoutMs ?? 60_000,
      headers: { "x-api-key": cfg.apiKey, "anthropic-version": "2023-06-01" },
    };
  }

  private body(req: ChatRequest, model: string, stream: boolean): string {
    const { system, turns } = splitSystem(req);
    if (turns.length === 0) throw new ProviderError(this.id, "bad_request", "no user content");
    return JSON.stringify({
      model, max_tokens: req.maxOutputTokens ?? this.maxTokens, messages: turns, stream,
      ...(system ? { system } : {}),
      ...(req.temperature !== undefined ? { temperature: req.temperature } : {}),
    });
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const model = assertValidModelId(req.model ?? this.model);
    const res = await providerRequest(this.http, `${this.base}/v1/messages`, { method: "POST", body: this.body(req, model, false) }, req.signal);
    const json = await readJson<MessageResponse>(this.id, res);
    if (!json.content) throw new ProviderError(this.id, "invalid_response", "no content");
    if (json.stop_reason === "refusal") throw new ProviderError(this.id, "blocked_by_provider", "request refused by provider");
    const usage: NonNullable<ChatResponse["usage"]> = {};
    if (json.usage?.input_tokens !== undefined) usage.inputTokens = json.usage.input_tokens;
    if (json.usage?.output_tokens !== undefined) usage.outputTokens = json.usage.output_tokens;
    return {
      model: json.model ?? model, content: json.content.filter((b) => b.type === "text").map((b) => b.text ?? "").join(""),
      ...(json.stop_reason ? { finishReason: json.stop_reason } : {}), usage,
    };
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
    const res = await providerRequest(this.http, `${this.base}/v1/messages`, { method: "POST", body: this.body(req, model, true) }, req.signal);
    if (!res.body) throw new ProviderError(this.id, "invalid_response", "empty stream");
    for await (const data of parseSse(res.body)) {
      let ev: StreamEvent;
      try { ev = JSON.parse(data) as StreamEvent; } catch { throw new ProviderError(this.id, "invalid_response", "malformed stream event"); }
      if (ev.type === "error") throw new ProviderError(this.id, ev.error?.type === "overloaded_error" ? "unavailable" : "invalid_response", "stream error");
      if (ev.type === "content_block_delta" && ev.delta?.type === "text_delta" && ev.delta.text) yield { delta: ev.delta.text, done: false, model };
      if (ev.type === "message_stop") break;
    }
    yield { delta: "", done: true, model };
  }

  async validate(): Promise<boolean> {
    try { await this.getModels(); return true; } catch { return false; }
  }

  async getModels(): Promise<ModelInfo[]> {
    const res = await providerRequest(this.http, `${this.base}/v1/models`, { method: "GET" });
    const json = await readJson<{ data?: { id?: string; display_name?: string }[] }>(this.id, res);
    return (json.data ?? []).filter((m): m is { id: string; display_name?: string } => typeof m.id === "string")
      .map((m) => ({ id: m.id, provider: this.id, displayName: m.display_name ?? m.id }));
  }
}
