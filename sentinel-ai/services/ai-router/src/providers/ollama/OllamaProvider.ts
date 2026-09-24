import {
  ProviderError,
  type AIProvider, type ChatRequest, type ChatResponse, type GenerateRequest, type ModelInfo, type StreamChunk,
} from "../../interfaces/AIProvider.js";
import { parseNdjson } from "../../streaming/ndjson.js";
import { assertValidModelId } from "../../validation/modelId.js";
import { normalizeBaseUrl, providerRequest, readJson } from "../http.js";

export interface OllamaConfig {
  baseUrl?: string;
  /** Required in practice: Ollama has no default model. Must be a model that has been pulled. */
  defaultModel: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

interface ChatChunk {
  model?: string;
  message?: { content?: string };
  done?: boolean;
  done_reason?: string;
  prompt_eval_count?: number;
  eval_count?: number;
  error?: string;
}

/**
 * Local models: content never leaves the machine/network, which the risk engine reflects (no external-provider penalty).
 * No API key; the base URL is operator configuration and must never be taken from request data (SSRF).
 */
export class OllamaProvider implements AIProvider {
  readonly id = "ollama";
  private readonly base: string;
  private readonly model: string;
  private readonly http: Parameters<typeof providerRequest>[0];

  constructor(cfg: OllamaConfig) {
    this.base = normalizeBaseUrl(cfg.baseUrl ?? "http://127.0.0.1:11434");
    this.model = assertValidModelId(cfg.defaultModel);
    this.http = { provider: this.id, fetchImpl: cfg.fetch ?? fetch, timeoutMs: cfg.timeoutMs ?? 120_000, headers: {} };
  }

  private body(req: ChatRequest, model: string, stream: boolean): string {
    if (req.messages.length === 0) throw new ProviderError(this.id, "bad_request", "no messages");
    return JSON.stringify({
      model, stream, messages: req.messages.map((m) => ({ role: m.role, content: m.content })),
      options: {
        ...(req.temperature !== undefined ? { temperature: req.temperature } : {}),
        ...(req.maxOutputTokens !== undefined ? { num_predict: req.maxOutputTokens } : {}),
      },
    });
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const model = assertValidModelId(req.model ?? this.model);
    const res = await providerRequest(this.http, `${this.base}/api/chat`, { method: "POST", body: this.body(req, model, false) }, req.signal);
    const json = await readJson<ChatChunk>(this.id, res);
    if (json.error) throw new ProviderError(this.id, "bad_request", "model error");
    if (!json.message) throw new ProviderError(this.id, "invalid_response", "no message");
    const usage: NonNullable<ChatResponse["usage"]> = {};
    if (json.prompt_eval_count !== undefined) usage.inputTokens = json.prompt_eval_count;
    if (json.eval_count !== undefined) usage.outputTokens = json.eval_count;
    return { model: json.model ?? model, content: json.message.content ?? "", ...(json.done_reason ? { finishReason: json.done_reason } : {}), usage };
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
    const res = await providerRequest(this.http, `${this.base}/api/chat`, { method: "POST", body: this.body(req, model, true) }, req.signal);
    if (!res.body) throw new ProviderError(this.id, "invalid_response", "empty stream");
    for await (const line of parseNdjson(res.body)) {
      let chunk: ChatChunk;
      try { chunk = JSON.parse(line) as ChatChunk; } catch { throw new ProviderError(this.id, "invalid_response", "malformed stream line"); }
      if (chunk.error) throw new ProviderError(this.id, "bad_request", "model error");
      if (chunk.message?.content) yield { delta: chunk.message.content, done: false, model };
      if (chunk.done) break;
    }
    yield { delta: "", done: true, model };
  }

  async validate(): Promise<boolean> {
    try { await this.getModels(); return true; } catch { return false; }
  }

  async getModels(): Promise<ModelInfo[]> {
    const res = await providerRequest(this.http, `${this.base}/api/tags`, { method: "GET" });
    const json = await readJson<{ models?: { name?: string }[] }>(this.id, res);
    return (json.models ?? []).filter((m): m is { name: string } => typeof m.name === "string").map((m) => ({ id: m.name, provider: this.id, displayName: m.name }));
  }
}
