export type Role = "system" | "user" | "assistant";
export interface ChatMessage { role: Role; content: string }

export interface ChatRequest {
  model?: string;
  messages: ChatMessage[];
  maxOutputTokens?: number;
  temperature?: number;
  signal?: AbortSignal;
}
export interface GenerateRequest {
  model?: string;
  prompt: string;
  maxOutputTokens?: number;
  temperature?: number;
  signal?: AbortSignal;
}
export interface ChatResponse {
  model: string;
  content: string;
  finishReason?: string;
  usage?: { inputTokens?: number; outputTokens?: number };
}
/** `model` is the model the request was actually sent to (adapters resolve request/default), so callers can audit and report it. */
export interface StreamChunk { delta: string; done: boolean; model?: string }
export interface ModelInfo { id: string; provider: string; displayName: string }

export type ProviderErrorCode =
  | "auth" | "rate_limit" | "bad_request" | "unavailable" | "timeout" | "invalid_response" | "blocked_by_provider";

/** Never carries the request body, prompt, or credentials in `message`. */
export class ProviderError extends Error {
  constructor(
    public readonly provider: string,
    public readonly code: ProviderErrorCode,
    message: string,
    public readonly status?: number,
  ) {
    super(`[${provider}] ${message}`);
    this.name = "ProviderError";
  }
  get retryable(): boolean {
    return this.code === "rate_limit" || this.code === "unavailable" || this.code === "timeout";
  }
}

export class UnknownProviderError extends Error {
  constructor(public readonly providerId: string) {
    super(`unknown provider: ${providerId}`);
    this.name = "UnknownProviderError";
  }
}

/** Contract every provider adapter implements. The core never contains provider-specific logic. */
export interface AIProvider {
  readonly id: string;
  chat(req: ChatRequest): Promise<ChatResponse>;
  generate(req: GenerateRequest): Promise<ChatResponse>;
  stream(req: ChatRequest): AsyncIterable<StreamChunk>;
  /** True if credentials work and the provider is reachable. Never throws for auth/network failures. */
  validate(): Promise<boolean>;
  getModels(): Promise<ModelInfo[]>;
}
