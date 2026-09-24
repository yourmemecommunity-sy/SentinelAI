import {
  UnknownProviderError, type AIProvider, type ChatRequest, type ChatResponse, type GenerateRequest, type StreamChunk,
} from "../interfaces/AIProvider.js";
import { withRetry, type RetryOptions } from "../retry/withRetry.js";

/**
 * Resolves a provider id to an adapter. Unknown providers throw (the gateway turns that into a fail-closed
 * block). There is deliberately NO automatic cross-provider fallback: routing sanitized content to a different
 * provider than the one the policy approved would be a policy bypass. Callers that want fallback must pass an
 * explicit, already-authorized provider list.
 */
export class AiRouter {
  private readonly providers = new Map<string, AIProvider>();
  constructor(private readonly retry: RetryOptions = {}) {}

  register(provider: AIProvider): this {
    if (this.providers.has(provider.id)) throw new Error(`provider already registered: ${provider.id}`);
    this.providers.set(provider.id, provider);
    return this;
  }

  has(id: string): boolean { return this.providers.has(id); }
  ids(): string[] { return [...this.providers.keys()]; }

  resolve(id: string): AIProvider {
    const p = this.providers.get(id);
    if (!p) throw new UnknownProviderError(id);
    return p;
  }

  async chat(providerId: string, req: ChatRequest): Promise<ChatResponse> {
    const p = this.resolve(providerId);
    return withRetry(() => p.chat(req), this.retry);
  }

  async generate(providerId: string, req: GenerateRequest): Promise<ChatResponse> {
    const p = this.resolve(providerId);
    return withRetry(() => p.generate(req), this.retry);
  }

  stream(providerId: string, req: ChatRequest): AsyncIterable<StreamChunk> {
    return this.resolve(providerId).stream(req); // streams are not retried once started
  }
}
