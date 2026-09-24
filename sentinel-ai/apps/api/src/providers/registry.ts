import { AiRouter, AnthropicProvider, GeminiProvider, OllamaProvider, OpenAIProvider } from "@sentinelai/ai-router";
import type { AppConfig } from "../config/env.js";

/**
 * The only place that knows which concrete providers exist. Providers are registered from operator configuration; a
 * provider that is not configured is simply absent, so requests for it are blocked as `unknown_provider`.
 */
export function registerConfiguredProviders(
  router: AiRouter,
  c: Pick<AppConfig, "geminiApiKey" | "openaiApiKey" | "anthropicApiKey" | "ollama">,
  fetchImpl?: typeof fetch,
): AiRouter {
  const f = fetchImpl ? { fetch: fetchImpl } : {};
  if (c.geminiApiKey) router.register(new GeminiProvider({ apiKey: c.geminiApiKey, ...f }));
  if (c.openaiApiKey) router.register(new OpenAIProvider({ apiKey: c.openaiApiKey, ...f }));
  if (c.anthropicApiKey) router.register(new AnthropicProvider({ apiKey: c.anthropicApiKey, ...f }));
  if (c.ollama) router.register(new OllamaProvider({ baseUrl: c.ollama.baseUrl, defaultModel: c.ollama.model, ...f }));
  return router;
}
