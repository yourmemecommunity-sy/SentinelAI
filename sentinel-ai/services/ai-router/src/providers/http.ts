import { ProviderError, type ChatRequest } from "../interfaces/AIProvider.js";

export interface HttpOptions {
  provider: string;
  fetchImpl: typeof fetch;
  timeoutMs: number;
  headers: Record<string, string>;
}

/**
 * One place that turns transport/HTTP failures into typed, non-leaky ProviderErrors. Response bodies are deliberately
 * never echoed (they can contain the prompt or provider-side diagnostics), and credentials only travel in headers.
 */
export async function providerRequest(o: HttpOptions, url: string, init: RequestInit, external?: AbortSignal): Promise<Response> {
  const timeout = AbortSignal.timeout(o.timeoutMs);
  let res: Response;
  try {
    res = await o.fetchImpl(url, {
      ...init,
      headers: { "content-type": "application/json", ...o.headers },
      signal: external ? AbortSignal.any([timeout, external]) : timeout,
    });
  } catch (err) {
    const timedOut = err instanceof DOMException && (err.name === "TimeoutError" || err.name === "AbortError");
    throw new ProviderError(o.provider, timedOut ? "timeout" : "unavailable", timedOut ? "request timed out" : "network error");
  }
  if (!res.ok) {
    const code = res.status === 401 || res.status === 403 ? "auth" : res.status === 429 ? "rate_limit"
      : res.status >= 500 || res.status === 529 ? "unavailable" : "bad_request";
    throw new ProviderError(o.provider, code, `HTTP ${res.status}`, res.status);
  }
  return res;
}

export async function readJson<T>(provider: string, res: Response): Promise<T> {
  try { return (await res.json()) as T; } catch { throw new ProviderError(provider, "invalid_response", "non-JSON response"); }
}

/** Only http(s) base URLs are accepted, and credentials in the URL are refused (they would end up in logs). */
export function normalizeBaseUrl(raw: string): string {
  const u = new URL(raw);
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new RangeError("base URL must be http(s)");
  if (u.username || u.password) throw new RangeError("base URL must not contain credentials");
  return raw.replace(/\/+$/, "");
}

export function splitSystem(req: ChatRequest): { system: string; turns: { role: "user" | "assistant"; content: string }[] } {
  return {
    system: req.messages.filter((m) => m.role === "system").map((m) => m.content).join("\n"),
    turns: req.messages.filter((m) => m.role !== "system").map((m) => ({ role: m.role as "user" | "assistant", content: m.content })),
  };
}
