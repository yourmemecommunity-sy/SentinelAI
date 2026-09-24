import { ProviderError } from "../interfaces/AIProvider.js";

export interface RetryOptions { attempts?: number; baseDelayMs?: number; sleep?: (ms: number) => Promise<void> }

/** Retries only retryable ProviderErrors (rate limit / unavailable / timeout) with exponential backoff. */
export async function withRetry<T>(fn: () => Promise<T>, opts: RetryOptions = {}): Promise<T> {
  const attempts = opts.attempts ?? 3;
  const base = opts.baseDelayMs ?? 200;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  for (let i = 0; ; i++) {
    try {
      return await fn();
    } catch (err) {
      if (!(err instanceof ProviderError) || !err.retryable || i >= attempts - 1) throw err;
      await sleep(base * 2 ** i);
    }
  }
}
