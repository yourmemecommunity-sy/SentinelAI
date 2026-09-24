/**
 * Error hierarchy. Every error message is built from fixed text plus non-sensitive status data: it never contains the API
 * key, request text, or response content, so errors are always safe to log.
 */
export class SentinelError extends Error {
  constructor(message: string, public readonly status?: number, public readonly code?: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** Bad SDK configuration (missing/malformed key, insecure base URL). Thrown before any network call. */
export class SentinelConfigError extends SentinelError {}

/** 401: missing, malformed, unknown, revoked or expired API key. */
export class SentinelAuthenticationError extends SentinelError {}

/** 403 without a block decision: the key's role may not use this endpoint. */
export class SentinelPermissionError extends SentinelError {}

/** 413 / 422: the request itself was rejected (too large, unknown field, bad enum...). */
export class SentinelValidationError extends SentinelError {
  constructor(message: string, status: number, public readonly issues: { path: string; message: string }[] = []) {
    super(message, status, "invalid_request");
  }
}

export class SentinelRateLimitError extends SentinelError {
  constructor(public readonly retryAfterSeconds: number | undefined) {
    super("rate limited", 429, "rate_limited");
  }
}

/**
 * The gateway BLOCKED the request (policy, prompt-injection, secrets, unknown provider, or a fail-closed condition).
 * Nothing was sent to the model (input stage) or nothing was returned to you (output stage). Carries no content.
 */
export class SentinelBlockedError extends SentinelError {
  constructor(
    public readonly stage: "input" | "output",
    public readonly decision: string,
    public readonly failedClosed: boolean,
    public readonly reason: string | null,
    public readonly eventId: string | null,
  ) {
    super(`request blocked at ${stage} stage (${decision}${failedClosed ? ", fail-closed" : ""})`, 403, "blocked");
  }
}

/** The upstream AI provider failed after the input passed security (auth/rate/unavailable...). No content returned. */
export class SentinelProviderError extends SentinelError {
  constructor(public readonly providerCode: string, public readonly eventId: string | null) {
    super(`AI provider error (${providerCode})`, 502, "provider_error");
  }
}

/** Network failure, timeout, 5xx, or an unusable response. The SDK fails closed: no content is ever returned on these. */
export class SentinelUnavailableError extends SentinelError {}
