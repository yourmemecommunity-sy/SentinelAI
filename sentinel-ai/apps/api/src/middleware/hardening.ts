import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { ZodError, type ZodIssue } from "zod";

/** Secure response headers on every response (API only serves JSON, so the CSP is maximally strict). */
/** The response headers every gateway response carries. Exported because hijacked (streaming) responses skip `onSend` hooks. */
export function securityHeaders(production: boolean): Record<string, string> {
  return {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "cross-origin-resource-policy": "same-origin",
    ...(production ? { "strict-transport-security": "max-age=63072000; includeSubDomains" } : {}),
  };
}

export function registerSecurityHeaders(app: FastifyInstance, production: boolean): void {
  const headers = Object.entries(securityHeaders(production));
  app.addHook("onSend", async (_req, reply) => {
    for (const [k, v] of headers) reply.header(k, v);
    reply.removeHeader("x-powered-by");
  });
}

/** Explicit-allowlist CORS. Never reflects an unlisted origin and never emits `*`. */
export function registerCors(app: FastifyInstance, allowedOrigins: string[]): void {
  const allowed = new Set(allowedOrigins);
  app.addHook("onRequest", async (req, reply) => {
    const origin = req.headers.origin;
    if (!origin) return;
    if (allowed.has(origin)) {
      reply.header("access-control-allow-origin", origin);
      reply.header("vary", "Origin");
      reply.header("access-control-allow-headers", "content-type, authorization, x-sentinel-api-key");
      reply.header("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS");
      reply.header("access-control-max-age", "600");
    }
    if (req.method === "OPTIONS") return reply.code(allowed.has(origin) ? 204 : 403).send();
  });
}

/**
 * Fixed-window limiter, in-process. Keyed by client IP before authentication (limits credential guessing) and by API
 * key after. Multi-replica deployments need the Redis-backed limiter (planned); this one is per-instance.
 */
export class RateLimiter {
  private readonly hits = new Map<string, { count: number; resetAt: number }>();
  constructor(private readonly limit: number, private readonly windowMs = 60_000, private readonly now: () => number = Date.now) {}

  /** Returns seconds until reset when limited, otherwise null. */
  check(key: string): number | null {
    const t = this.now();
    if (this.hits.size > 10_000) for (const [k, v] of this.hits) if (v.resetAt <= t) this.hits.delete(k);
    const cur = this.hits.get(key);
    if (!cur || cur.resetAt <= t) { this.hits.set(key, { count: 1, resetAt: t + this.windowMs }); return null; }
    cur.count += 1;
    return cur.count > this.limit ? Math.ceil((cur.resetAt - t) / 1000) : null;
  }
}

export function registerRateLimit(app: FastifyInstance, limiter: RateLimiter): void {
  app.addHook("onRequest", async (req: FastifyRequest, reply: FastifyReply) => {
    if (req.url === "/health" || req.url === "/ready") return;
    const retry = limiter.check(`ip:${req.ip}`);
    if (retry !== null) return reply.code(429).header("retry-after", String(retry)).send({ error: "rate_limited" });
  });
}

/**
 * A validation message that never contains client input. Zod's defaults embed the received value for enums and
 * literals ("received 'xyz'") and the offending key names for unknown fields - found by fuzzing. Messages built from the
 * schema (allowed options, bounds, expected type) are kept; anything that could carry client data is replaced.
 */
export function safeIssueMessage(i: ZodIssue): string {
  switch (i.code) {
    case "invalid_enum_value": return `Invalid value. Expected one of: ${i.options.join(", ")}`;
    case "unrecognized_keys": return `Unrecognized field(s): ${i.keys.length}`;
    case "invalid_literal": return "Invalid literal value";
    case "invalid_type": return `Expected ${i.expected}, received ${i.received}`;   // type names, never the value
    case "custom": return i.message;                                                   // written by us, static
    default: return i.message;   // too_small/too_big/invalid_string/invalid_union...: built from the schema only
  }
}

// PostgreSQL rejects text it cannot store (NUL bytes, invalid encoding). Input validation should stop that first; if some
// field slips through, it is still the client's malformed input, not a server failure.
const PG_INVALID_TEXT = new Set(["22021", "22P05"]);

/** Errors never echo request bodies or internal details. */
export function registerErrorHandler(app: FastifyInstance): void {
  app.setErrorHandler((err: unknown, req, reply) => {
    if (err instanceof ZodError) {
      return reply.code(422).send({ error: "invalid_request", issues: err.issues.map((i) => ({ path: i.path.join("."), message: safeIssueMessage(i) })) });
    }
    const e = err as { statusCode?: number; code?: string };
    if (e.code && PG_INVALID_TEXT.has(e.code)) return reply.code(400).send({ error: "invalid_request", message: "text contains characters that cannot be stored" });
    if (e.statusCode === 413 || e.code === "FST_ERR_CTP_BODY_TOO_LARGE") return reply.code(413).send({ error: "payload_too_large" });
    if (e.statusCode && e.statusCode >= 400 && e.statusCode < 500) return reply.code(e.statusCode).send({ error: "bad_request" });
    req.log.error({ errorClass: (err as Error)?.constructor?.name }, "unhandled error");
    return reply.code(500).send({ error: "internal_error", request_id: req.id });
  });
  app.setNotFoundHandler((_req, reply) => reply.code(404).send({ error: "not_found" }));
}
