import Fastify, { type FastifyInstance } from "fastify";
import { registerCors, registerErrorHandler, registerRateLimit, registerSecurityHeaders, RateLimiter } from "./middleware/hardening.js";
import { registerRoutes, type RouteDeps } from "./routes/registerRoutes.js";

/** Builds the HTTP app from injected dependencies (real ones in server.ts, fakes in tests). */
export function buildApp(deps: RouteDeps, opts: { logger?: boolean } = {}): FastifyInstance {
  const production = deps.config.nodeEnv === "production";
  const app = Fastify({
    logger: opts.logger === false ? false : {
      level: production ? "info" : "debug",
      // Credentials must never appear in logs; bodies are never logged by default.
      redact: ["req.headers.authorization", "req.headers['x-sentinel-api-key']", "req.headers.cookie"],
    },
    bodyLimit: 2_000_000,
    trustProxy: false,          // enable explicitly behind a known proxy so X-Forwarded-For cannot spoof rate-limit keys
  });
  registerSecurityHeaders(app, production);
  registerCors(app, deps.config.corsOrigins);
  registerRateLimit(app, new RateLimiter(deps.config.rateLimitPerMinute));
  registerErrorHandler(app);
  registerRoutes(app, deps);
  return app;
}
