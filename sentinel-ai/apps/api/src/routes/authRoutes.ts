import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { RateLimiter } from "../middleware/hardening.js";
import { authenticated, principalOf } from "../middleware/auth.js";
import type { ApiKeyAuthenticator } from "../security/apiKeys.js";
import type { AuthService, Session } from "../services/authService.js";
import { displayName } from "../validators/schemas.js";

const Email = z.string().trim().min(3).max(254).email();
const Password = z.string().min(1).max(128);
const SignupBody = z.object({ organization_name: displayName(200), email: Email, password: Password }).strict();
const LoginBody = z.object({ email: Email, password: Password }).strict();
const RefreshBody = z.object({ refresh_token: z.string().regex(/^snr_[A-Za-z0-9_-]{43}$/) }).strict();

const shape = (s: Session) => ({
  access_token: s.accessToken, refresh_token: s.refreshToken, token_type: "Bearer", expires_in: s.expiresIn,
  user: { id: s.user.id, organization_id: s.user.organizationId, role: s.user.role },
});

export interface AuthRouteDeps {
  authService: AuthService;
  auth: ApiKeyAuthenticator;
  signupEnabled: boolean;
  /** Attempts per minute per client IP (all auth endpoints) and per target email (login). */
  ipLimit?: number;
  emailLimit?: number;
}

/**
 * Failures are deliberately uniform (`invalid_credentials` / `invalid_token`) and authentication endpoints have their own,
 * much stricter limiter than the global one. Responses are never cached (global no-store header).
 */
export function registerAuthRoutes(app: FastifyInstance, d: AuthRouteDeps): void {
  const ipLimiter = new RateLimiter(d.ipLimit ?? 20);
  const emailLimiter = new RateLimiter(d.emailLimit ?? 10);
  const limited = (reply: FastifyReply, retry: number) => reply.code(429).header("retry-after", String(retry)).send({ error: "rate_limited" });
  const guardIp = async (req: FastifyRequest, reply: FastifyReply) => {
    const retry = ipLimiter.check(`auth:${req.ip}`);
    if (retry !== null) return limited(reply, retry);
  };

  app.post("/v1/auth/signup", { preHandler: guardIp }, async (req, reply) => {
    if (!d.signupEnabled) return reply.code(403).send({ error: "signup_disabled" });
    const b = SignupBody.parse(req.body);
    const r = await d.authService.signup({ organizationName: b.organization_name, email: b.email, password: b.password });
    if (r.ok) return reply.code(201).send(shape(r.session));
    if (r.reason === "weak_password") return reply.code(422).send({ error: "weak_password", message: r.detail });
    return reply.code(409).send({ error: "account_exists" });
  });

  app.post("/v1/auth/login", { preHandler: guardIp }, async (req, reply) => {
    const b = LoginBody.parse(req.body);
    const retry = emailLimiter.check(`login:${b.email.toLowerCase()}`);
    if (retry !== null) return limited(reply, retry);
    const session = await d.authService.login(b.email, b.password);
    return session ? reply.send(shape(session)) : reply.code(401).send({ error: "invalid_credentials" });
  });

  app.post("/v1/auth/refresh", { preHandler: guardIp }, async (req, reply) => {
    const b = RefreshBody.parse(req.body);
    const session = await d.authService.refresh(b.refresh_token);
    return session ? reply.send(shape(session)) : reply.code(401).send({ error: "invalid_token" });
  });

  app.post("/v1/auth/logout", { preHandler: guardIp }, async (req, reply) => {
    const b = RefreshBody.safeParse(req.body);
    if (b.success) await d.authService.logout(b.data.refresh_token); // always 204: never reveals whether the token existed
    return reply.code(204).send();
  });

  app.get("/v1/auth/me", { preHandler: authenticated(d.auth) }, async (req) => {
    const p = principalOf(req);
    return { user_id: p.userId, api_key_id: p.apiKeyId, organization_id: p.organizationId, role: p.role };
  });
}
