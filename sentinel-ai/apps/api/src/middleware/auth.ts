import type { FastifyReply, FastifyRequest } from "fastify";
import type { ApiKeyAuthenticator } from "../security/apiKeys.js";
import { can, type Permission, type Principal } from "../security/rbac.js";

declare module "fastify" {
  interface FastifyRequest { principal?: Principal }
}

function extractKey(req: FastifyRequest): string | undefined {
  const header = req.headers["x-sentinel-api-key"];
  if (typeof header === "string") return header;
  const auth = req.headers.authorization;
  return typeof auth === "string" && auth.startsWith("Bearer ") ? auth.slice(7) : undefined;
}

/** preHandler factory: authenticates the API key, then enforces the required permission. */
/**
 * "The credential is wrong" (401) and "the credential cannot be checked right now" (503) are different answers. Both refuse
 * the request, but answering 401 during a database outage tells every client its valid key is bad, which invites needless
 * key rotation and false alarms. The 503 depends only on the outage, never on the key, so it reveals nothing about which
 * keys exist.
 */
const authUnavailable = (reply: FastifyReply) =>
  reply.code(503).header("retry-after", "5").send({ error: "auth_unavailable" });

export function requirePermission(auth: ApiKeyAuthenticator, permission: Permission) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    let principal: Principal | null;
    try { principal = await auth.authenticate(extractKey(req)); } catch { return authUnavailable(reply); }
    if (!principal) return reply.code(401).header("www-authenticate", "Bearer").send({ error: "unauthorized" });
    if (!can(principal, permission)) return reply.code(403).send({ error: "forbidden" });
    req.principal = principal;
  };
}

/** Any valid credential, no specific permission (e.g. /v1/auth/me). */
export function authenticated(auth: ApiKeyAuthenticator) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    let principal: Principal | null;
    try { principal = await auth.authenticate(extractKey(req)); } catch { return authUnavailable(reply); }
    if (!principal) return reply.code(401).header("www-authenticate", "Bearer").send({ error: "unauthorized" });
    req.principal = principal;
  };
}

export function principalOf(req: FastifyRequest): Principal {
  if (!req.principal) throw new Error("route reached without authentication"); // programming error => 500, never open access
  return req.principal;
}
