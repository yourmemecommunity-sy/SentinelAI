import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { AuditLogWriter } from "../events/auditLog.js";
import { principalOf, requirePermission } from "../middleware/auth.js";
import type { ApiKeyRepository } from "../repositories/apiKeyRepository.js";
import type { ApiKeyAuthenticator } from "../security/apiKeys.js";
import { ROLES, roleCanGrant, type RoleName } from "../security/rbac.js";
import { displayName } from "../validators/schemas.js";

const CreateBody = z.object({
  name: displayName(100),
  role: z.enum(ROLES),
  expires_in_days: z.number().int().min(1).max(365).default(90),
}).strict();

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface ApiKeyRouteDeps { auth: ApiKeyAuthenticator; keys: ApiKeyRepository; auditLog: AuditLogWriter }

/**
 * Key management rules (each is enforced server-side and tested):
 *  - requires `keys:manage`, and a *user* session: API keys can never mint or revoke keys (no self-perpetuating credentials);
 *  - you may only grant a role whose permissions are a subset of your own (no privilege escalation);
 *  - you may only revoke keys whose role you could grant;
 *  - the secret is returned exactly once, in the create response; listings never contain it or its hash;
 *  - keys expire (default 90 days, max 365) and each organization is capped at 100 active keys.
 */
export function registerApiKeyRoutes(app: FastifyInstance, d: ApiKeyRouteDeps): void {
  const pre = requirePermission(d.auth, "keys:manage");
  const audit = (orgId: string, actorId: string | null, action: string, target: string, metadata: Record<string, string | number | boolean | null>) =>
    d.auditLog.record({ organizationId: orgId, actorId, actorType: "user", action, target, metadata });

  app.get("/v1/api-keys", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    if (!p.userId) return reply.code(403).send({ error: "forbidden", reason: "user_session_required" });
    return { api_keys: await d.keys.list(p.organizationId) };
  });

  app.post("/v1/api-keys", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    if (!p.userId) return reply.code(403).send({ error: "forbidden", reason: "user_session_required" });
    const b = CreateBody.parse(req.body);
    if (!roleCanGrant(p.role, b.role as RoleName)) {
      return reply.code(403).send({ error: "forbidden", reason: "cannot_grant_role", grantable: ROLES.filter((r) => roleCanGrant(p.role, r)) });
    }
    const created = await d.keys.create(p.organizationId, b.name, b.role, p.userId, new Date(Date.now() + b.expires_in_days * 86_400_000));
    if (!created) return reply.code(409).send({ error: "key_limit_reached" });
    await audit(p.organizationId, p.userId, "apikey.create", created.info.id, { role: b.role, expires_in_days: b.expires_in_days });
    // The only time the secret is ever returned.
    return reply.code(201).header("cache-control", "no-store").send({ ...created.info, key: created.key });
  });

  app.delete<{ Params: { id: string } }>("/v1/api-keys/:id", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    if (!p.userId) return reply.code(403).send({ error: "forbidden", reason: "user_session_required" });
    if (!UUID_RE.test(req.params.id)) return reply.code(404).send({ error: "not_found" });
    const existing = await d.keys.get(p.organizationId, req.params.id);
    if (!existing) return reply.code(404).send({ error: "not_found" });
    if (!roleCanGrant(p.role, existing.role)) return reply.code(403).send({ error: "forbidden", reason: "key_has_higher_privilege" });
    await d.keys.revoke(p.organizationId, req.params.id);
    await audit(p.organizationId, p.userId, "apikey.revoke", req.params.id, { role: existing.role });
    return reply.code(204).send();
  });
}
