import type { FastifyInstance, FastifyReply } from "fastify";
import { z } from "zod";
import type { AuditLogWriter } from "../events/auditLog.js";
import { principalOf, requirePermission } from "../middleware/auth.js";
import { isTenantKeyed, TENANT_KEYED_PROVIDERS, type RouterSource } from "../providers/orgRouters.js";
import type { ProviderRepository } from "../repositories/providerRepository.js";
import type { ApiKeyAuthenticator } from "../security/apiKeys.js";
import type { CredentialCipher } from "../security/credentialCipher.js";
import type { Principal } from "../security/rbac.js";

// Printable ASCII without whitespace; real provider keys fit comfortably. Rejecting anything else keeps header injection and
// accidental pastes (a whole .env line, a key with a trailing newline) out of the credential store.
const CredentialBody = z.object({ api_key: z.string().regex(/^[\x21-\x7e]{16,512}$/, "api_key must be 16-512 printable characters without spaces") }).strict();
const EnabledBody = z.object({ enabled: z.boolean() }).strict();
const PROVIDER_RE = /^[a-z][a-z0-9_-]{1,31}$/;

export interface ProviderRouteDeps {
  auth: ApiKeyAuthenticator; repo: ProviderRepository; routers: RouterSource; auditLog: AuditLogWriter;
  /** Operator-configured provider ids (shared by all organizations unless overridden). */
  platformProviders: string[];
  /** Absent: organizations cannot store credentials (PUT answers 503). */
  cipher: CredentialCipher | undefined;
}

/**
 * Per-organization provider settings. Requires `providers:manage` and a user session. Credentials are write-only: they are
 * sealed (AES-256-GCM, bound to organization+provider) before they reach the database, and no response, log line or audit
 * record ever contains them - only the last 4 characters as a hint. Base URLs are not tenant-settable (SSRF).
 */
export function registerProviderRoutes(app: FastifyInstance, d: ProviderRouteDeps): void {
  const pre = requirePermission(d.auth, "providers:manage");
  const known = (id: string) => isTenantKeyed(id) || d.platformProviders.includes(id);
  const sessionOnly = (p: Principal, reply: FastifyReply) => (p.userId ? null : reply.code(403).send({ error: "forbidden", reason: "user_session_required" }));
  const audit = (p: Principal, action: string, target: string, metadata: Record<string, string | number | boolean | null>) =>
    d.auditLog.record({ organizationId: p.organizationId, actorId: p.userId, actorType: "user", action, target, metadata });

  app.get("/v1/providers", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    if (sessionOnly(p, reply)) return reply;
    const rows = new Map((await d.repo.list(p.organizationId)).map((r) => [r.provider, r]));
    const ids = [...new Set([...TENANT_KEYED_PROVIDERS, ...d.platformProviders])].sort();
    return {
      credential_storage: d.cipher ? "available" : "not_configured",
      providers: ids.map((id) => {
        const r = rows.get(id);
        const enabled = r ? r.enabled : true;
        const source = !enabled ? "disabled" : r?.sealed ? "organization" : d.platformProviders.includes(id) ? "platform" : "none";
        return { provider: id, enabled, source, organization_credential: r?.sealed ? { hint: r.hint, key_id: r.sealed.keyId, updated_at: r.updatedAt } : null,
          accepts_organization_credential: isTenantKeyed(id) };
      }),
    };
  });

  app.put<{ Params: { provider: string } }>("/v1/providers/:provider/credential", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    if (sessionOnly(p, reply)) return reply;
    const id = req.params.provider;
    if (!PROVIDER_RE.test(id) || !isTenantKeyed(id)) return reply.code(404).send({ error: "not_found", hint: `organization credentials are accepted for: ${TENANT_KEYED_PROVIDERS.join(", ")}` });
    if (!d.cipher) return reply.code(503).send({ error: "credential_storage_not_configured" });
    const { api_key } = CredentialBody.parse(req.body);
    const sealed = d.cipher.seal(p.organizationId, id, api_key);
    const hint = api_key.slice(-4).replace(/[^A-Za-z0-9_-]/g, "");
    await d.repo.setCredential(p.organizationId, id, sealed, hint, p.userId!);
    d.routers.invalidate(p.organizationId);
    await audit(p, "provider.credential_set", id, { key_id: sealed.keyId });
    return reply.code(204).send();
  });

  app.delete<{ Params: { provider: string } }>("/v1/providers/:provider/credential", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    if (sessionOnly(p, reply)) return reply;
    const id = req.params.provider;
    if (!PROVIDER_RE.test(id) || !isTenantKeyed(id)) return reply.code(404).send({ error: "not_found" });
    if (!(await d.repo.clearCredential(p.organizationId, id, p.userId!))) return reply.code(404).send({ error: "not_found" });
    d.routers.invalidate(p.organizationId);
    await audit(p, "provider.credential_delete", id, {});
    return reply.code(204).send();
  });

  app.patch<{ Params: { provider: string } }>("/v1/providers/:provider", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    if (sessionOnly(p, reply)) return reply;
    const id = req.params.provider;
    if (!PROVIDER_RE.test(id) || !known(id)) return reply.code(404).send({ error: "not_found" });
    const { enabled } = EnabledBody.parse(req.body);
    await d.repo.setEnabled(p.organizationId, id, enabled, p.userId!);
    d.routers.invalidate(p.organizationId);
    await audit(p, enabled ? "provider.enable" : "provider.disable", id, {});
    return reply.send({ provider: id, enabled });
  });
}
