import { createHmac, randomBytes } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { AuditLogWriter } from "../events/auditLog.js";
import { RateLimiter } from "../middleware/hardening.js";
import { principalOf, requirePermission } from "../middleware/auth.js";
import type { DirectoryRepository } from "../repositories/directoryRepository.js";
import type { ApiKeyAuthenticator } from "../security/apiKeys.js";
import { hashPassword, passwordPolicyViolation } from "../security/passwords.js";
import { ROLES, roleCanGrant, type Principal, type RoleName } from "../security/rbac.js";
import { displayName } from "../validators/schemas.js";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TOKEN_RE = /^sni_[A-Za-z0-9_-]{43}$/;

const InviteBody = z.object({
  email: z.string().trim().toLowerCase().min(3).max(254).email(),
  role: z.enum(ROLES),
  expires_in_hours: z.number().int().min(1).max(168).default(72),
}).strict();
const AcceptBody = z.object({ token: z.string().regex(TOKEN_RE), password: z.string().min(1).max(128) }).strict();
const UserPatch = z.object({ role: z.enum(ROLES).optional(), disabled: z.boolean().optional() }).strict()
  .refine((b) => b.role !== undefined || b.disabled !== undefined, { message: "nothing to change" });
const TeamBody = z.object({ name: displayName(100) }).strict();

/** Invitation tokens are stored as HMAC(pepper) - a database dump alone cannot redeem them. Domain-separated from API keys. */
export const hashInvitationToken = (pepper: string, token: string): string =>
  createHmac("sha256", pepper).update(`invitation:${token}`).digest("hex");

export interface DirectoryRouteDeps {
  auth: ApiKeyAuthenticator; directory: DirectoryRepository; auditLog: AuditLogWriter; pepper: string;
  /** Attempts/min per IP for the public accept endpoint. */
  acceptLimit?: number;
}

/**
 * User, invitation and team management. Rules (each enforced server-side and tested):
 *  - requires `users:manage` AND a user session: an API key can never create users or change roles;
 *  - a caller may only grant, and only act on users/invitations holding, a role whose permissions are a subset of their own;
 *  - a caller cannot change their own role or disable themselves (no accidental lock-out; ask another administrator);
 *  - the organization always keeps an active OWNER (a database trigger, so no code path can violate it);
 *  - disabling a user revokes their refresh tokens (trigger) and their access tokens stop working on the next request;
 *  - invitation tokens are returned once and stored only as an HMAC; acceptance is single-use, expiring and revocable.
 */
export function registerDirectoryRoutes(app: FastifyInstance, d: DirectoryRouteDeps): void {
  const pre = requirePermission(d.auth, "users:manage");
  const acceptLimiter = new RateLimiter(d.acceptLimit ?? 20);
  const sessionOnly = (p: Principal, reply: FastifyReply) => (p.userId ? null : reply.code(403).send({ error: "forbidden", reason: "user_session_required" }));
  const audit = (p: Principal, action: string, target: string, metadata: Record<string, string | number | boolean | null>) =>
    d.auditLog.record({ organizationId: p.organizationId, actorId: p.userId, actorType: "user", action, target, metadata });
  const cannotGrant = (p: Principal, reply: FastifyReply, reason = "cannot_grant_role") =>
    reply.code(403).send({ error: "forbidden", reason, grantable: ROLES.filter((r) => roleCanGrant(p.role, r)) });
  const notFound = (reply: FastifyReply) => reply.code(404).send({ error: "not_found" });

  // ---------------------------------------------------------------- users
  app.get("/v1/users", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    return sessionOnly(p, reply) ?? { users: await d.directory.listUsers(p.organizationId) };
  });

  app.patch<{ Params: { id: string } }>("/v1/users/:id", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    if (sessionOnly(p, reply)) return reply;
    if (!UUID_RE.test(req.params.id)) return notFound(reply);
    const b = UserPatch.parse(req.body);
    return changeUser(req, reply, p, req.params.id, b);
  });

  // DELETE disables (soft): security events and audit records keep referring to a real user.
  app.delete<{ Params: { id: string } }>("/v1/users/:id", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    if (sessionOnly(p, reply)) return reply;
    if (!UUID_RE.test(req.params.id)) return notFound(reply);
    return changeUser(req, reply, p, req.params.id, { disabled: true });
  });

  async function changeUser(_req: FastifyRequest, reply: FastifyReply, p: Principal, id: string, b: { role?: RoleName | undefined; disabled?: boolean | undefined }) {
    if (id === p.userId) return reply.code(403).send({ error: "forbidden", reason: "cannot_modify_self" });
    const target = await d.directory.getUser(p.organizationId, id);
    if (!target) return notFound(reply);
    if (!roleCanGrant(p.role, target.role)) return cannotGrant(p, reply, "user_has_higher_privilege");
    if (b.role !== undefined && !roleCanGrant(p.role, b.role)) return cannotGrant(p, reply);
    const r = await d.directory.updateUser(p.organizationId, id, { ...(b.role !== undefined ? { role: b.role } : {}), ...(b.disabled !== undefined ? { disabled: b.disabled } : {}) });
    if (r === "not_found") return notFound(reply);
    if (r === "last_owner") return reply.code(409).send({ error: "last_owner", message: "an organization must keep at least one active OWNER" });
    if (b.role !== undefined && b.role !== target.role) await audit(p, "user.role_change", id, { from: target.role, to: b.role });
    if (b.disabled !== undefined && b.disabled !== target.disabled) await audit(p, b.disabled ? "user.disable" : "user.enable", id, {});
    return reply.send(await d.directory.getUser(p.organizationId, id));
  }

  // ---------------------------------------------------------------- invitations
  app.post("/v1/invitations", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    if (sessionOnly(p, reply)) return reply;
    const b = InviteBody.parse(req.body);
    if (!roleCanGrant(p.role, b.role)) return cannotGrant(p, reply);
    if (await d.directory.emailInOrg(p.organizationId, b.email)) return reply.code(409).send({ error: "already_member" });
    const token = `sni_${randomBytes(32).toString("base64url")}`;
    const inv = await d.directory.createInvitation(p.organizationId, b.email, b.role, hashInvitationToken(d.pepper, token),
      new Date(Date.now() + b.expires_in_hours * 3_600_000), p.userId!);
    if (inv === "pending_exists") return reply.code(409).send({ error: "invitation_pending", hint: "revoke the pending invitation first" });
    await audit(p, "invitation.create", inv.id, { role: b.role, expires_in_hours: b.expires_in_hours });
    // The only time the token is ever returned. Deliver it to the invitee out of band.
    return reply.code(201).header("cache-control", "no-store").send({ ...inv, token });
  });

  app.get("/v1/invitations", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    return sessionOnly(p, reply) ?? { invitations: await d.directory.listInvitations(p.organizationId) };
  });

  app.delete<{ Params: { id: string } }>("/v1/invitations/:id", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    if (sessionOnly(p, reply)) return reply;
    if (!UUID_RE.test(req.params.id)) return notFound(reply);
    const inv = await d.directory.getInvitation(p.organizationId, req.params.id);
    if (!inv) return notFound(reply);
    if (!roleCanGrant(p.role, inv.role)) return cannotGrant(p, reply, "invitation_has_higher_privilege");
    if (!(await d.directory.revokeInvitation(p.organizationId, inv.id))) return reply.code(409).send({ error: "not_pending", status: inv.status });
    await audit(p, "invitation.revoke", inv.id, { role: inv.role });
    return reply.code(204).send();
  });

  // Public: the invitee has no account yet. Failures are uniform (`invalid_invitation`) except a taken address, which only
  // the holder of a valid token can learn and which they need to know.
  app.post("/v1/invitations/accept", async (req, reply) => {
    const retry = acceptLimiter.check(`accept:${req.ip}`);
    if (retry !== null) return reply.code(429).header("retry-after", String(retry)).send({ error: "rate_limited" });
    const parsed = AcceptBody.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "invalid_invitation" });
    const weak = passwordPolicyViolation(parsed.data.password, "");
    if (weak) return reply.code(422).send({ error: "weak_password", message: weak });
    const r = await d.directory.acceptInvitation(hashInvitationToken(d.pepper, parsed.data.token), await hashPassword(parsed.data.password));
    if (r.status === "invalid") return reply.code(400).send({ error: "invalid_invitation" });
    if (r.status !== "ok") return reply.code(409).send({ error: "account_exists" });
    await d.auditLog.record({ organizationId: r.organizationId, actorId: r.userId, actorType: "user", action: "invitation.accept", target: r.userId, metadata: { role: r.role } })
      .catch(() => undefined);   // the account exists either way; do not fail the invitee on an audit hiccup
    return reply.code(201).send({ user_id: r.userId, organization_id: r.organizationId, role: r.role });
  });

  // ---------------------------------------------------------------- teams (organizational grouping; not an authorization boundary)
  app.get("/v1/teams", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    return sessionOnly(p, reply) ?? { teams: await d.directory.listTeams(p.organizationId) };
  });

  app.post("/v1/teams", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    if (sessionOnly(p, reply)) return reply;
    const t = await d.directory.createTeam(p.organizationId, TeamBody.parse(req.body).name);
    if (t === "exists") return reply.code(409).send({ error: "team_exists" });
    await audit(p, "team.create", t.id, { name: t.name });
    return reply.code(201).send(t);
  });

  app.delete<{ Params: { id: string } }>("/v1/teams/:id", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    if (sessionOnly(p, reply)) return reply;
    if (!UUID_RE.test(req.params.id) || !(await d.directory.deleteTeam(p.organizationId, req.params.id))) return notFound(reply);
    await audit(p, "team.delete", req.params.id, {});
    return reply.code(204).send();
  });

  app.put<{ Params: { id: string; userId: string } }>("/v1/teams/:id/members/:userId", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    if (sessionOnly(p, reply)) return reply;
    if (!UUID_RE.test(req.params.id) || !UUID_RE.test(req.params.userId)) return notFound(reply);
    if ((await d.directory.addMember(p.organizationId, req.params.id, req.params.userId)) === "not_found") return notFound(reply);
    await audit(p, "team.member_add", req.params.id, { user_id: req.params.userId });
    return reply.code(204).send();
  });

  app.delete<{ Params: { id: string; userId: string } }>("/v1/teams/:id/members/:userId", { preHandler: pre }, async (req, reply) => {
    const p = principalOf(req);
    if (sessionOnly(p, reply)) return reply;
    if (!UUID_RE.test(req.params.id) || !UUID_RE.test(req.params.userId)) return notFound(reply);
    if (!(await d.directory.removeMember(p.organizationId, req.params.id, req.params.userId))) return notFound(reply);
    await audit(p, "team.member_remove", req.params.id, { user_id: req.params.userId });
    return reply.code(204).send();
  });
}
