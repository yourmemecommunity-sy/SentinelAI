import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { AuditLogWriter } from "../events/auditLog.js";
import { principalOf, requirePermission } from "../middleware/auth.js";
import type { RedTeamRepository } from "../repositories/redTeamRepository.js";
import type { ApiKeyAuthenticator } from "../security/apiKeys.js";

const Counts = z.object({ attacks: z.number().int().min(0), blocked: z.number().int().min(0), slipped: z.number().int().min(0),
  by_tier: z.record(z.number().int().min(0)).optional() }).strict();

// Examples are synthetic attack prompts that the harness has already sanitized and truncated; the bound here is a second line.
const RoundSchema = z.object({
  round: z.number().int().min(1).max(100_000),
  dataset_version: z.string().min(1).max(64),
  generator_model: z.string().min(1).max(128),
  engine_version: z.string().min(1).max(256),
  attacks: z.number().int().min(0),
  blocked: z.number().int().min(0),
  slipped: z.number().int().min(0),
  per_category: z.record(z.string().max(64), Counts).refine((o) => Object.keys(o).length <= 32),
  examples: z.array(z.object({ category: z.string().max(64), outcome: z.enum(["blocked", "slipped"]), decided_by: z.string().max(32),
    text: z.string().max(240) }).strict()).max(40),
  cost_usd: z.number().min(0).max(1000),
}).strict().refine((r) => r.blocked + r.slipped === r.attacks, { message: "blocked + slipped must equal attacks" });

export function registerRedTeamRoutes(app: FastifyInstance, d: { auth: ApiKeyAuthenticator; repo: RedTeamRepository; auditLog: AuditLogWriter }): void {
  app.get("/v1/red-team/rounds", { preHandler: requirePermission(d.auth, "events:read") }, async (req) => {
    const limit = z.coerce.number().int().min(1).max(200).default(50).parse((req.query as { limit?: unknown }).limit);
    return { rounds: await d.repo.list(principalOf(req).organizationId, limit) };
  });

  app.post("/v1/red-team/rounds", { preHandler: requirePermission(d.auth, "evaluation:run") }, async (req, reply) => {
    const r = RoundSchema.parse(req.body);
    const p = principalOf(req);
    if (!(await d.repo.record(p.organizationId, r))) return reply.code(409).send({ error: "round_exists", round: r.round });
    await d.auditLog.record({ organizationId: p.organizationId, actorId: p.userId ?? p.apiKeyId, actorType: p.userId ? "user" : "api_key",
      action: "red_team.round", target: String(r.round), metadata: { attacks: r.attacks, slipped: r.slipped, generator: r.generator_model } });
    return reply.code(201).send({ round: r.round });
  });
}
