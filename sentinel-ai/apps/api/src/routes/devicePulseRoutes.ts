import type { FastifyInstance, FastifyReply } from "fastify";
import {
  DIAGNOSTICS, DIAGNOSTIC_TYPES, DISCLAIMER_CODES, ERROR_CODES, LIMITATION_CODES, LIMITS, LOCALES, METRICS, SCHEMA_VERSION,
  SUPPORTED_SCHEMA_VERSIONS, validateExplainRequest, validateFeedbackRequest, type CapabilitiesResponse, type ErrorCode, type Issue,
} from "@sentinelai/devicepulse-contracts";
import { actorOf, type DevicePulseService } from "../devicepulse/devicePulseService.js";
import type { AuditLogWriter } from "../events/auditLog.js";
import { RateLimiter } from "../middleware/hardening.js";
import { principalOf, requirePermission } from "../middleware/auth.js";
import type { DevicePulseRepository } from "../repositories/devicePulseRepository.js";
import type { ApiKeyAuthenticator } from "../security/apiKeys.js";

export interface DevicePulseRouteDeps {
  auth: ApiKeyAuthenticator;
  service: DevicePulseService;
  repo: DevicePulseRepository;
  auditLog: AuditLogWriter;
  /** Injected in tests; defaults to a per-process limiter at config.explainPerMinute per credential. */
  limiter?: RateLimiter;
}

/** Typed error body shared by every DevicePulse handler. */
function sendError(reply: FastifyReply, status: number, error: ErrorCode, message: string, retryable: boolean,
  extra: { requestId?: string; issues?: Issue[] } = {}) {
  return reply.code(status).send({
    error, message, retryable, ...(extra.requestId ? { request_id: extra.requestId } : {}), ...(extra.issues ? { issues: extra.issues } : {}),
  });
}

const VALIDATION_MESSAGES: Partial<Record<ErrorCode, string>> = {
  consent_required: "Cloud analysis requires the user's explicit consent.",
  consent_outdated: "The consent text has changed; the user must accept the current version.",
  consent_expired: "The user's consent has expired and must be renewed.",
  unsupported_schema_version: "Unsupported schema_version.",
  unsupported_diagnostic_type: "Unsupported diagnostic_type.",
  invalid_observation: "One or more observations are invalid.",
  invalid_evidence_reference: "One or more evidence references are invalid.",
  invalid_local_finding: "One or more local findings are invalid.",
  insufficient_evidence: "At least one observation is required.",
  invalid_request: "The request does not match the schema.",
};

export function registerDevicePulseRoutes(app: FastifyInstance, d: DevicePulseRouteDeps): void {
  const cfg = d.service.config;
  const limiter = d.limiter ?? new RateLimiter(cfg.explainPerMinute);
  const use = { preHandler: requirePermission(d.auth, "devicepulse:use") };

  // ------------------------------------------------------------------ health (public, coarse, no organization data)
  app.get("/v1/devicepulse/health", async () => {
    const remote = await d.service.globallyAvailable();
    return { status: remote ? "ok" : "degraded", service: "devicepulse", supported_schema_versions: [...SUPPORTED_SCHEMA_VERSIONS],
      remote_analysis: remote ? "available" : "unavailable" };
  });

  // ------------------------------------------------------------------ capabilities (per organization)
  app.get("/v1/devicepulse/capabilities", use, async (req) => {
    const availability = await d.service.availability(principalOf(req).organizationId);
    const body: CapabilitiesResponse = {
      schema_version: SCHEMA_VERSION, supported_schema_versions: [...SUPPORTED_SCHEMA_VERSIONS],
      remote_analysis: { available: availability.available, reason: availability.reason },
      consent: { accepted_versions: cfg.consentVersions, max_age_days: LIMITS.consentMaxAgeDays },
      limits: {
        max_request_bytes: LIMITS.maxRequestBytes, max_observations: LIMITS.maxObservations, max_local_findings: LIMITS.maxLocalFindings,
        max_evidence_ids_per_finding: LIMITS.maxEvidenceIdsPerFinding, observation_max_age_hours: LIMITS.observationMaxAgeHours,
        clock_skew_seconds: LIMITS.clockSkewSeconds, explain_requests_per_minute: cfg.explainPerMinute, request_timeout_ms: cfg.timeoutMs,
      },
      locales: [...LOCALES],
      diagnostic_types: DIAGNOSTIC_TYPES.map((id) => ({
        id,
        metrics: DIAGNOSTICS[id].metrics.map((m) => ({ id: m, unit: METRICS[m].unit, min: METRICS[m].min, max: METRICS[m].max, integer: METRICS[m].integer })),
        local_finding_codes: [...DIAGNOSTICS[id].localFindingCodes],
        action_ids: [...DIAGNOSTICS[id].actions],
      })),
      limitation_codes: [...LIMITATION_CODES], disclaimer_codes: [...DISCLAIMER_CODES], error_codes: [...ERROR_CODES],
    };
    return body;
  });

  // ------------------------------------------------------------------ explain
  app.post("/v1/devicepulse/diagnostics/explain", { ...use, bodyLimit: LIMITS.maxRequestBytes }, async (req, reply) => {
    const p = principalOf(req);
    const actor = actorOf(p);
    if (!actor) return sendError(reply, 403, "forbidden", "Credential has no user or key identity.", false);

    // Per-credential limit (model calls cost money), on top of the gateway-wide per-IP limit. Counted before validation.
    const retry = limiter.check(`devicepulse:${p.organizationId}:${actor.type}:${actor.id}`);
    if (retry !== null) {
      return reply.code(429).header("retry-after", String(retry))
        .send({ error: "rate_limited", message: "Too many explanation requests. Try again later.", retryable: true });
    }

    const v = validateExplainRequest(req.body, { now: new Date(), acceptedConsentVersions: cfg.consentVersions });
    if (!v.ok) return sendError(reply, v.status, v.error, VALIDATION_MESSAGES[v.error] ?? "Invalid request.", false, { issues: v.issues });

    const out = await d.service.explain(p, actor, v.value, req.ip);
    if (out.kind === "error") {
      // Reason codes only: never content, never the provider's message.
      req.log.warn({ devicepulse: { error: out.error, detail: out.detail ?? null, request_id: out.requestId } }, "devicepulse explain failed");
      if (out.status === 503 || out.status === 504) reply.header("retry-after", "5");
      return sendError(reply, out.status, out.error, out.message, out.retryable, { requestId: out.requestId });
    }
    return reply.send(out.response);
  });

  // ------------------------------------------------------------------ feedback (enum-only, separately consented)
  app.post("/v1/devicepulse/diagnostics/feedback", { ...use, bodyLimit: 2048 }, async (req, reply) => {
    const p = principalOf(req);
    const actor = actorOf(p);
    if (!actor) return sendError(reply, 403, "forbidden", "Credential has no user or key identity.", false);
    const v = validateFeedbackRequest(req.body);
    if (!v.ok) return sendError(reply, v.status, v.error, VALIDATION_MESSAGES[v.error] ?? "Invalid request.", false, { issues: v.issues });
    let result;
    try {
      result = await d.repo.recordFeedback(p.organizationId, actor, { requestId: v.value.request_id, rating: v.value.rating, reasonCode: v.value.reason_code ?? null });
    } catch {
      return sendError(reply, 503, "audit_unavailable", "Feedback could not be stored. Try again later.", true);
    }
    if (result === "unknown_request") return sendError(reply, 404, "unknown_request", "No explanation with this request_id exists for this credential.", false);
    if (result === "exists") return sendError(reply, 409, "feedback_exists", "Feedback for this explanation was already recorded.", false);
    return reply.code(201).send({ schema_version: SCHEMA_VERSION, request_id: v.value.request_id, status: "recorded" });
  });

  // ------------------------------------------------------------------ erasure (consent withdrawal, account cleanup)
  app.delete("/v1/devicepulse/data", use, async (req, reply) => {
    const p = principalOf(req);
    const actor = actorOf(p);
    if (!actor) return sendError(reply, 403, "forbidden", "Credential has no user or key identity.", false);
    let deleted;
    try {
      deleted = await d.repo.deleteActorData(p.organizationId, actor);
      await d.auditLog.record({ organizationId: p.organizationId, actorId: actor.id, actorType: actor.type, action: "devicepulse.data_deleted",
        target: null, metadata: { requests: deleted.requests, feedback: deleted.feedback } });
    } catch {
      return sendError(reply, 503, "audit_unavailable", "Data could not be deleted right now. Try again later.", true);
    }
    return reply.send({ schema_version: SCHEMA_VERSION, deleted });
  });
}
