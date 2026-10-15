import { randomUUID } from "node:crypto";
import {
  SCHEMA_VERSION, type ActionId, type DisclaimerCode, type ErrorCode, type ExplainRequest, type ExplainResponse,
} from "@sentinelai/devicepulse-contracts";
import type { DevicePulseConfig } from "../config/env.js";
import type { RouterSource } from "../providers/orgRouters.js";
import type { Actor, DevicePulseRepository } from "../repositories/devicePulseRepository.js";
import type { Principal } from "../security/rbac.js";
import type { SecurityScanner } from "../security/securityClient.js";
import type { SecureAiService } from "../services/secureAiService.js";
import { validateModelOutput } from "./modelOutput.js";
import { buildPrompt } from "./prompt.js";

/** Application name recorded on every security event, so DevicePulse traffic is attributable in /v1/events and /v1/usage. */
export const DEVICEPULSE_APPLICATION = "devicepulse";

export type ExplainOutcome =
  | { kind: "ok"; response: ExplainResponse }
  | { kind: "error"; status: number; error: ErrorCode; retryable: boolean; message: string; requestId: string;
      /** Internal diagnosis for logs only (never sent to the client). */ detail?: string };

export type RemoteAvailability = { available: true; reason: null }
  | { available: false; reason: "not_configured" | "provider_disabled_for_organization" | "provider_config_unavailable" | "security_engine_unavailable" };

export interface DevicePulseDeps {
  config: DevicePulseConfig;
  secureAi: SecureAiService;
  routers: RouterSource;
  scanner: SecurityScanner;
  repo: DevicePulseRepository;
  now?: () => Date;
}

export const actorOf = (p: Principal): Actor | null =>
  p.userId ? { type: "user", id: p.userId } : p.apiKeyId ? { type: "api_key", id: p.apiKeyId } : null;

const SAFETY_TEMPERATURE: Partial<Record<string, number>> = { battery_temperature: 45, skin_temperature: 45, cpu_temperature: 90 };

/** Disclaimers are decided here from the request and the approved actions, never by the model. */
export function disclaimersFor(req: ExplainRequest, actions: readonly ActionId[]): DisclaimerCode[] {
  const out: DisclaimerCode[] = ["ai_generated_content", "not_professional_repair_advice"];
  const hot = req.observations.some((o) => (SAFETY_TEMPERATURE[o.metric] !== undefined && o.value >= SAFETY_TEMPERATURE[o.metric]!)
    || (o.metric === "thermal_status" && o.value >= 3))
    || req.local_findings.some((f) => f.code === "device_overheating" || f.code === "high_battery_temperature");
  if (hot) out.push("battery_safety_warning");
  if (actions.some((a) => a === "review_large_files" || a === "remove_unused_apps")) out.push("backup_before_deleting_data");
  return out;
}

const level = (c: number): "low" | "medium" | "high" => (c < 0.4 ? "low" : c < 0.7 ? "medium" : "high");

const MESSAGES: Partial<Record<ErrorCode, string>> = {
  consent_required: "Cloud analysis requires the user's explicit consent.",
  remote_analysis_unavailable: "Remote analysis is not available for this account. Local diagnostics are unaffected.",
  security_unavailable: "Security screening is temporarily unavailable, so nothing was sent for analysis. Try again later.",
  blocked_by_security_policy: "The request was blocked by the organization's security policy.",
  model_timeout: "The AI model did not answer in time. Local diagnostics are unaffected.",
  model_unavailable: "The AI model is temporarily unavailable. Local diagnostics are unaffected.",
  model_response_invalid: "The AI model returned an answer that failed validation, so it was discarded.",
  audit_unavailable: "The request could not be recorded, so it was not completed. Try again later.",
};

/**
 * The DevicePulse remote-analysis pipeline. Authentication, authorization, rate limiting and request validation happen in
 * the route before this runs. Then:
 *   1. remote analysis must be configured (one operator-chosen provider; no fallback to any other);
 *   2. the request is minimized into a prompt of enums, numbers and server aliases (prompt.ts);
 *   3. SecureAiService.chat: org provider settings -> org policy -> security-engine scan of the prompt -> audit event ->
 *      model call with a deadline -> security-engine scan of the reply -> audit event. Any failure there fails closed;
 *   4. the reply is validated against what was sent (modelOutput.ts) and mapped back to the client's identifiers;
 *   5. the request is recorded (for feedback and erasure); if that fails, the result is withheld.
 */
export class DevicePulseService {
  private readonly now: () => Date;
  constructor(private readonly d: DevicePulseDeps) { this.now = d.now ?? (() => new Date()); }

  get config(): DevicePulseConfig { return this.d.config; }

  /** Whether remote analysis can run for this organization right now. Never throws. */
  async availability(orgId: string): Promise<RemoteAvailability> {
    const provider = this.d.config.provider;
    if (!provider) return { available: false, reason: "not_configured" };
    let router;
    try { router = await this.d.routers.routerFor(orgId); } catch { return { available: false, reason: "provider_config_unavailable" }; }
    if (!router.has(provider)) return { available: false, reason: "provider_disabled_for_organization" };
    if (!(await this.d.scanner.ready())) return { available: false, reason: "security_engine_unavailable" };
    return { available: true, reason: null };
  }

  /** Coarse, organization-independent readiness for the public health endpoint. */
  async globallyAvailable(): Promise<boolean> {
    return !!this.d.config.provider && (await this.d.scanner.ready());
  }

  async explain(p: Principal, actor: Actor, req: ExplainRequest, ip?: string): Promise<ExplainOutcome> {
    const requestId = randomUUID();
    const err = (status: number, error: ErrorCode, retryable: boolean, detail?: string): ExplainOutcome =>
      ({ kind: "error", status, error, retryable, message: MESSAGES[error] ?? error, requestId, ...(detail ? { detail } : {}) });

    // Defence in depth: the route already refused requests without consent; nothing below may run without it either.
    if (req.consent.cloud_analysis !== true) return err(403, "consent_required", false);
    const provider = this.d.config.provider;
    if (!provider) return err(503, "remote_analysis_unavailable", false, "not_configured");

    const now = this.now();
    const { messages, aliases } = buildPrompt(req, now);
    const outcome = await this.d.secureAi.chat(p, provider, messages,
      { application: DEVICEPULSE_APPLICATION, model: this.d.config.model, ...(ip ? { ip } : {}) },
      { temperature: 0.2, maxOutputTokens: 1500, providerTimeoutMs: this.d.config.timeoutMs, hydrate: false, jsonOutput: true });

    switch (outcome.kind) {
      case "audit_unavailable": return err(503, "audit_unavailable", true, `stage_${outcome.stage}`);
      case "provider_error":
        if (outcome.code === "timeout") return err(504, "model_timeout", true);
        if (outcome.code === "invalid_response") return err(502, "model_response_invalid", false, "provider_invalid_response");
        return err(502, "model_unavailable", outcome.code === "rate_limit" || outcome.code === "unavailable", outcome.code);
      case "blocked": {
        if (outcome.reason === "unknown_provider" || outcome.reason === "provider_config_unavailable") {
          return err(503, "remote_analysis_unavailable", false, outcome.reason);
        }
        if (outcome.failedClosed) return err(503, "security_unavailable", true, outcome.reason ?? "failed_closed");
        return err(422, "blocked_by_security_policy", false, `${outcome.stage}_${outcome.decision}`);
      }
      case "ok": break;
    }

    const checked = validateModelOutput(outcome.content, req.diagnostic_type, aliases);
    if (!checked.ok) return err(502, "model_response_invalid", false, `model_output_${checked.reason}`);
    const v = checked.value;

    try {
      await this.d.repo.recordRequest({
        id: requestId, organizationId: p.organizationId, actor, diagnosticType: req.diagnostic_type, status: v.status,
        findingCount: v.findings.length, inputEventId: outcome.input.eventId, retentionDays: this.d.config.retentionDays,
      });
    } catch {
      return err(503, "audit_unavailable", true, "request_record");
    }

    return {
      kind: "ok",
      response: {
        schema_version: SCHEMA_VERSION, request_id: requestId, status: v.status, diagnostic_type: req.diagnostic_type, locale: req.locale,
        summary: v.summary, findings: v.findings,
        confidence: { overall: v.overallConfidence, level: v.status === "insufficient_data" ? "low" : level(v.overallConfidence) },
        limitations: v.limitations, recommended_action_ids: v.actions, disclaimer_codes: disclaimersFor(req, v.actions),
        processing_mode: "remote_ai", generated_at: this.now().toISOString(),
      },
    };
  }
}
