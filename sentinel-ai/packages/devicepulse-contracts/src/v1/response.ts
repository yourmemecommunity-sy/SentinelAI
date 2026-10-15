import { z } from "zod";
import {
  ACTION_IDS, DIAGNOSTIC_TYPES, DISCLAIMER_CODES, ERROR_CODES, FINDING_SEVERITIES, LIMITATION_CODES, LIMITS, LOCALES,
  PROCESSING_STATUSES, SCHEMA_VERSION, UNITS,
} from "./catalog.js";
import { ClientId } from "./request.js";

const Confidence = z.number().min(0).max(1);

export const ExplainFindingSchema = z.object({
  /** Server-assigned, stable within one response: f1, f2, … */
  finding_id: z.string().regex(/^f[1-9]\d?$/),
  title: z.string().min(1).max(LIMITS.findingTitleMaxChars),
  explanation: z.string().min(1).max(LIMITS.findingExplanationMaxChars),
  severity: z.enum(FINDING_SEVERITIES),
  /** Model-estimated and uncalibrated: treat as a ranking hint, not a probability. */
  confidence: Confidence,
  /** Always a non-empty subset of the request's observation evidence ids. */
  evidence_ids: z.array(ClientId).min(1).max(LIMITS.maxEvidenceIdsPerFinding),
  /** Subset of the request's local finding ids. */
  related_local_finding_ids: z.array(ClientId).max(LIMITS.maxLocalFindings),
}).strict();

export const ExplainResponseSchema = z.object({
  schema_version: z.literal(SCHEMA_VERSION),
  request_id: z.string().uuid(),
  status: z.enum(PROCESSING_STATUSES),
  diagnostic_type: z.enum(DIAGNOSTIC_TYPES),
  locale: z.enum(LOCALES),
  summary: z.string().min(1).max(LIMITS.summaryMaxChars),
  findings: z.array(ExplainFindingSchema).max(LIMITS.maxResponseFindings),
  confidence: z.object({ overall: Confidence, level: z.enum(["low", "medium", "high"]) }).strict(),
  limitations: z.array(z.enum(LIMITATION_CODES)).min(1),
  recommended_action_ids: z.array(z.enum(ACTION_IDS)).max(LIMITS.maxRecommendedActions),
  disclaimer_codes: z.array(z.enum(DISCLAIMER_CODES)).min(1),
  processing_mode: z.literal("remote_ai"),
  generated_at: z.string().datetime({ offset: true }),
}).strict();
export type ExplainResponse = z.infer<typeof ExplainResponseSchema>;
export type ExplainFinding = z.infer<typeof ExplainFindingSchema>;

export const FeedbackResponseSchema = z.object({
  schema_version: z.literal(SCHEMA_VERSION),
  request_id: z.string().uuid(),
  status: z.literal("recorded"),
}).strict();

export const DeleteDataResponseSchema = z.object({
  schema_version: z.literal(SCHEMA_VERSION),
  deleted: z.object({ requests: z.number().int().min(0), feedback: z.number().int().min(0) }).strict(),
}).strict();

/**
 * Error body. `error` is always present. Errors raised by DevicePulse handlers also carry `message` and `retryable`, and
 * `request_id` once one was assigned; gateway-wide errors (401, 429, 413…) may carry only `error`. Clients must ignore
 * fields they do not know.
 */
export const ErrorResponseSchema = z.object({
  error: z.enum(ERROR_CODES),
  message: z.string().optional(),
  retryable: z.boolean().optional(),
  request_id: z.string().optional(),
  issues: z.array(z.object({ path: z.string(), message: z.string() })).optional(),
}).passthrough();
export type ErrorResponse = z.infer<typeof ErrorResponseSchema>;

export const HealthResponseSchema = z.object({
  status: z.enum(["ok", "degraded"]),
  service: z.literal("devicepulse"),
  supported_schema_versions: z.array(z.string()),
  /** Whether the operator configured a model for DevicePulse and the security engine answers. Per-organization detail is in /capabilities. */
  remote_analysis: z.enum(["available", "unavailable"]),
}).strict();

export const RemoteAnalysisReasons = ["not_configured", "provider_disabled_for_organization", "provider_config_unavailable", "security_engine_unavailable"] as const;

export const CapabilitiesResponseSchema = z.object({
  schema_version: z.literal(SCHEMA_VERSION),
  supported_schema_versions: z.array(z.string()).min(1),
  remote_analysis: z.object({ available: z.boolean(), reason: z.enum(RemoteAnalysisReasons).nullable() }).strict(),
  consent: z.object({ accepted_versions: z.array(z.string()), max_age_days: z.number().int() }).strict(),
  limits: z.object({
    max_request_bytes: z.number().int(), max_observations: z.number().int(), max_local_findings: z.number().int(),
    max_evidence_ids_per_finding: z.number().int(), observation_max_age_hours: z.number().int(), clock_skew_seconds: z.number().int(),
    explain_requests_per_minute: z.number().int(), request_timeout_ms: z.number().int(),
  }).strict(),
  locales: z.array(z.enum(LOCALES)),
  diagnostic_types: z.array(z.object({
    id: z.enum(DIAGNOSTIC_TYPES),
    metrics: z.array(z.object({ id: z.string(), unit: z.enum(UNITS), min: z.number(), max: z.number(), integer: z.boolean() }).strict()),
    local_finding_codes: z.array(z.string()),
    action_ids: z.array(z.enum(ACTION_IDS)),
  }).strict()),
  limitation_codes: z.array(z.enum(LIMITATION_CODES)),
  disclaimer_codes: z.array(z.enum(DISCLAIMER_CODES)),
  error_codes: z.array(z.enum(ERROR_CODES)),
}).strict();
export type CapabilitiesResponse = z.infer<typeof CapabilitiesResponseSchema>;
