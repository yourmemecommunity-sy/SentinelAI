import { z, type ZodIssue } from "zod";
import {
  DIAGNOSTICS, DIAGNOSTIC_TYPES, FEEDBACK_RATINGS, FEEDBACK_REASON_CODES, LIMITS, LOCAL_FINDING_CODES, LOCALES, METRICS,
  METRIC_IDS, SCHEMA_VERSION, SEVERITIES, UNITS, type ErrorCode,
} from "./catalog.js";

/** Opaque client identifier (evidence, local finding). Never shown to a model: the server replaces it with an alias. */
export const ClientId = z.string().regex(/^[A-Za-z0-9_-]{1,40}$/, "must be 1-40 characters of A-Z, a-z, 0-9, _ or -");
/** RFC 3339 timestamp with an explicit offset (`Z` or `+05:30`). */
const Timestamp = z.string().datetime({ offset: true });

export const ObservationSchema = z.object({
  evidence_id: ClientId,
  metric: z.enum(METRIC_IDS),
  value: z.number().finite(),
  unit: z.enum(UNITS),
  observed_at: Timestamp,
}).strict();

export const LocalFindingSchema = z.object({
  finding_id: ClientId,
  code: z.enum(LOCAL_FINDING_CODES),
  severity: z.enum(SEVERITIES),
  evidence_ids: z.array(ClientId).min(1).max(LIMITS.maxEvidenceIdsPerFinding),
}).strict();

export const ConsentSchema = z.object({
  /** Must be literally true for any remote processing. */
  cloud_analysis: z.literal(true),
  /** Version (date) of the consent text the user accepted. */
  consent_version: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  granted_at: Timestamp,
}).strict();

export const ExplainRequestSchema = z.object({
  schema_version: z.literal(SCHEMA_VERSION),
  diagnostic_type: z.enum(DIAGNOSTIC_TYPES),
  locale: z.enum(LOCALES),
  consent: ConsentSchema,
  client: z.object({
    app_version: z.string().regex(/^\d{1,3}\.\d{1,3}\.\d{1,4}$/),
    android_api_level: z.number().int().min(26).max(40),
  }).strict(),
  observations: z.array(ObservationSchema).max(LIMITS.maxObservations),
  local_findings: z.array(LocalFindingSchema).max(LIMITS.maxLocalFindings),
}).strict();
export type ExplainRequest = z.infer<typeof ExplainRequestSchema>;
export type Observation = z.infer<typeof ObservationSchema>;
export type LocalFinding = z.infer<typeof LocalFindingSchema>;

export const FeedbackRequestSchema = z.object({
  schema_version: z.literal(SCHEMA_VERSION),
  request_id: z.string().uuid(),
  rating: z.enum(FEEDBACK_RATINGS),
  reason_code: z.enum(FEEDBACK_REASON_CODES).optional(),
  /** Feedback is stored; the user must agree to that separately from cloud analysis. */
  consent_to_store: z.literal(true),
}).strict();
export type FeedbackRequest = z.infer<typeof FeedbackRequestSchema>;

/** A validation problem. `message` is built from the schema only and never contains a value the client sent. */
export interface Issue { path: string; message: string }

export type Validated<T> =
  | { ok: true; value: T }
  | { ok: false; status: 403 | 422; error: ErrorCode; issues: Issue[] };

/** Zod's default messages can echo client input ("received 'x'", unknown key names); these never do. */
export function safeIssue(i: ZodIssue): Issue {
  const path = i.path.join(".");
  switch (i.code) {
    case "invalid_enum_value": return { path, message: `Invalid value. Expected one of: ${i.options.join(", ")}` };
    case "unrecognized_keys": return { path, message: `Unrecognized field(s): ${i.keys.length}` };
    case "invalid_literal": return { path, message: `Invalid literal value, expected ${JSON.stringify(i.expected)}` };
    case "invalid_type": return { path, message: `Expected ${i.expected}, received ${i.received}` };
    default: return { path, message: i.message };
  }
}

export interface ExplainValidationOptions {
  now: Date;
  /** Consent text versions the operator currently accepts. */
  acceptedConsentVersions: readonly string[];
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const fail = (status: 403 | 422, error: ErrorCode, issues: Issue[]) => ({ ok: false as const, status, error, issues });

/**
 * Full validation of an explanation request, in this order:
 *   1. schema version, 2. explicit cloud-analysis consent (checked before anything else is looked at, so a request without
 *   consent is refused even if it is otherwise malformed), 3. diagnostic type, 4. strict schema (unknown fields rejected),
 *   5. consent version and age, 6. per-observation metric/unit/bounds/timestamps, 7. evidence references.
 * Pure function: the caller supplies the clock.
 */
export function validateExplainRequest(raw: unknown, o: ExplainValidationOptions): Validated<ExplainRequest> {
  if (!isRecord(raw)) return fail(422, "invalid_request", [{ path: "", message: "Expected a JSON object" }]);
  if (raw.schema_version !== undefined && raw.schema_version !== SCHEMA_VERSION) {
    return fail(422, "unsupported_schema_version", [{ path: "schema_version", message: `Supported: ${SCHEMA_VERSION}` }]);
  }
  if (!isRecord(raw.consent) || raw.consent.cloud_analysis !== true) {
    return fail(403, "consent_required", [{ path: "consent.cloud_analysis", message: "Cloud analysis requires the user's explicit consent (true)" }]);
  }
  if (typeof raw.diagnostic_type === "string" && !(DIAGNOSTIC_TYPES as readonly string[]).includes(raw.diagnostic_type)) {
    return fail(422, "unsupported_diagnostic_type", [{ path: "diagnostic_type", message: `Expected one of: ${DIAGNOSTIC_TYPES.join(", ")}` }]);
  }
  const parsed = ExplainRequestSchema.safeParse(raw);
  if (!parsed.success) return fail(422, "invalid_request", parsed.error.issues.map(safeIssue));
  const req = parsed.data;
  const now = o.now.getTime();
  const skewMs = LIMITS.clockSkewSeconds * 1000;

  // ---- consent
  if (!o.acceptedConsentVersions.includes(req.consent.consent_version)) {
    return fail(403, "consent_outdated", [{ path: "consent.consent_version", message: `Accepted versions: ${o.acceptedConsentVersions.join(", ")}` }]);
  }
  const granted = Date.parse(req.consent.granted_at);
  if (granted > now + skewMs) return fail(422, "invalid_request", [{ path: "consent.granted_at", message: "Must not be in the future" }]);
  if (granted < now - LIMITS.consentMaxAgeDays * 86_400_000) {
    return fail(403, "consent_expired", [{ path: "consent.granted_at", message: `Consent older than ${LIMITS.consentMaxAgeDays} days must be renewed` }]);
  }

  // ---- observations
  if (req.observations.length === 0) {
    return fail(422, "insufficient_evidence", [{ path: "observations", message: "At least one observation is required" }]);
  }
  const spec = DIAGNOSTICS[req.diagnostic_type];
  const obsIssues: Issue[] = [];
  const evidence = new Set<string>();
  const dupEvidence: Issue[] = [];
  req.observations.forEach((ob, i) => {
    const at = `observations.${i}`;
    const m = METRICS[ob.metric];
    if (!spec.metrics.includes(ob.metric)) obsIssues.push({ path: `${at}.metric`, message: `Not accepted for diagnostic type ${req.diagnostic_type}` });
    if (ob.unit !== m.unit) obsIssues.push({ path: `${at}.unit`, message: `Metric ${ob.metric} must be reported in ${m.unit}` });
    if (ob.value < m.min || ob.value > m.max) obsIssues.push({ path: `${at}.value`, message: `Must be between ${m.min} and ${m.max}` });
    if (m.integer && !Number.isInteger(ob.value)) obsIssues.push({ path: `${at}.value`, message: "Must be a whole number" });
    const t = Date.parse(ob.observed_at);
    if (t > now + skewMs) obsIssues.push({ path: `${at}.observed_at`, message: "Must not be in the future" });
    if (t < now - LIMITS.observationMaxAgeHours * 3_600_000) obsIssues.push({ path: `${at}.observed_at`, message: `Older than ${LIMITS.observationMaxAgeHours} hours` });
    if (evidence.has(ob.evidence_id)) dupEvidence.push({ path: `${at}.evidence_id`, message: "Duplicate evidence id" });
    evidence.add(ob.evidence_id);
  });
  if (obsIssues.length) return fail(422, "invalid_observation", obsIssues);
  if (dupEvidence.length) return fail(422, "invalid_evidence_reference", dupEvidence);

  // ---- local findings and evidence references
  const findingIssues: Issue[] = [];
  const refIssues: Issue[] = [];
  const findingIds = new Set<string>();
  req.local_findings.forEach((f, i) => {
    const at = `local_findings.${i}`;
    if (!spec.localFindingCodes.includes(f.code)) findingIssues.push({ path: `${at}.code`, message: `Not accepted for diagnostic type ${req.diagnostic_type}` });
    if (findingIds.has(f.finding_id)) findingIssues.push({ path: `${at}.finding_id`, message: "Duplicate finding id" });
    findingIds.add(f.finding_id);
    if (new Set(f.evidence_ids).size !== f.evidence_ids.length) refIssues.push({ path: `${at}.evidence_ids`, message: "Duplicate evidence id" });
    f.evidence_ids.forEach((e, j) => {
      if (!evidence.has(e)) refIssues.push({ path: `${at}.evidence_ids.${j}`, message: "Does not refer to an observation in this request" });
    });
  });
  if (findingIssues.length) return fail(422, "invalid_local_finding", findingIssues);
  if (refIssues.length) return fail(422, "invalid_evidence_reference", refIssues);
  return { ok: true, value: req };
}

export function validateFeedbackRequest(raw: unknown): Validated<FeedbackRequest> {
  if (!isRecord(raw)) return fail(422, "invalid_request", [{ path: "", message: "Expected a JSON object" }]);
  if (raw.schema_version !== undefined && raw.schema_version !== SCHEMA_VERSION) {
    return fail(422, "unsupported_schema_version", [{ path: "schema_version", message: `Supported: ${SCHEMA_VERSION}` }]);
  }
  if (raw.consent_to_store !== true) {
    return fail(403, "consent_required", [{ path: "consent_to_store", message: "Storing feedback requires the user's explicit consent (true)" }]);
  }
  const parsed = FeedbackRequestSchema.safeParse(raw);
  return parsed.success ? { ok: true, value: parsed.data } : fail(422, "invalid_request", parsed.error.issues.map(safeIssue));
}
