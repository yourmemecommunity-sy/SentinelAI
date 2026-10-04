/**
 * Wire contracts shared with the Python security engine (snake_case JSON on the wire).
 * Source of truth: services/security-engine/app/models and docs/api/openapi.yaml.
 */
export const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export const ACTIONS = ["ALLOW", "HASH", "MASK", "TOKENIZE", "REDACT", "QUARANTINE", "BLOCK"] as const;
export const DIRECTIONS = ["INPUT", "OUTPUT"] as const;
export const ENTITY_TYPES = [
  "NAME", "LOCATION", // NER layer (person names; cities, regions, countries)
  "EMAIL", "PHONE", "ADDRESS", "DATE_OF_BIRTH", "PAN", "AADHAAR", "PASSPORT", "SSN", "DRIVER_LICENSE",
  "CREDIT_CARD", "BANK_ACCOUNT", "UPI", "IFSC",
  "API_KEY", "AWS_CREDENTIAL", "GOOGLE_CREDENTIAL", "GITHUB_TOKEN", "JWT", "OAUTH_TOKEN",
  "PASSWORD", "PRIVATE_KEY", "CONNECTION_STRING", "HIGH_ENTROPY_SECRET",
  "INTERNAL_URL", "CONFIDENTIAL_MARKER", "CUSTOM_CONFIDENTIAL",
  "PROMPT_INJECTION", "SYSTEM_PROMPT_EXTRACTION", "JAILBREAK", "DATA_EXFILTRATION",
] as const;
/** Entities policy may sanitize or block but never ALLOW (mirrors the engine and the DB CHECK constraint). */
export const NEVER_ALLOW_ENTITIES = [
  "PRIVATE_KEY", "AWS_CREDENTIAL", "GOOGLE_CREDENTIAL", "GITHUB_TOKEN", "JWT", "OAUTH_TOKEN", "PASSWORD",
  "CONNECTION_STRING", "API_KEY", "CREDIT_CARD",
  "PROMPT_INJECTION", "SYSTEM_PROMPT_EXTRACTION", "JAILBREAK", "DATA_EXFILTRATION",
] as const;

export type Severity = (typeof SEVERITIES)[number];
export type Action = (typeof ACTIONS)[number];
export type Direction = (typeof DIRECTIONS)[number];
export type RiskLevel = Severity;
export type EntityType = (typeof ENTITY_TYPES)[number];

/** Structured evidence. NEVER contains the matched value - only location and a keyed digest. */
export interface Detection {
  entity: EntityType;
  confidence: number; // 0..1
  severity: Severity;
  location: { start: number; end: number };
  detector: string;
  detector_version: string;
  value_digest?: string | null;
}

export interface RequestContext {
  user_id?: string; team?: string; application?: string; provider?: string;
  model?: string; environment?: string; ip?: string;
}

export interface ScanRequest {
  text: string;
  direction?: Direction;
  organization_id: string;
  context?: RequestContext;
  policy?: import("./policy.js").Policy;
  /** Token-vault session that TOKENIZE actions write to, so a reply can later be de-tokenized. Absent -> one-way per-request tokens. */
  vault_session?: string;
}

export interface RiskFactor { name: string; contribution: number; detail: string }
export interface Risk { risk_score: number; risk_level: RiskLevel; decision: Action; factors: RiskFactor[] }
export interface EntityAction { entity: EntityType; action: Action; count: number }

export interface ScanResult {
  request_id: string;
  decision: Action;
  failed_closed: boolean;
  fail_closed_reason?: string | null;
  detections: Detection[];
  entity_actions: EntityAction[];
  risk: Risk;
  /** null whenever the decision withholds content (BLOCK / QUARANTINE). Forward only this, never the original. */
  sanitized_text: string | null;
  policy_id: string;
  detector_version: string;
  latency_ms: number;
  explanation?: Explanation | null;
}

/**
 * Why a decision was made. Mirrors services/security-engine/app/models/explanation.py. Contains no content: only
 * detector names, scores, versions and a keyed HMAC of the scanned text (used to check a replay's input).
 */
export type DecidedBy = "rules" | "classifier" | "judge" | "fail_closed";
export interface Explanation {
  decided_by: DecidedBy;
  tier: number; // 1 rules + NER, 2 local classifier, 3 LLM judge
  detectors_fired: { detector: string; entity: EntityType; count: number; max_confidence: number; tier: number }[];
  classifier?: { model: string; score: number; threshold: number; band_low: number | null; band_high: number | null;
    band: "attack" | "uncertain" | "benign";
    /** windows_scored < windows_total: only the start and end of a long text were classified (tier 1 scans all of it). */
    windows_scored?: number; windows_total?: number } | null;
  judge?: { called: boolean; cached: boolean; skipped_reason: string | null; verdict: "attack" | "benign" | null;
    category: string | null; confidence: number | null;
    /** Model prose about the (masked) text: returned to the caller, NEVER stored. */
    reason?: string | null;
    model: string | null; prompt_version: string | null; latency_ms: number | null } | null;
  policy: { policy_id: string; policy_version: number; deciding_entity: EntityType | null; deciding_action: Action;
    source: "policy_rule" | "baseline" | "risk_escalation" | "no_detection" | "fail_closed" };
  versions: Record<string, string>;
  content_hmac: string;
}

/** Explanation without transient fields (the judge's free-text reason): the only form that may be persisted. */
export function storableExplanation(e: Explanation): Explanation {
  return e.judge ? { ...e, judge: { ...e.judge, reason: null } } : e;
}
