/**
 * Wire contracts shared with the Python security engine (snake_case JSON on the wire).
 * Source of truth: services/security-engine/app/models and docs/api/openapi.yaml.
 */
export const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export const ACTIONS = ["ALLOW", "HASH", "MASK", "TOKENIZE", "REDACT", "QUARANTINE", "BLOCK"] as const;
export const DIRECTIONS = ["INPUT", "OUTPUT"] as const;
export const ENTITY_TYPES = [
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
}
