import type { Action, EntityType, RiskLevel, Severity } from "@sentinelai/shared-types";

/** Events as returned by GET /v1/events (snake_case; contains no prompt/response content by design). */
export interface SecurityEvent {
  id: string; request_id: string; user_id: string | null; api_key_id: string | null;
  application: string | null; provider: string | null; model: string | null;
  direction: "INPUT" | "OUTPUT"; event_type: "scan" | "ai_request" | "ai_response" | "fail_closed" | "file_scan";
  risk_level: RiskLevel; risk_score: number; action: Action; entity_types: EntityType[];
  policy_id: string; failed_closed: boolean; fail_closed_reason: string | null;
  detector_version: string; latency_ms: number; timestamp: string;
  /** Why the decision was made (no content). Null for events recorded before 2026-10. */
  explanation?: Explanation | null;
}
export interface EventsPage { events: SecurityEvent[]; next_before: string | null }

export interface UsageRow { day: string; provider: string; requests: number; blocked: number; sanitized: number }

export interface PolicySummary { policy_id: string; version: number; active: boolean; rule_count: number; created_at: string }
export interface PolicyRuleDto { entity: EntityType; action: Action; severity?: Severity; min_confidence?: number }
export interface PolicyDetail { policy_id: string; version: number; active: boolean; rules: PolicyRuleDto[] }

export interface Me { user_id: string | null; api_key_id: string | null; organization_id: string; role: string }

export interface ScanResponse {
  request_id: string; event_id: string | null; decision: Action; failed_closed: boolean; fail_closed_reason: string | null;
  risk: { risk_score: number; risk_level: RiskLevel; decision: Action; factors: { name: string; contribution: number; detail: string }[] };
  detections: { entity: EntityType; confidence: number; severity: Severity; location: { start: number; end: number }; detector: string }[];
  sanitized_text: string | null; policy_id: string;
}

export interface FileScanResponse {
  event_id: string | null; decision: Action; blocked: boolean; failed_closed: boolean; reason: string | null;
  file: { sha256: string; size: number; detected_type: string | null; mime: string | null; pages: number | null; ocr_used: boolean };
  findings: { type: string; severity: string; detail: string }[];
  risk: { risk_score: number; risk_level: RiskLevel; decision: Action; factors: { name: string; contribution: number; detail: string }[] };
  detections: ScanResponse["detections"];
  sanitized_text: string | null; policy_id: string;
}

export interface ApiKeyInfo {
  id: string; name: string; prefix: string;
  role: "OWNER" | "ADMIN" | "SECURITY_ANALYST" | "DEVELOPER" | "VIEWER";
  created_at: string; expires_at: string | null; revoked_at: string | null; last_used_at: string | null; created_by: string | null;
}

export type RoleName = ApiKeyInfo["role"];
export interface UserInfo { id: string; email: string; role: RoleName; disabled: boolean; created_at: string; teams: string[] }
export interface InvitationInfo { id: string; email: string; role: RoleName; status: "pending" | "accepted" | "revoked" | "expired"; expires_at: string; created_at: string; created_by: string }
export interface TeamInfo { id: string; name: string; members: string[] }
export interface ProviderSetting {
  provider: string; enabled: boolean; source: "organization" | "platform" | "disabled" | "none";
  organization_credential: { hint: string | null; key_id: string; updated_at: string } | null; accepts_organization_credential: boolean;
}

/** Mirrors the engine's explanation (services/security-engine/app/models/explanation.py). Holds no content. */
export interface Explanation {
  decided_by: "rules" | "classifier" | "judge" | "fail_closed";
  tier: number;
  detectors_fired: { detector: string; entity: EntityType; count: number; max_confidence: number; tier: number }[];
  classifier?: { model: string; score: number; threshold: number; band_low: number | null; band_high: number | null; band: "attack" | "uncertain" | "benign";
    windows_scored?: number; windows_total?: number } | null;
  judge?: { called: boolean; cached: boolean; skipped_reason: string | null; verdict: "attack" | "benign" | null; category: string | null;
    confidence: number | null; reason?: string | null; model: string | null; prompt_version: string | null; latency_ms: number | null } | null;
  policy: { policy_id: string; policy_version: number; deciding_entity: EntityType | null; deciding_action: Action;
    source: "policy_rule" | "baseline" | "risk_escalation" | "no_detection" | "fail_closed" };
  versions: Record<string, string>;
  content_hmac: string;
}

export interface ReplayResponse {
  event_id: string; content_matches: boolean; identical: boolean; recorded_decision: Action; replayed_decision: Action | null;
  recorded_decided_by: string; replayed_decided_by: string | null; differences: string[];
  versions: { name: string; recorded: string | null; current: string | null; same: boolean }[]; versions_identical: boolean; judge_source: string;
}

export interface RedTeamRound {
  round: number; dataset_version: string; generator_model: string; engine_version: string; attacks: number; blocked: number; slipped: number;
  per_category: Record<string, { attacks: number; blocked: number; slipped: number; by_tier?: Record<string, number> }>;
  examples: { category: string; outcome: "blocked" | "slipped"; decided_by: string; text: string }[];
  cost_usd: number; ran_at?: string;
}
