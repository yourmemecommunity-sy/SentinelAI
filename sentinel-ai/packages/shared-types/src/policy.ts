import type { Action, Direction, EntityType, Severity } from "./security.js";

/** Wire format (snake_case). ALLOW is rejected for credentials, payment cards and threat entities. */
export interface RuleScope {
  users?: string[]; teams?: string[]; applications?: string[]; providers?: string[];
  models?: string[]; environments?: string[]; ip_cidrs?: string[];
  time_window_utc?: { start: string; end: string }; // HH:MM, UTC
  directions?: Direction[];
}

export interface PolicyRule {
  entity: EntityType;
  action: Action;
  severity?: Severity;
  min_confidence?: number;
  scope?: RuleScope;
}

export interface Policy {
  policy_id: string;
  organization_id?: string;
  version?: number;
  rules: PolicyRule[];
  /** Organization switch: false -> the external LLM judge is never called (set by the gateway, not by policy authors). */
  external_judge?: boolean;
}
