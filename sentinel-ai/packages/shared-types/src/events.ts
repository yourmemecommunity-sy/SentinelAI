import type { Action, Direction, EntityType, RiskLevel } from "./security.js";

/** Audit-safe security event. Contains no raw content by design. */
export interface SecurityEvent {
  eventId: string;
  organizationId: string;
  userId: string | null;
  application: string | null;
  provider: string | null;
  model: string | null;
  timestamp: string; // ISO-8601
  direction: Direction;
  riskLevel: RiskLevel;
  entityTypes: EntityType[];
  policyId: string;
  action: Action;
  failedClosed: boolean;
  detectorVersion: string;
}
