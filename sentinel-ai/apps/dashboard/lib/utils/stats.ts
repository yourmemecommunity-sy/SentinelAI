import type { EntityType } from "@sentinelai/shared-types";
import type { SecurityEvent, UsageRow } from "@/types/api";

export const PII_ENTITIES: ReadonlySet<EntityType> = new Set<EntityType>([
  "EMAIL", "PHONE", "ADDRESS", "DATE_OF_BIRTH", "PAN", "AADHAAR", "PASSPORT", "SSN", "DRIVER_LICENSE",
  "CREDIT_CARD", "BANK_ACCOUNT", "UPI", "IFSC",
]);
export const SECRET_ENTITIES: ReadonlySet<EntityType> = new Set<EntityType>([
  "API_KEY", "AWS_CREDENTIAL", "GOOGLE_CREDENTIAL", "GITHUB_TOKEN", "JWT", "OAUTH_TOKEN", "PASSWORD", "PRIVATE_KEY",
  "CONNECTION_STRING", "HIGH_ENTROPY_SECRET",
]);
export const THREAT_ENTITIES: ReadonlySet<EntityType> = new Set<EntityType>([
  "PROMPT_INJECTION", "SYSTEM_PROMPT_EXTRACTION", "JAILBREAK", "DATA_EXFILTRATION",
]);

const WITHHELD = new Set(["BLOCK", "QUARANTINE"]);
const SANITIZED = new Set(["MASK", "REDACT", "TOKENIZE", "HASH"]);

export interface OverviewStats {
  totalRequests: number; blocked: number; masked: number; critical: number; high: number;
  pii: number; secrets: number; promptInjection: number; failedClosed: number;
  providers: { provider: string; requests: number }[];
}

/**
 * Counts input-stage decisions (one per request) from a window of recent events. Output-stage events are excluded from
 * "requests" so a chat is not counted twice, but still contribute to the threat/leak counters.
 */
export function computeStats(events: SecurityEvent[], usage: UsageRow[]): OverviewStats {
  const inputs = events.filter((e) => e.direction === "INPUT");
  const has = (e: SecurityEvent, set: ReadonlySet<EntityType>) => e.entity_types.some((t) => set.has(t));
  const byProvider = new Map<string, number>();
  for (const u of usage) byProvider.set(u.provider, (byProvider.get(u.provider) ?? 0) + u.requests);
  return {
    totalRequests: inputs.length,
    blocked: inputs.filter((e) => WITHHELD.has(e.action)).length,
    masked: inputs.filter((e) => SANITIZED.has(e.action)).length,
    critical: events.filter((e) => e.risk_level === "CRITICAL").length,
    high: events.filter((e) => e.risk_level === "HIGH").length,
    pii: events.filter((e) => has(e, PII_ENTITIES)).length,
    secrets: events.filter((e) => has(e, SECRET_ENTITIES)).length,
    promptInjection: events.filter((e) => has(e, THREAT_ENTITIES)).length,
    failedClosed: events.filter((e) => e.failed_closed).length,
    providers: [...byProvider].map(([provider, requests]) => ({ provider, requests })).sort((a, b) => b.requests - a.requests),
  };
}

export function isThreat(e: SecurityEvent): boolean {
  return e.risk_level === "HIGH" || e.risk_level === "CRITICAL" || e.failed_closed || e.entity_types.some((t) => THREAT_ENTITIES.has(t) || SECRET_ENTITIES.has(t));
}

export function entityBreakdown(events: SecurityEvent[]): { entity: EntityType; count: number }[] {
  const m = new Map<EntityType, number>();
  for (const e of events) for (const t of e.entity_types) m.set(t, (m.get(t) ?? 0) + 1);
  return [...m].map(([entity, count]) => ({ entity, count })).sort((a, b) => b.count - a.count);
}
