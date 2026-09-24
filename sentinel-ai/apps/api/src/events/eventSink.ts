import type { Action, Direction, EntityType, RiskLevel, ScanResult } from "@sentinelai/shared-types";
import type { TenantDb } from "../db/tenantDb.js";

export type EventType = "scan" | "ai_request" | "ai_response" | "fail_closed" | "file_scan";

/** Audit-safe security event. By construction it has no field that can hold prompt/response text or a secret. */
export interface SecurityEventInput {
  organizationId: string;
  userId: string | null;
  apiKeyId: string | null;
  requestId: string;
  application: string | null;
  provider: string | null;
  model: string | null;
  direction: Direction;
  eventType: EventType;
  riskLevel: RiskLevel;
  riskScore: number;
  action: Action;
  entityTypes: EntityType[];
  policyId: string;
  failedClosed: boolean;
  failClosedReason: string | null;
  detectorVersion: string;
  latencyMs: number;
  /** Optional per-detection metadata (entity, severity, confidence, location, digest). Skipped in zero-retention orgs. */
  scan?: ScanResult;
}

export interface StoredEvent extends Omit<SecurityEventInput, "scan"> { id: string; timestamp: string }

/** Wire format for events: snake_case like every other API response (see docs/api/openapi.yaml). */
export function eventToWire(e: StoredEvent) {
  return {
    id: e.id, request_id: e.requestId, user_id: e.userId, api_key_id: e.apiKeyId, application: e.application, provider: e.provider,
    model: e.model, direction: e.direction, event_type: e.eventType, risk_level: e.riskLevel, risk_score: e.riskScore, action: e.action,
    entity_types: e.entityTypes, policy_id: e.policyId, failed_closed: e.failedClosed, fail_closed_reason: e.failClosedReason,
    detector_version: e.detectorVersion, latency_ms: e.latencyMs, timestamp: e.timestamp,
  };
}

export interface EventFilter { riskLevel?: RiskLevel; action?: Action; eventType?: EventType; limit: number; before?: string }

export interface EventSink {
  /** Must throw on failure: callers treat an unwritable audit trail as a fail-closed condition. */
  record(event: SecurityEventInput): Promise<string>;
  list(orgId: string, filter: EventFilter): Promise<StoredEvent[]>;
  get(orgId: string, id: string): Promise<StoredEvent | null>;
  usage(orgId: string, days: number): Promise<{ day: string; provider: string; requests: number; blocked: number; sanitized: number }[]>;
}

export function eventFromScan(
  base: Pick<SecurityEventInput, "organizationId" | "userId" | "apiKeyId" | "application" | "provider" | "model" | "direction" | "eventType">,
  scan: ScanResult,
): SecurityEventInput {
  return {
    ...base,
    requestId: scan.request_id,
    riskLevel: scan.risk.risk_level,
    riskScore: scan.risk.risk_score,
    action: scan.decision,
    entityTypes: [...new Set(scan.detections.map((d) => d.entity))].sort() as EntityType[],
    policyId: scan.policy_id,
    failedClosed: scan.failed_closed,
    failClosedReason: scan.fail_closed_reason ?? null,
    detectorVersion: scan.detector_version,
    latencyMs: scan.latency_ms,
    scan,
  };
}

const COLUMNS = `id, organization_id, user_id, api_key_id, request_id, application, provider, model, direction, event_type,
  risk_level, risk_score, action, entity_types, policy_id, failed_closed, fail_closed_reason, detector_version, latency_ms, "timestamp"`;

type Row = Record<string, unknown>;
const toStored = (r: Row): StoredEvent => ({
  id: r.id as string, organizationId: r.organization_id as string, userId: (r.user_id as string) ?? null,
  apiKeyId: (r.api_key_id as string) ?? null, requestId: r.request_id as string, application: (r.application as string) ?? null,
  provider: (r.provider as string) ?? null, model: (r.model as string) ?? null, direction: r.direction as Direction,
  eventType: r.event_type as EventType, riskLevel: r.risk_level as RiskLevel, riskScore: r.risk_score as number,
  action: r.action as Action, entityTypes: r.entity_types as EntityType[], policyId: r.policy_id as string,
  failedClosed: r.failed_closed as boolean, failClosedReason: (r.fail_closed_reason as string) ?? null,
  detectorVersion: r.detector_version as string, latencyMs: Number(r.latency_ms ?? 0),
  timestamp: new Date(r.timestamp as string).toISOString(),
});

export class PgEventSink implements EventSink {
  constructor(private readonly db: TenantDb) {}

  record(e: SecurityEventInput): Promise<string> {
    return this.db.withTenant(e.organizationId, async (q) => {
      const { rows } = await q.query<{ id: string }>(
        `INSERT INTO security_events (organization_id, user_id, api_key_id, request_id, application, provider, model, direction,
           event_type, risk_level, risk_score, action, entity_types, policy_id, failed_closed, fail_closed_reason, detector_version, latency_ms)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING id`,
        [e.organizationId, e.userId, e.apiKeyId, e.requestId, e.application, e.provider, e.model, e.direction, e.eventType,
          e.riskLevel, e.riskScore, e.action, e.entityTypes, e.policyId, e.failedClosed, e.failClosedReason, e.detectorVersion, e.latencyMs]);
      const id = rows[0]!.id;

      // Zero-retention orgs keep only the metadata row above: no per-detection offsets or digests.
      const org = await q.query<{ zero_retention: boolean }>("SELECT zero_retention FROM organizations");
      if (e.scan && org.rows[0]?.zero_retention === false) {
        const meta = e.scan.detections.map((d) => ({ entity: d.entity, severity: d.severity, confidence: d.confidence,
          location: d.location, detector: d.detector, digest: d.value_digest ?? null }));
        await q.query("INSERT INTO scan_results (organization_id, event_id, detections_meta, risk_factors) VALUES ($1,$2,$3,$4)",
          [e.organizationId, id, JSON.stringify(meta), JSON.stringify(e.scan.risk.factors)]);
      }

      if (e.provider) {
        const withheld = e.action === "BLOCK" || e.action === "QUARANTINE";
        const sanitized = !withheld && e.action !== "ALLOW";
        await q.query(
          `INSERT INTO usage (organization_id, day, provider, requests, blocked, sanitized)
           VALUES ($1, current_date, $2, 1, $3, $4)
           ON CONFLICT (organization_id, day, provider) DO UPDATE
             SET requests = usage.requests + 1, blocked = usage.blocked + $3, sanitized = usage.sanitized + $4`,
          [e.organizationId, e.provider, withheld ? 1 : 0, sanitized ? 1 : 0]);
      }
      return id;
    });
  }

  list(orgId: string, f: EventFilter): Promise<StoredEvent[]> {
    return this.db.withTenant(orgId, async (q) => {
      const where: string[] = []; const params: unknown[] = [];
      const add = (cond: string, v: unknown) => { params.push(v); where.push(cond.replace("?", `$${params.length}`)); };
      if (f.riskLevel) add("risk_level = ?", f.riskLevel);
      if (f.action) add("action = ?", f.action);
      if (f.eventType) add("event_type = ?", f.eventType);
      if (f.before) add(`"timestamp" < ?`, f.before);
      params.push(Math.min(Math.max(f.limit, 1), 200));
      const { rows } = await q.query<Row>(
        `SELECT ${COLUMNS} FROM security_events ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
         ORDER BY "timestamp" DESC, id LIMIT $${params.length}`, params);
      return rows.map(toStored);
    });
  }

  get(orgId: string, id: string): Promise<StoredEvent | null> {
    return this.db.withTenant(orgId, async (q) => {
      const { rows } = await q.query<Row>(`SELECT ${COLUMNS} FROM security_events WHERE id = $1`, [id]);
      return rows[0] ? toStored(rows[0]) : null;
    });
  }

  usage(orgId: string, days: number) {
    return this.db.withTenant(orgId, async (q) => {
      const { rows } = await q.query<{ day: string; provider: string; requests: string; blocked: string; sanitized: string }>(
        `SELECT day::text AS day, provider, requests, blocked, sanitized FROM usage
         WHERE day >= current_date - $1::int ORDER BY day DESC, provider`, [Math.min(Math.max(days, 1), 366)]);
      return rows.map((r) => ({ day: r.day, provider: r.provider, requests: Number(r.requests), blocked: Number(r.blocked), sanitized: Number(r.sanitized) }));
    });
  }
}

/** Test/dev sink. Not for production: nothing is persisted. */
export class InMemoryEventSink implements EventSink {
  readonly events: StoredEvent[] = [];
  failNext = false;
  async record(e: SecurityEventInput): Promise<string> {
    if (this.failNext) { this.failNext = false; throw new Error("audit store unavailable"); }
    const { scan: _scan, ...rest } = e;
    const id = crypto.randomUUID();
    this.events.unshift({ ...rest, id, timestamp: new Date().toISOString() });
    return id;
  }
  async list(orgId: string, f: EventFilter) {
    // Same filters as the SQL sink, so tests of filtering are meaningful.
    return this.events
      .filter((e) => e.organizationId === orgId && (!f.riskLevel || e.riskLevel === f.riskLevel) && (!f.action || e.action === f.action) && (!f.eventType || e.eventType === f.eventType))
      .slice(0, f.limit);
  }
  async get(orgId: string, id: string) { return this.events.find((e) => e.organizationId === orgId && e.id === id) ?? null; }
  async usage() { return []; }
}
