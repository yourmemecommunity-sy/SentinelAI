import type { TenantDb } from "../db/tenantDb.js";

export interface AuditLogEntry {
  organizationId: string;
  actorId: string | null;
  actorType: "user" | "api_key" | "system";
  action: string;
  target: string | null;
  /** Structural metadata only (versions, counts, ids) - never content or secrets. */
  metadata: Record<string, string | number | boolean | null>;
}

export interface AuditLogWriter { record(entry: AuditLogEntry): Promise<void> }

export class PgAuditLogWriter implements AuditLogWriter {
  constructor(private readonly db: TenantDb) {}
  record(e: AuditLogEntry): Promise<void> {
    return this.db.withTenant(e.organizationId, async (q) => {
      await q.query("INSERT INTO audit_logs (organization_id, actor_id, actor_type, action, target, metadata) VALUES ($1,$2,$3,$4,$5,$6)",
        [e.organizationId, e.actorId, e.actorType, e.action, e.target, JSON.stringify(e.metadata)]);
    });
  }
}

export class InMemoryAuditLog implements AuditLogWriter {
  readonly entries: AuditLogEntry[] = [];
  async record(e: AuditLogEntry): Promise<void> { this.entries.push(e); }
}
