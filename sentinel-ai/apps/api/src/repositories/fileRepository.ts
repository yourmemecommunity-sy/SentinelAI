import type { TenantDb } from "../db/tenantDb.js";

export type FileVerdict = "CLEAN" | "SANITIZED" | "BLOCKED" | "ERROR";

export interface FileScanRecord {
  sha256: string;
  mime: string | null;
  sizeBytes: number;
  verdict: FileVerdict;
  /** Finding TYPES and severities only (never details, names or content). */
  findings: { type: string; severity: string }[];
}

export interface FileRepository {
  /** Persists file METADATA (hash, type, size, verdict). Never content, and nothing at all for zero-retention organizations. */
  record(orgId: string, rec: FileScanRecord): Promise<void>;
}

export class PgFileRepository implements FileRepository {
  constructor(private readonly db: TenantDb) {}

  record(orgId: string, r: FileScanRecord): Promise<void> {
    return this.db.withTenant(orgId, async (q) => {
      const org = await q.query<{ zero_retention: boolean }>("SELECT zero_retention FROM organizations");
      if (org.rows[0]?.zero_retention !== false) return;
      const file = (await q.query<{ id: string }>(
        "INSERT INTO files (organization_id, sha256, mime, size_bytes, storage_key) VALUES ($1,$2,$3,$4,NULL) RETURNING id",
        [orgId, r.sha256, r.mime ?? "application/octet-stream", r.sizeBytes])).rows[0]!;
      await q.query("INSERT INTO file_scans (organization_id, file_id, verdict, findings_meta) VALUES ($1,$2,$3,$4)",
        [orgId, file.id, r.verdict, JSON.stringify(r.findings)]);
    });
  }
}

export class InMemoryFileRepository implements FileRepository {
  readonly records: (FileScanRecord & { orgId: string })[] = [];
  fail = false;
  async record(orgId: string, rec: FileScanRecord): Promise<void> {
    if (this.fail) throw new Error("db down");
    this.records.push({ ...rec, orgId });
  }
}
