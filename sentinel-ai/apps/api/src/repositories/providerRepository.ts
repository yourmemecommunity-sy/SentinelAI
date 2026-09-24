import type { TenantDb } from "../db/tenantDb.js";

/** Stored per-organization provider settings. `sealed` is ciphertext; it never leaves the server in any response. */
export interface ProviderRow {
  provider: string;
  enabled: boolean;
  sealed: { keyId: string; blob: Buffer } | null;
  hint: string | null;
  updatedAt: string;
}

export interface ProviderRepository {
  list(orgId: string): Promise<ProviderRow[]>;
  /** Creates the row if missing. */
  setCredential(orgId: string, provider: string, sealed: { keyId: string; blob: Buffer }, hint: string, userId: string): Promise<void>;
  /** Returns false when there was no stored credential. */
  clearCredential(orgId: string, provider: string, userId: string): Promise<boolean>;
  setEnabled(orgId: string, provider: string, enabled: boolean, userId: string): Promise<void>;
}

type Row = { provider_type: string; enabled: boolean; credentials_encrypted: Buffer | Uint8Array | null; credential_key_id: string | null; credential_hint: string | null; updated_at: Date };

export class PgProviderRepository implements ProviderRepository {
  constructor(private readonly db: TenantDb) {}

  list(orgId: string): Promise<ProviderRow[]> {
    return this.db.withTenant(orgId, async (q) => (await q.query<Row>(
      "SELECT provider_type, enabled, credentials_encrypted, credential_key_id, credential_hint, updated_at FROM providers ORDER BY provider_type")).rows
      .map((r) => ({
        provider: r.provider_type, enabled: r.enabled, hint: r.credential_hint, updatedAt: new Date(r.updated_at).toISOString(),
        sealed: r.credentials_encrypted && r.credential_key_id ? { keyId: r.credential_key_id, blob: Buffer.from(r.credentials_encrypted) } : null,
      })));
  }

  async setCredential(orgId: string, provider: string, sealed: { keyId: string; blob: Buffer }, hint: string, userId: string): Promise<void> {
    await this.db.withTenant(orgId, (q) => q.query(
      `INSERT INTO providers (organization_id, provider_type, credentials_encrypted, credential_key_id, credential_hint, enabled, updated_by, updated_at)
       VALUES ($1, $2, $3, $4, $5, true, $6, now())
       ON CONFLICT (organization_id, provider_type) DO UPDATE SET credentials_encrypted = EXCLUDED.credentials_encrypted,
         credential_key_id = EXCLUDED.credential_key_id, credential_hint = EXCLUDED.credential_hint, updated_by = EXCLUDED.updated_by, updated_at = now()`,
      [orgId, provider, sealed.blob, sealed.keyId, hint, userId]));
  }

  clearCredential(orgId: string, provider: string, userId: string): Promise<boolean> {
    return this.db.withTenant(orgId, async (q) => (await q.query(
      `UPDATE providers SET credentials_encrypted = NULL, credential_key_id = NULL, credential_hint = NULL, updated_by = $2, updated_at = now()
       WHERE provider_type = $1 AND credentials_encrypted IS NOT NULL RETURNING id`, [provider, userId])).rows.length > 0);
  }

  async setEnabled(orgId: string, provider: string, enabled: boolean, userId: string): Promise<void> {
    await this.db.withTenant(orgId, (q) => q.query(
      `INSERT INTO providers (organization_id, provider_type, enabled, updated_by, updated_at) VALUES ($1, $2, $3, $4, now())
       ON CONFLICT (organization_id, provider_type) DO UPDATE SET enabled = EXCLUDED.enabled, updated_by = EXCLUDED.updated_by, updated_at = now()`,
      [orgId, provider, enabled, userId]));
  }
}
