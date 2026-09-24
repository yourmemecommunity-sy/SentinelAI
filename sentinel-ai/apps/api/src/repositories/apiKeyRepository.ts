import type { TenantDb } from "../db/tenantDb.js";
import { createApiKey } from "../security/apiKeys.js";
import type { RoleName } from "../security/rbac.js";

export interface ApiKeyInfo {
  id: string; name: string; prefix: string; role: RoleName;
  created_at: string; expires_at: string | null; revoked_at: string | null; last_used_at: string | null; created_by: string | null;
}

export const MAX_ACTIVE_KEYS = 100;

export interface ApiKeyRepository {
  /** Returns null when the organization already has the maximum number of active keys. */
  create(orgId: string, name: string, role: RoleName, createdBy: string | null, expiresAt: Date): Promise<{ info: ApiKeyInfo; key: string } | null>;
  list(orgId: string): Promise<ApiKeyInfo[]>;
  get(orgId: string, id: string): Promise<ApiKeyInfo | null>;
  /** Idempotent. Returns false when no such key exists in this organization. */
  revoke(orgId: string, id: string): Promise<boolean>;
}

type Row = { id: string; name: string; prefix: string; role: RoleName; created_at: Date; expires_at: Date | null; revoked_at: Date | null; last_used_at: Date | null; created_by: string | null };
const iso = (d: Date | null) => (d ? new Date(d).toISOString() : null);
const toInfo = (r: Row): ApiKeyInfo => ({
  id: r.id, name: r.name, prefix: r.prefix, role: r.role, created_at: new Date(r.created_at).toISOString(),
  expires_at: iso(r.expires_at), revoked_at: iso(r.revoked_at), last_used_at: iso(r.last_used_at), created_by: r.created_by,
});
const SELECT = `SELECT k.id, k.name, k.prefix, r.name AS role, k.created_at, k.expires_at, k.revoked_at, k.last_used_at, k.created_by
                FROM api_keys k JOIN roles r ON r.id = k.role_id`;

/** Never selects `key_hash`: the hash is not needed by any management path and must not be exposable by accident. */
export class PgApiKeyRepository implements ApiKeyRepository {
  constructor(private readonly db: TenantDb, private readonly pepper: string) {}

  async create(orgId: string, name: string, role: RoleName, createdBy: string | null, expiresAt: Date) {
    const active = await this.db.withTenant(orgId, async (q) =>
      Number((await q.query<{ n: string }>("SELECT count(*) AS n FROM api_keys WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())")).rows[0]!.n));
    if (active >= MAX_ACTIVE_KEYS) return null;
    const created = await createApiKey(this.db, this.pepper, { organizationId: orgId, name, role, createdBy, expiresAt });
    const info = await this.get(orgId, created.id);
    return { info: info!, key: created.key };
  }

  list(orgId: string): Promise<ApiKeyInfo[]> {
    return this.db.withTenant(orgId, async (q) => (await q.query<Row>(`${SELECT} ORDER BY k.created_at DESC`)).rows.map(toInfo));
  }

  get(orgId: string, id: string): Promise<ApiKeyInfo | null> {
    return this.db.withTenant(orgId, async (q) => {
      const r = (await q.query<Row>(`${SELECT} WHERE k.id = $1`, [id])).rows[0];
      return r ? toInfo(r) : null;
    });
  }

  revoke(orgId: string, id: string): Promise<boolean> {
    return this.db.withTenant(orgId, async (q) => {
      const exists = (await q.query("SELECT 1 FROM api_keys WHERE id = $1", [id])).rows.length > 0;
      await q.query("UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL", [id]);
      return exists;
    });
  }
}
