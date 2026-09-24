import { randomUUID } from "node:crypto";
import type { TenantDb } from "../db/tenantDb.js";
import type { RoleName } from "../security/rbac.js";

export interface LoginRecord { id: string; organizationId: string; passwordHash: string; role: RoleName; disabled: boolean }
export interface RefreshRecord {
  id: string; organizationId: string; userId: string; familyId: string; expiresAt: Date; revoked: boolean; role: RoleName; userDisabled: boolean;
}

export interface AuthRepository {
  /** Creates organization + OWNER atomically. Returns null if the slug or email already exists. */
  signup(name: string, slug: string, email: string, passwordHash: string): Promise<{ organizationId: string; userId: string } | null>;
  findLogin(email: string): Promise<LoginRecord | null>;
  createRefresh(orgId: string, userId: string, familyId: string | null, tokenHash: string, expiresAt: Date): Promise<{ id: string; familyId: string }>;
  findRefresh(tokenHash: string): Promise<RefreshRecord | null>;
  /** Atomically revokes `oldId` and inserts its successor. Returns false if `oldId` was already revoked (reuse / race). */
  rotate(orgId: string, old: RefreshRecord, newHash: string, expiresAt: Date): Promise<boolean>;
  revokeFamily(orgId: string, familyId: string): Promise<void>;
}

export class PgAuthRepository implements AuthRepository {
  constructor(private readonly db: TenantDb) {}

  async signup(name: string, slug: string, email: string, passwordHash: string) {
    try {
      const row = await this.db.withoutTenant(async (q) =>
        (await q.query<{ organization_id: string; user_id: string }>("SELECT * FROM app_signup_organization($1,$2,$3,$4)", [name, slug, email, passwordHash])).rows[0]!);
      return { organizationId: row.organization_id, userId: row.user_id };
    } catch (err) {
      if ((err as { code?: string }).code === "23505" || /duplicate key/i.test((err as Error).message)) return null;
      throw err;
    }
  }

  async findLogin(email: string): Promise<LoginRecord | null> {
    const r = await this.db.withoutTenant(async (q) =>
      (await q.query<{ id: string; organization_id: string; password_hash: string; role: RoleName; disabled_at: Date | null }>("SELECT * FROM app_find_login($1)", [email])).rows[0]);
    return r ? { id: r.id, organizationId: r.organization_id, passwordHash: r.password_hash, role: r.role, disabled: r.disabled_at !== null } : null;
  }

  createRefresh(orgId: string, userId: string, familyId: string | null, tokenHash: string, expiresAt: Date) {
    const family = familyId ?? randomUUID();
    return this.db.withTenant(orgId, async (q) => {
      const { rows } = await q.query<{ id: string }>(
        "INSERT INTO refresh_tokens (organization_id, user_id, family_id, token_hash, expires_at) VALUES ($1,$2,$3,$4,$5) RETURNING id",
        [orgId, userId, family, tokenHash, expiresAt]);
      return { id: rows[0]!.id, familyId: family };
    });
  }

  async findRefresh(tokenHash: string): Promise<RefreshRecord | null> {
    const r = await this.db.withoutTenant(async (q) => (await q.query<{
      id: string; organization_id: string; user_id: string; family_id: string; expires_at: Date; revoked_at: Date | null; role: RoleName; user_disabled_at: Date | null;
    }>("SELECT * FROM app_find_refresh_token($1)", [tokenHash])).rows[0]);
    return r ? { id: r.id, organizationId: r.organization_id, userId: r.user_id, familyId: r.family_id, expiresAt: new Date(r.expires_at),
      revoked: r.revoked_at !== null, role: r.role, userDisabled: r.user_disabled_at !== null } : null;
  }

  rotate(orgId: string, old: RefreshRecord, newHash: string, expiresAt: Date): Promise<boolean> {
    return this.db.withTenant(orgId, async (q) => {
      const claimed = await q.query("UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL RETURNING id", [old.id]);
      if (claimed.rows.length === 0) return false; // someone else already used this token
      const next = (await q.query<{ id: string }>(
        "INSERT INTO refresh_tokens (organization_id, user_id, family_id, token_hash, expires_at) VALUES ($1,$2,$3,$4,$5) RETURNING id",
        [orgId, old.userId, old.familyId, newHash, expiresAt])).rows[0]!;
      await q.query("UPDATE refresh_tokens SET replaced_by = $1 WHERE id = $2", [next.id, old.id]);
      return true;
    });
  }

  revokeFamily(orgId: string, familyId: string): Promise<void> {
    return this.db.withTenant(orgId, async (q) => {
      await q.query("UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL", [familyId]);
    });
  }
}
