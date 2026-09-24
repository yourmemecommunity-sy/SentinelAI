import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { TenantDb } from "../db/tenantDb.js";
import { ROLES, type Principal, type RoleName } from "./rbac.js";

const KEY_FORMAT = /^snl_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{43}$/;
const PREFIX_LEN = 12; // "snl_" + 8 chars

export function hashApiKey(key: string, pepper: string): string {
  return createHmac("sha256", pepper).update(key).digest("hex");
}

export interface CreatedApiKey { id: string; key: string; prefix: string }

/** Creates a key. The plaintext is returned exactly once and never stored; only HMAC(pepper, key) is persisted. */
export async function createApiKey(
  db: TenantDb, pepper: string, opts: { organizationId: string; name: string; role: RoleName; createdBy?: string | null; expiresAt?: Date | null },
): Promise<CreatedApiKey> {
  const id8 = randomBytes(6).toString("base64url").slice(0, 8);
  const key = `snl_${id8}_${randomBytes(32).toString("base64url")}`;
  const prefix = key.slice(0, PREFIX_LEN);
  const row = await db.withTenant(opts.organizationId, async (q) => (await q.query<{ id: string }>(
    `INSERT INTO api_keys (organization_id, name, prefix, key_hash, role_id, created_by, expires_at)
     VALUES ($1,$2,$3,$4,(SELECT id FROM roles WHERE name = $5),$6,$7) RETURNING id`,
    [opts.organizationId, opts.name, prefix, hashApiKey(key, pepper), opts.role, opts.createdBy ?? null, opts.expiresAt ?? null])).rows[0]!);
  return { id: row.id, key, prefix };
}

export interface ApiKeyAuthenticator { authenticate(rawKey: string | undefined): Promise<Principal | null> }

export class DbApiKeyAuthenticator implements ApiKeyAuthenticator {
  constructor(private readonly db: TenantDb, private readonly pepper: string, private readonly now: () => Date = () => new Date()) {}

  /** Returns null for every failure mode (unknown, malformed, revoked, expired, wrong secret) so callers cannot distinguish them. */
  async authenticate(rawKey: string | undefined): Promise<Principal | null> {
    if (!rawKey || !KEY_FORMAT.test(rawKey)) return null;
    const presented = createHmac("sha256", this.pepper).update(rawKey).digest();
    const row = await this.db.withoutTenant(async (q) => (await q.query<{
      id: string; organization_id: string; key_hash: string; role: string; expires_at: Date | null; revoked_at: Date | null; last_used_at: Date | null;
    }>("SELECT * FROM app_find_api_key($1)", [rawKey.slice(0, PREFIX_LEN)])).rows[0]);

    // Compare against a dummy when the prefix is unknown so timing does not reveal prefix existence.
    const stored = Buffer.from(row?.key_hash ?? "0".repeat(64), "hex");
    const equal = stored.length === presented.length && timingSafeEqual(stored, presented);
    if (!row || !equal) return null;
    if (row.revoked_at) return null;
    if (row.expires_at && new Date(row.expires_at) <= this.now()) return null;
    if (!(ROLES as readonly string[]).includes(row.role)) return null;
    // Best-effort, at most hourly: keeps `last_used_at` useful for spotting stale keys without a write per request.
    const stale = !row.last_used_at || this.now().getTime() - new Date(row.last_used_at).getTime() > 3_600_000;
    if (stale) {
      void this.db.withTenant(row.organization_id, (q) => q.query("UPDATE api_keys SET last_used_at = now() WHERE id = $1", [row.id])).catch(() => undefined);
    }
    return { organizationId: row.organization_id, role: row.role as RoleName, apiKeyId: row.id, userId: null };
  }
}
