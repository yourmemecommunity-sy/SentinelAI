import pg from "pg";

export interface Queryable {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
}

/**
 * All tenant data access goes through here. `withTenant` opens a transaction and sets `app.org_id` (transaction-local)
 * so Postgres RLS confines every statement to that organization; with no org set, RLS returns no rows.
 * `withoutTenant` is only for the SECURITY DEFINER pre-authentication lookups (app_find_api_key, app_find_login...).
 */
export interface TenantDb {
  withTenant<T>(orgId: string, fn: (q: Queryable) => Promise<T>): Promise<T>;
  withoutTenant<T>(fn: (q: Queryable) => Promise<T>): Promise<T>;
  ping(): Promise<boolean>;
  close(): Promise<void>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface RlsStatus { enforced: boolean; role: string; reason: string | null }

/**
 * Whether row-level security actually applies to the role the application runs as. PostgreSQL silently SKIPS RLS for
 * superusers, for roles with BYPASSRLS, and for the owner of a table (unless the table uses FORCE ROW LEVEL SECURITY).
 * Connecting the gateway as any of those - e.g. the POSTGRES_USER a container image creates, which is a superuser - would
 * disable tenant isolation with no error anywhere. Run inside the same transaction setup as real queries, so a
 * `SET LOCAL ROLE` (assumeRole) is taken into account.
 */
export async function checkRlsEnforced(q: Queryable): Promise<RlsStatus> {
  const { rows } = await q.query<{ role: string; super: boolean; bypass: boolean; owner: string | null; member: boolean }>(`
    SELECT current_user AS role, r.rolsuper AS super, r.rolbypassrls AS bypass,
           (SELECT pg_get_userbyid(c.relowner) FROM pg_class c
              WHERE c.relname = 'api_keys' AND c.relnamespace = 'public'::regnamespace) AS owner,
           pg_has_role(current_user, 'sentinel_app', 'MEMBER') AS member
    FROM pg_roles r WHERE r.rolname = current_user`);
  const r = rows[0];
  if (!r) return { enforced: false, role: "unknown", reason: "current role not found" };
  if (r.super) return { enforced: false, role: r.role, reason: "role is a superuser (superusers bypass RLS)" };
  if (r.bypass) return { enforced: false, role: r.role, reason: "role has BYPASSRLS" };
  if (r.owner === r.role) return { enforced: false, role: r.role, reason: "role owns the tenant tables (owners bypass RLS)" };
  if (!r.member) return { enforced: false, role: r.role, reason: "role is not a member of sentinel_app (it lacks the application grants)" };
  return { enforced: true, role: r.role, reason: null };
}

export function assertUuid(id: string): string {
  if (!UUID.test(id)) throw new TypeError("invalid organization id");
  return id;
}

export class PgTenantDb implements TenantDb {
  private readonly pool: pg.Pool;
  /** In production the login role IS sentinel_app. Set `assumeRole` only when connecting as a role that may SET ROLE. */
  constructor(connectionString: string, private readonly assumeRole = false, opts: { connectTimeoutMs?: number } = {}) {
    // connectionTimeoutMillis: pg's default is NO timeout, so with the database down every request hung indefinitely
    // (found by stopping the Postgres container). Now acquiring a connection fails after a bounded wait and the request
    // fails closed promptly instead of holding a socket open forever.
    this.pool = new pg.Pool({ connectionString, max: 10, statement_timeout: 10_000, connectionTimeoutMillis: opts.connectTimeoutMs ?? 5_000 });
    // A dropped idle connection must not crash the process (pg emits 'error' on the pool for those).
    this.pool.on("error", () => undefined);
  }

  private async tx<T>(orgId: string | null, fn: (q: Queryable) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      if (this.assumeRole) await client.query("SET LOCAL ROLE sentinel_app");
      await client.query("SELECT set_config('app.org_id', $1, true)", [orgId === null ? "" : assertUuid(orgId)]);
      const result = await fn(client as unknown as Queryable);
      await client.query("COMMIT");
      return result;
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  withTenant<T>(orgId: string, fn: (q: Queryable) => Promise<T>): Promise<T> { return this.tx(assertUuid(orgId), fn); }
  withoutTenant<T>(fn: (q: Queryable) => Promise<T>): Promise<T> { return this.tx(null, fn); }
  async ping(): Promise<boolean> {
    try { await this.pool.query("SELECT 1"); return true; } catch { return false; }
  }
  close(): Promise<void> { return this.pool.end(); }

  /** See checkRlsEnforced. Evaluated exactly as a tenant query would run, including any SET LOCAL ROLE. */
  rlsStatus(): Promise<RlsStatus> { return this.tx(null, checkRlsEnforced); }
}
