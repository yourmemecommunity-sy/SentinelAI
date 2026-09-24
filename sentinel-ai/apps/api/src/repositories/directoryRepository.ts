import type { TenantDb } from "../db/tenantDb.js";
import type { RoleName } from "../security/rbac.js";

export interface UserInfo { id: string; email: string; role: RoleName; disabled: boolean; created_at: string; teams: string[] }
export interface TeamInfo { id: string; name: string; members: string[] }
export interface InvitationInfo {
  id: string; email: string; role: RoleName; status: "pending" | "accepted" | "revoked" | "expired";
  expires_at: string; created_at: string; created_by: string;
}
export type AcceptResult =
  | { status: "ok"; userId: string; organizationId: string; role: RoleName }
  | { status: "invalid" | "email_taken" };

/** A user's current standing, looked up on every session request so disabling or demoting takes effect immediately. */
export interface UserState { role: RoleName; disabled: boolean }

export interface DirectoryRepository {
  listUsers(orgId: string): Promise<UserInfo[]>;
  getUser(orgId: string, id: string): Promise<UserInfo | null>;
  userState(orgId: string, id: string): Promise<UserState | null>;
  /** Returns "last_owner" when the change would leave the organization without an active OWNER (enforced in the database). */
  updateUser(orgId: string, id: string, change: { role?: RoleName; disabled?: boolean }): Promise<"ok" | "not_found" | "last_owner">;
  emailInOrg(orgId: string, email: string): Promise<boolean>;

  createInvitation(orgId: string, email: string, role: RoleName, tokenHash: string, expiresAt: Date, createdBy: string): Promise<InvitationInfo | "pending_exists">;
  listInvitations(orgId: string): Promise<InvitationInfo[]>;
  getInvitation(orgId: string, id: string): Promise<InvitationInfo | null>;
  revokeInvitation(orgId: string, id: string): Promise<boolean>;
  acceptInvitation(tokenHash: string, passwordHash: string): Promise<AcceptResult>;

  listTeams(orgId: string): Promise<TeamInfo[]>;
  createTeam(orgId: string, name: string): Promise<TeamInfo | "exists">;
  deleteTeam(orgId: string, id: string): Promise<boolean>;
  addMember(orgId: string, teamId: string, userId: string): Promise<"ok" | "not_found">;
  removeMember(orgId: string, teamId: string, userId: string): Promise<boolean>;
}

const iso = (d: Date | string) => new Date(d).toISOString();
const isUnique = (e: unknown) => (e as { code?: string }).code === "23505" || /duplicate key|unique/i.test((e as Error).message);
const isCheck = (e: unknown) => (e as { code?: string }).code === "23514" || /at least one active OWNER/.test((e as Error).message);

type InvRow = { id: string; email: string; role: RoleName; expires_at: Date; accepted_at: Date | null; revoked_at: Date | null; created_at: Date; created_by: string };
const INV_SELECT = `SELECT i.id, i.email, r.name AS role, i.expires_at, i.accepted_at, i.revoked_at, i.created_at, i.created_by
                    FROM invitations i JOIN roles r ON r.id = i.role_id`;
const toInv = (r: InvRow): InvitationInfo => ({
  id: r.id, email: r.email, role: r.role, created_by: r.created_by, created_at: iso(r.created_at), expires_at: iso(r.expires_at),
  status: r.accepted_at ? "accepted" : r.revoked_at ? "revoked" : new Date(r.expires_at).getTime() <= Date.now() ? "expired" : "pending",
});

type UserRow = { id: string; email: string; role: RoleName; disabled_at: Date | null; created_at: Date; teams: string[] | null };
const USER_SELECT = `SELECT u.id, u.email, r.name AS role, u.disabled_at, u.created_at,
                       COALESCE((SELECT array_agg(t.name ORDER BY t.name) FROM team_members m JOIN teams t ON t.id = m.team_id WHERE m.user_id = u.id), '{}') AS teams
                     FROM users u JOIN roles r ON r.id = u.role_id`;
const toUser = (r: UserRow): UserInfo => ({ id: r.id, email: r.email, role: r.role, disabled: r.disabled_at !== null, created_at: iso(r.created_at), teams: r.teams ?? [] });

/** Never selects password hashes or invitation token hashes: no management response can leak them by accident. */
export class PgDirectoryRepository implements DirectoryRepository {
  constructor(private readonly db: TenantDb) {}

  listUsers(orgId: string) {
    return this.db.withTenant(orgId, async (q) => (await q.query<UserRow>(`${USER_SELECT} ORDER BY u.created_at`)).rows.map(toUser));
  }
  getUser(orgId: string, id: string) {
    return this.db.withTenant(orgId, async (q) => { const r = (await q.query<UserRow>(`${USER_SELECT} WHERE u.id = $1`, [id])).rows[0]; return r ? toUser(r) : null; });
  }
  userState(orgId: string, id: string) {
    return this.db.withTenant(orgId, async (q) => {
      const r = (await q.query<{ role: RoleName; disabled_at: Date | null }>("SELECT r.name AS role, u.disabled_at FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1", [id])).rows[0];
      return r ? { role: r.role, disabled: r.disabled_at !== null } : null;
    });
  }
  async updateUser(orgId: string, id: string, change: { role?: RoleName; disabled?: boolean }): Promise<"ok" | "not_found" | "last_owner"> {
    try {
      return await this.db.withTenant(orgId, async (q) => {
        const sets: string[] = []; const params: unknown[] = [id];
        if (change.role !== undefined) { params.push(change.role); sets.push(`role_id = (SELECT id FROM roles WHERE name = $${params.length})`); }
        if (change.disabled !== undefined) sets.push(change.disabled ? "disabled_at = COALESCE(disabled_at, now())" : "disabled_at = NULL");
        if (sets.length === 0) return (await q.query("SELECT 1 FROM users WHERE id = $1", [id])).rows.length ? "ok" : "not_found";
        const r = await q.query(`UPDATE users SET ${sets.join(", ")} WHERE id = $1 RETURNING id`, params);
        return r.rows.length ? "ok" : "not_found";
      });
    } catch (e) {
      if (isCheck(e)) return "last_owner";
      throw e;
    }
  }
  emailInOrg(orgId: string, email: string) {
    return this.db.withTenant(orgId, async (q) => (await q.query("SELECT 1 FROM users WHERE email = $1", [email])).rows.length > 0);
  }

  async createInvitation(orgId: string, email: string, role: RoleName, tokenHash: string, expiresAt: Date, createdBy: string) {
    try {
      return await this.db.withTenant(orgId, async (q) => {
        // An expired, never-accepted invitation still occupies the "one open invitation per address" slot; retire it first.
        await q.query("UPDATE invitations SET revoked_at = now() WHERE email = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at <= now()", [email]);
        const { rows } = await q.query<{ id: string }>(
          `INSERT INTO invitations (organization_id, email, role_id, token_hash, expires_at, created_by)
           VALUES ($1, $2, (SELECT id FROM roles WHERE name = $3), $4, $5, $6) RETURNING id`, [orgId, email, role, tokenHash, expiresAt, createdBy]);
        return toInv((await q.query<InvRow>(`${INV_SELECT} WHERE i.id = $1`, [rows[0]!.id])).rows[0]!);
      });
    } catch (e) {
      if (isUnique(e)) return "pending_exists" as const;
      throw e;
    }
  }
  listInvitations(orgId: string) {
    return this.db.withTenant(orgId, async (q) => (await q.query<InvRow>(`${INV_SELECT} ORDER BY i.created_at DESC LIMIT 500`)).rows.map(toInv));
  }
  getInvitation(orgId: string, id: string) {
    return this.db.withTenant(orgId, async (q) => { const r = (await q.query<InvRow>(`${INV_SELECT} WHERE i.id = $1`, [id])).rows[0]; return r ? toInv(r) : null; });
  }
  revokeInvitation(orgId: string, id: string) {
    return this.db.withTenant(orgId, async (q) =>
      (await q.query("UPDATE invitations SET revoked_at = now() WHERE id = $1 AND accepted_at IS NULL AND revoked_at IS NULL RETURNING id", [id])).rows.length > 0);
  }
  async acceptInvitation(tokenHash: string, passwordHash: string): Promise<AcceptResult> {
    try {
      const r = await this.db.withoutTenant(async (q) => (await q.query<{ status: string; user_id: string | null; organization_id: string | null; role: RoleName | null }>(
        "SELECT * FROM app_accept_invitation($1, $2)", [tokenHash, passwordHash])).rows[0]);
      if (r?.status === "ok") return { status: "ok", userId: r.user_id!, organizationId: r.organization_id!, role: r.role! };
      return { status: r?.status === "email_taken" ? "email_taken" : "invalid" };
    } catch (e) {
      if (isUnique(e)) return { status: "email_taken" };   // concurrent signup of the same address
      throw e;
    }
  }

  listTeams(orgId: string) {
    return this.db.withTenant(orgId, async (q) => (await q.query<{ id: string; name: string; members: string[] | null }>(
      `SELECT t.id, t.name, COALESCE((SELECT array_agg(m.user_id::text ORDER BY m.user_id) FROM team_members m WHERE m.team_id = t.id), '{}') AS members
       FROM teams t ORDER BY t.name`)).rows.map((r) => ({ id: r.id, name: r.name, members: r.members ?? [] })));
  }
  async createTeam(orgId: string, name: string) {
    try {
      return await this.db.withTenant(orgId, async (q) => {
        const r = (await q.query<{ id: string }>("INSERT INTO teams (organization_id, name) VALUES ($1, $2) RETURNING id", [orgId, name])).rows[0]!;
        return { id: r.id, name, members: [] };
      });
    } catch (e) {
      if (isUnique(e)) return "exists" as const;
      throw e;
    }
  }
  deleteTeam(orgId: string, id: string) {
    return this.db.withTenant(orgId, async (q) => (await q.query("DELETE FROM teams WHERE id = $1 RETURNING id", [id])).rows.length > 0);
  }
  addMember(orgId: string, teamId: string, userId: string) {
    return this.db.withTenant(orgId, async (q) => {
      // Both must be visible under this tenant's RLS scope; a foreign id is simply not found.
      const ok = (await q.query("SELECT 1 FROM teams t, users u WHERE t.id = $1 AND u.id = $2", [teamId, userId])).rows.length > 0;
      if (!ok) return "not_found" as const;
      await q.query("INSERT INTO team_members (organization_id, team_id, user_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", [orgId, teamId, userId]);
      return "ok" as const;
    });
  }
  removeMember(orgId: string, teamId: string, userId: string) {
    return this.db.withTenant(orgId, async (q) =>
      (await q.query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2 RETURNING team_id", [teamId, userId])).rows.length > 0);
  }
}
