import { randomBytes } from "node:crypto";
import type { AuditLogWriter } from "../events/auditLog.js";
import type { AuthRepository } from "../repositories/authRepository.js";
import { dummyHash, hashPassword, passwordPolicyViolation, verifyPassword } from "../security/passwords.js";
import type { RoleName } from "../security/rbac.js";
import { hashRefreshToken, newRefreshToken, type AccessTokens } from "../security/tokens.js";

export interface Session {
  accessToken: string; refreshToken: string; expiresIn: number;
  user: { id: string; organizationId: string; role: RoleName };
}

export type SignupResult =
  | { ok: true; session: Session }
  | { ok: false; reason: "weak_password" | "conflict"; detail?: string };

export interface AuthServiceDeps {
  repo: AuthRepository; tokens: AccessTokens; audit: AuditLogWriter;
  accessTtlSeconds: number; refreshTtlSeconds: number; now?: () => Date;
}

const slugify = (s: string): string => {
  const base = s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "org";
  return `${base}-${randomBytes(3).toString("hex")}`;
};

export class AuthService {
  private readonly now: () => Date;
  constructor(private readonly d: AuthServiceDeps) { this.now = d.now ?? (() => new Date()); }

  private async issue(user: { id: string; organizationId: string; role: RoleName }, familyId: string | null): Promise<Session> {
    const refresh = newRefreshToken();
    const expiresAt = new Date(this.now().getTime() + this.d.refreshTtlSeconds * 1000);
    await this.d.repo.createRefresh(user.organizationId, user.id, familyId, refresh.hash, expiresAt);
    return {
      accessToken: await this.d.tokens.sign({ userId: user.id, organizationId: user.organizationId, role: user.role }),
      refreshToken: refresh.token, expiresIn: this.d.accessTtlSeconds, user,
    };
  }

  private async note(orgId: string, actorId: string | null, action: string, target: string | null = null): Promise<void> {
    try { await this.d.audit.record({ organizationId: orgId, actorId, actorType: "user", action, target, metadata: {} }); } catch { /* auth flow must not depend on audit availability */ }
  }

  async signup(input: { organizationName: string; email: string; password: string }): Promise<SignupResult> {
    const email = input.email.trim().toLowerCase();
    const violation = passwordPolicyViolation(input.password, email);
    if (violation) return { ok: false, reason: "weak_password", detail: violation };
    const created = await this.d.repo.signup(input.organizationName.trim(), slugify(input.organizationName), email, await hashPassword(input.password));
    if (!created) return { ok: false, reason: "conflict" };
    await this.note(created.organizationId, created.userId, "auth.signup");
    return { ok: true, session: await this.issue({ id: created.userId, organizationId: created.organizationId, role: "OWNER" }, null) };
  }

  /** Returns null for every failure so callers cannot tell unknown email from wrong password from disabled account. */
  async login(emailRaw: string, password: string): Promise<Session | null> {
    const email = emailRaw.trim().toLowerCase();
    const rec = await this.d.repo.findLogin(email);
    // Always run one scrypt verification (against a dummy for unknown accounts) so timing does not reveal existence.
    const ok = await verifyPassword(password, rec?.passwordHash ?? await dummyHash());
    if (!rec || !ok || rec.disabled) {
      if (rec) await this.note(rec.organizationId, rec.id, "auth.login_failed");
      return null;
    }
    await this.note(rec.organizationId, rec.id, "auth.login");
    return this.issue({ id: rec.id, organizationId: rec.organizationId, role: rec.role }, null);
  }

  /** Rotating refresh with reuse detection: replaying a used token revokes the entire token family. */
  async refresh(rawToken: string): Promise<Session | null> {
    const rec = await this.d.repo.findRefresh(hashRefreshToken(rawToken));
    if (!rec) return null;
    if (rec.revoked) {
      await this.d.repo.revokeFamily(rec.organizationId, rec.familyId);
      await this.note(rec.organizationId, rec.userId, "auth.refresh_reuse_detected");
      return null;
    }
    if (rec.expiresAt <= this.now() || rec.userDisabled) return null;

    const next = newRefreshToken();
    const expiresAt = new Date(this.now().getTime() + this.d.refreshTtlSeconds * 1000);
    if (!(await this.d.repo.rotate(rec.organizationId, rec, next.hash, expiresAt))) {
      await this.d.repo.revokeFamily(rec.organizationId, rec.familyId); // lost a race or replay
      await this.note(rec.organizationId, rec.userId, "auth.refresh_reuse_detected");
      return null;
    }
    const user = { id: rec.userId, organizationId: rec.organizationId, role: rec.role }; // role re-read from the DB on every refresh
    return {
      accessToken: await this.d.tokens.sign({ userId: user.id, organizationId: user.organizationId, role: user.role }),
      refreshToken: next.token, expiresIn: this.d.accessTtlSeconds, user,
    };
  }

  async logout(rawToken: string): Promise<void> {
    const rec = await this.d.repo.findRefresh(hashRefreshToken(rawToken));
    if (!rec) return;
    await this.d.repo.revokeFamily(rec.organizationId, rec.familyId);
    await this.note(rec.organizationId, rec.userId, "auth.logout");
  }
}
