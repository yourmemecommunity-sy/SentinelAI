import type { ApiKeyAuthenticator } from "./apiKeys.js";
import type { Principal, RoleName } from "./rbac.js";
import type { AccessTokens } from "./tokens.js";

/** Current standing of a user, read from the database. */
export interface UserStateSource {
  userState(orgId: string, userId: string): Promise<{ role: RoleName; disabled: boolean } | null>;
}

/**
 * Accepts either a SentinelAI API key (`snl_...`) or a user access token (JWT). Anything else is rejected.
 *
 * With `users`, a valid JWT is also checked against the user's CURRENT state on every request: a disabled or deleted user is
 * refused and a changed role applies immediately, instead of the token's claims staying authoritative until it expires.
 * A lookup failure propagates (the middleware answers 503 auth_unavailable), never an allow.
 */
export class CompositeAuthenticator implements ApiKeyAuthenticator {
  constructor(private readonly apiKeys: ApiKeyAuthenticator, private readonly jwt: AccessTokens | undefined, private readonly users?: UserStateSource) {}

  async authenticate(raw: string | undefined): Promise<Principal | null> {
    if (!raw) return null;
    if (raw.startsWith("snl_")) return this.apiKeys.authenticate(raw);
    const p = this.jwt ? await this.jwt.verify(raw) : null;
    if (!p || !this.users || !p.userId) return p;
    const state = await this.users.userState(p.organizationId, p.userId);
    if (!state || state.disabled) return null;
    return { ...p, role: state.role };
  }
}
