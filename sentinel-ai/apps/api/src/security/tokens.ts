import { createHash, randomBytes } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import { ROLES, type Principal, type RoleName } from "./rbac.js";

const ISSUER = "sentinelai-api";
const AUDIENCE = "sentinelai";

export interface AccessTokenConfig { secret: string; ttlSeconds: number }

export class AccessTokens {
  private readonly key: Uint8Array;
  constructor(private readonly cfg: AccessTokenConfig, private readonly now: () => number = () => Date.now()) {
    if (cfg.secret.length < 32) throw new Error("JWT access secret must be at least 32 characters");
    this.key = new TextEncoder().encode(cfg.secret);
  }

  async sign(p: { userId: string; organizationId: string; role: RoleName }): Promise<string> {
    const iat = Math.floor(this.now() / 1000);
    return new SignJWT({ org: p.organizationId, role: p.role })
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setSubject(p.userId).setIssuer(ISSUER).setAudience(AUDIENCE)
      .setIssuedAt(iat).setExpirationTime(iat + this.cfg.ttlSeconds).setJti(randomBytes(12).toString("base64url"))
      .sign(this.key);
  }

  /** Returns null for any invalid token. The algorithm is pinned to HS256, so `alg: none` and key-confusion tokens fail. */
  async verify(token: string): Promise<Principal | null> {
    try {
      const { payload } = await jwtVerify(token, this.key, {
        algorithms: ["HS256"], issuer: ISSUER, audience: AUDIENCE, currentDate: new Date(this.now()), requiredClaims: ["sub", "exp", "iat"],
      });
      const role = payload["role"], org = payload["org"];
      if (typeof payload.sub !== "string" || typeof org !== "string" || typeof role !== "string") return null;
      if (!(ROLES as readonly string[]).includes(role)) return null;
      return { userId: payload.sub, organizationId: org, role: role as RoleName, apiKeyId: null };
    } catch { return null; }
  }
}

/** Opaque 256-bit refresh token; only its SHA-256 is ever stored. */
export function newRefreshToken(): { token: string; hash: string } {
  const token = `snr_${randomBytes(32).toString("base64url")}`;
  return { token, hash: hashRefreshToken(token) };
}
export const hashRefreshToken = (token: string): string => createHash("sha256").update(token).digest("hex");
