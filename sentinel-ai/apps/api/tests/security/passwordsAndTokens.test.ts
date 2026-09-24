import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { dummyHash, hashPassword, passwordPolicyViolation, verifyPassword } from "../../src/security/passwords.js";
import { AccessTokens, hashRefreshToken, newRefreshToken } from "../../src/security/tokens.js";

const SECRET = "s".repeat(40);
const enc = (s: string) => new TextEncoder().encode(s);
const claims = { userId: "11111111-1111-4111-8111-111111111111", organizationId: "22222222-2222-4222-8222-222222222222", role: "ADMIN" as const };

describe("passwords", () => {
  it("round-trips, salts every hash, and rejects wrong passwords", async () => {
    const [a, b] = await Promise.all([hashPassword("correct horse battery"), hashPassword("correct horse battery")]);
    expect(a).not.toBe(b);
    expect(a).toMatch(/^scrypt\$32768\$8\$1\$/);
    expect(a).not.toContain("correct horse");
    expect(await verifyPassword("correct horse battery", a)).toBe(true);
    expect(await verifyPassword("correct horse batterY", a)).toBe(false);
    expect(await verifyPassword("", a)).toBe(false);
  });

  it("treats Unicode-equivalent passwords as equal (NFKC) so users are not locked out by input method", async () => {
    const h = await hashPassword("passéword-long-enough");
    expect(await verifyPassword("passéword-long-enough", h)).toBe(true);
  });

  it("refuses malformed hashes and attacker-chosen work factors", async () => {
    for (const bad of ["", "plain", "scrypt$1$2", "bcrypt$1$2$3$4$5", "scrypt$abc$8$1$AAAA$AAAA", `scrypt$${2 ** 30}$8$1$AAAA$AAAA`, "scrypt$32768$999$1$AAAA$AAAA"]) {
      expect(await verifyPassword("x", bad), bad).toBe(false);
    }
  });

  it("dummy hash is a real scrypt hash (so unknown accounts cost the same to check)", async () => {
    expect(await dummyHash()).toMatch(/^scrypt\$/);
    expect(await verifyPassword("anything", await dummyHash())).toBe(false);
  });

  it("policy: length, email-name reuse, repetition; never echoes the password", () => {
    expect(passwordPolicyViolation("short", "a@b.co")).toMatch(/at least 12/);
    expect(passwordPolicyViolation("x".repeat(129), "a@b.co")).toMatch(/at most 128/);
    expect(passwordPolicyViolation("my-alexander-pass-1", "alexander@example.com")).toMatch(/email name/);
    expect(passwordPolicyViolation("aaaaaaaaaaaaaa", "a@b.co")).toMatch(/repetitive/);
    expect(passwordPolicyViolation("Tr0ub4dor&3-horse", "a@b.co")).toBeNull();
    expect(passwordPolicyViolation("short", "a@b.co")).not.toContain("short");
  });
});

describe("access tokens (JWT)", () => {
  it("signs and verifies, carrying user, org and role", async () => {
    const t = new AccessTokens({ secret: SECRET, ttlSeconds: 900 });
    expect(await t.verify(await t.sign(claims))).toEqual({ userId: claims.userId, organizationId: claims.organizationId, role: "ADMIN", apiKeyId: null });
  });

  it("rejects expired tokens (and accepts just before expiry)", async () => {
    let now = Date.now();
    const t = new AccessTokens({ secret: SECRET, ttlSeconds: 60 }, () => now);
    const token = await t.sign(claims);
    now += 59_000; expect(await t.verify(token)).not.toBeNull();
    now += 2_000; expect(await t.verify(token)).toBeNull();
  });

  it("rejects tampering, wrong secret, and garbage", async () => {
    const t = new AccessTokens({ secret: SECRET, ttlSeconds: 900 });
    const token = await t.sign(claims);
    const [h, p, s] = token.split(".");
    const forgedPayload = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p!, "base64url").toString()), role: "OWNER" })).toString("base64url");
    for (const bad of [`${h}.${forgedPayload}.${s}`, `${h}.${p}.${s!.slice(0, -2)}AA`, "", "abc", "a.b.c", token + "x"]) expect(await t.verify(bad), bad).toBeNull();
    expect(await new AccessTokens({ secret: "z".repeat(40), ttlSeconds: 900 }).verify(token)).toBeNull();
  });

  it("rejects alg=none and non-HS256 algorithms (algorithm confusion)", async () => {
    const t = new AccessTokens({ secret: SECRET, ttlSeconds: 900 });
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const now = Math.floor(Date.now() / 1000);
    const body = { sub: claims.userId, org: claims.organizationId, role: "OWNER", iss: "sentinelai-api", aud: "sentinelai", iat: now, exp: now + 600 };
    expect(await t.verify(`${b64({ alg: "none", typ: "JWT" })}.${b64(body)}.`)).toBeNull();
    const hs512 = await new SignJWT(body).setProtectedHeader({ alg: "HS512" }).sign(enc(SECRET));
    expect(await t.verify(hs512)).toBeNull();
  });

  it("rejects wrong issuer/audience, missing claims and unknown roles even with a valid signature", async () => {
    const t = new AccessTokens({ secret: SECRET, ttlSeconds: 900 });
    const sign = (over: { iss?: string; aud?: string; role?: string; org?: string | undefined; sub?: string | undefined }) => {
      const j = new SignJWT({ org: "org" in over ? over.org : claims.organizationId, role: over.role ?? "ADMIN" })
        .setProtectedHeader({ alg: "HS256" }).setIssuer(over.iss ?? "sentinelai-api").setAudience(over.aud ?? "sentinelai")
        .setIssuedAt().setExpirationTime("10m");
      if (!("sub" in over) || over.sub) j.setSubject(over.sub ?? claims.userId);
      return j.sign(enc(SECRET));
    };
    expect(await t.verify(await sign({}))).not.toBeNull();
    for (const over of [{ iss: "evil" }, { aud: "other" }, { role: "SUPERUSER" }, { org: undefined }, { sub: undefined }]) {
      expect(await t.verify(await sign(over)), JSON.stringify(over)).toBeNull();
    }
  });

  it("refuses to be constructed with a weak secret", () => {
    expect(() => new AccessTokens({ secret: "short", ttlSeconds: 900 })).toThrow();
  });
});

describe("refresh tokens", () => {
  it("are random, prefixed, and stored only as a hash", () => {
    const a = newRefreshToken(); const b = newRefreshToken();
    expect(a.token).toMatch(/^snr_[A-Za-z0-9_-]{43}$/);
    expect(a.token).not.toBe(b.token);
    expect(a.hash).toBe(hashRefreshToken(a.token));
    expect(a.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(a.hash).not.toContain(a.token.slice(4, 20));
  });
});
