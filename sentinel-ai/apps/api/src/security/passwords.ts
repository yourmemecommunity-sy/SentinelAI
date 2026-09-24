import { randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCb) as (pw: string, salt: Buffer, keylen: number, opts: object) => Promise<Buffer>;

/** scrypt parameters (OWASP-recommended minimum: N=2^17,r=8,p=1 ~128MB; N=2^15 is the memory-lean profile used here). */
const PARAMS = { N: 32768, r: 8, p: 1 } as const;
const KEYLEN = 64;
const MAXMEM = 128 * PARAMS.N * PARAMS.r * 2;

export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 128;

/** Returns a reason string when the password is unacceptable, otherwise null. Never echoes the password. */
export function passwordPolicyViolation(password: string, email: string): string | null {
  if (password.length < PASSWORD_MIN) return `password must be at least ${PASSWORD_MIN} characters`;
  if (password.length > PASSWORD_MAX) return `password must be at most ${PASSWORD_MAX} characters`;
  const local = email.split("@")[0]?.toLowerCase() ?? "";
  if (local.length >= 4 && password.toLowerCase().includes(local)) return "password must not contain your email name";
  if (new Set(password).size < 5) return "password is too repetitive";
  return null;
}

/** Format: scrypt$N$r$p$<salt b64>$<hash b64>. Parameters are stored so they can be raised later. */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(password.normalize("NFKC"), salt, KEYLEN, { ...PARAMS, maxmem: MAXMEM });
  return `scrypt$${PARAMS.N}$${PARAMS.r}$${PARAMS.p}$${salt.toString("base64")}$${key.toString("base64")}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [scheme, n, r, p, saltB64, hashB64] = stored.split("$");
  if (scheme !== "scrypt" || !n || !r || !p || !saltB64 || !hashB64) return false;
  const N = Number(n); const R = Number(r); const P = Number(p);
  if (![N, R, P].every(Number.isInteger) || N > 2 ** 20 || R > 32 || P > 16) return false; // refuse attacker-chosen costs
  const expected = Buffer.from(hashB64, "base64");
  const key = await scrypt(password.normalize("NFKC"), Buffer.from(saltB64, "base64"), expected.length,
    { N, r: R, p: P, maxmem: 128 * N * R * 2 });
  return key.length === expected.length && timingSafeEqual(key, expected);
}

let dummy: Promise<string> | undefined;
/** Hash to verify against when the account does not exist, so unknown and known emails cost the same time. */
export function dummyHash(): Promise<string> {
  return (dummy ??= hashPassword("dummy-password-for-timing-equalisation"));
}
