import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export interface CredentialKey { id: string; key: Buffer }

const IV_BYTES = 12;
const TAG_BYTES = 16;
const VERSION = 1;

export class CredentialDecryptError extends Error {
  constructor(reason: string) { super(`provider credential cannot be decrypted: ${reason}`); this.name = "CredentialDecryptError"; }
}

/**
 * AES-256-GCM sealing of per-organization provider credentials.
 *
 * - The additional authenticated data binds a ciphertext to `organization:provider`, so a row copied to another
 *   organization or provider (a bug, a malicious DBA edit) fails authentication instead of lending one tenant's key to another.
 * - Blob layout: version(1) | iv(12) | tag(16) | ciphertext. The key id is stored next to it, so master keys can be rotated:
 *   new credentials are sealed with the first (active) key, old ones stay readable while their key is still configured.
 * - Any failure to open is an error, never an empty string: callers must fail closed.
 */
export class CredentialCipher {
  private readonly byId: Map<string, Buffer>;
  constructor(private readonly keys: CredentialKey[]) {
    if (keys.length === 0) throw new Error("at least one credential key is required");
    for (const k of keys) if (k.key.length !== 32) throw new Error(`credential key ${k.id} must be 32 bytes`);
    this.byId = new Map(keys.map((k) => [k.id, k.key]));
  }

  get activeKeyId(): string { return this.keys[0]!.id; }

  static aad(orgId: string, provider: string): Buffer { return Buffer.from(`sentinelai:provider-credential:v1:${orgId}:${provider}`); }

  seal(orgId: string, provider: string, plaintext: string): { keyId: string; blob: Buffer } {
    const iv = randomBytes(IV_BYTES);
    const c = createCipheriv("aes-256-gcm", this.keys[0]!.key, iv);
    c.setAAD(CredentialCipher.aad(orgId, provider));
    const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
    return { keyId: this.activeKeyId, blob: Buffer.concat([Buffer.from([VERSION]), iv, c.getAuthTag(), ct]) };
  }

  open(orgId: string, provider: string, keyId: string, blob: Buffer): string {
    const key = this.byId.get(keyId);
    if (!key) throw new CredentialDecryptError(`unknown key id "${keyId}"`);
    if (blob.length < 1 + IV_BYTES + TAG_BYTES + 1 || blob[0] !== VERSION) throw new CredentialDecryptError("malformed ciphertext");
    try {
      const d = createDecipheriv("aes-256-gcm", key, blob.subarray(1, 1 + IV_BYTES));
      d.setAAD(CredentialCipher.aad(orgId, provider));
      d.setAuthTag(blob.subarray(1 + IV_BYTES, 1 + IV_BYTES + TAG_BYTES));
      return Buffer.concat([d.update(blob.subarray(1 + IV_BYTES + TAG_BYTES)), d.final()]).toString("utf8");
    } catch {
      throw new CredentialDecryptError("authentication failed");
    }
  }
}

/** Parses `id:base64key[,id:base64key...]`; the first entry is the active sealing key. */
export function parseCredentialKeys(raw: string): CredentialKey[] {
  const out: CredentialKey[] = [];
  for (const part of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    const i = part.indexOf(":");
    const id = part.slice(0, i);
    if (i < 1 || !/^[a-z0-9_-]{1,16}$/i.test(id)) throw new Error("PROVIDER_CREDENTIAL_KEYS entries must look like id:base64key");
    const key = Buffer.from(part.slice(i + 1), "base64");
    if (key.length !== 32) throw new Error(`PROVIDER_CREDENTIAL_KEYS key "${id}" must decode to 32 bytes`);
    if (out.some((k) => k.id === id)) throw new Error(`PROVIDER_CREDENTIAL_KEYS has duplicate id "${id}"`);
    out.push({ id, key });
  }
  if (out.length === 0) throw new Error("PROVIDER_CREDENTIAL_KEYS is empty");
  return out;
}
