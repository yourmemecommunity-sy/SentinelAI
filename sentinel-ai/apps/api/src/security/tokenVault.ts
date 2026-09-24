import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import type { Principal } from "./rbac.js";

export class VaultUnavailableError extends Error {
  constructor(message = "vault_unavailable") { super(message); this.name = "VaultUnavailableError"; }
}

/** Client for the token-vault service. Only what the gateway needs: resolve tokens, drop a session, readiness. */
export interface TokenVault {
  resolve(organizationId: string, sessionId: string, tokens: string[], signal?: AbortSignal): Promise<Map<string, string>>;
  deleteSession(organizationId: string, sessionId: string): Promise<void>;
  ready(): Promise<boolean>;
}

export const VAULT_SESSION_ID = /^[A-Za-z0-9_.:@-]{1,128}$/;
const TOKEN = /^\[TOK_[A-Z](?:[A-Z_]{0,30}[A-Z])?_[0-9]{1,6}\]$/;
const ResolveResponse = z.object({ values: z.record(z.string(), z.string().max(16_384)) });
const MAX_RESPONSE_CHARS = 4_000_000;
const MAX_TOKENS_PER_CALL = 512;

export interface HttpTokenVaultOptions { baseUrl: string; token?: string | undefined; timeoutMs: number; fetch?: typeof fetch }

export class HttpTokenVault implements TokenVault {
  private readonly f: typeof fetch;
  constructor(private readonly o: HttpTokenVaultOptions) { this.f = o.fetch ?? fetch; }

  private async call(path: string, method: string, body: unknown, external?: AbortSignal): Promise<Response> {
    const timeout = AbortSignal.timeout(this.o.timeoutMs);
    try {
      return await this.f(`${this.o.baseUrl}${path}`, {
        method, redirect: "error",                                   // the internal token must never follow a redirect
        headers: { "content-type": "application/json", ...(this.o.token ? { "x-internal-token": this.o.token } : {}) },
        body: JSON.stringify(body), signal: external ? AbortSignal.any([timeout, external]) : timeout,
      });
    } catch { throw new VaultUnavailableError("vault_unreachable"); }
  }

  async resolve(organizationId: string, sessionId: string, tokens: string[], signal?: AbortSignal): Promise<Map<string, string>> {
    const wanted = [...new Set(tokens.filter((t) => TOKEN.test(t)))].slice(0, MAX_TOKENS_PER_CALL);
    if (wanted.length === 0) return new Map();
    const res = await this.call("/v1/vault/resolve", "POST", { organization_id: organizationId, session_id: sessionId, tokens: wanted }, signal);
    if (!res.ok) throw new VaultUnavailableError(`vault_http_${res.status}`);
    let parsed: z.SafeParseReturnType<unknown, z.infer<typeof ResolveResponse>>;
    try {
      const text = await res.text();
      if (text.length > MAX_RESPONSE_CHARS) throw new Error("too large");
      parsed = ResolveResponse.safeParse(JSON.parse(text));
    } catch { throw new VaultUnavailableError("vault_invalid_response"); }
    if (!parsed.success) throw new VaultUnavailableError("vault_invalid_response");
    const asked = new Set(wanted);
    // Only tokens we asked about can come back: a misbehaving vault cannot inject text for other tokens.
    return new Map(Object.entries(parsed.data.values).filter(([t]) => asked.has(t)));
  }

  async deleteSession(organizationId: string, sessionId: string): Promise<void> {
    const res = await this.call("/v1/vault/sessions", "DELETE", { organization_id: organizationId, session_id: sessionId });
    if (!res.ok && res.status !== 204) throw new VaultUnavailableError(`vault_http_${res.status}`);
  }

  async ready(): Promise<boolean> {
    try { return (await this.f(`${this.o.baseUrl}/ready`, { redirect: "error", signal: AbortSignal.timeout(this.o.timeoutMs) })).ok; } catch { return false; }
  }
}

export interface VaultSession { id: string; ephemeral: boolean }

/**
 * The vault session a request uses. It is derived from the authenticated principal, so one caller can never name (or guess) another
 * caller's session: two principals sending the same `session_id` get unrelated vault sessions. Without a client-supplied id the
 * session is random and ephemeral (it only needs to live for this request/stream and is deleted afterwards).
 */
export function deriveVaultSession(p: Principal, clientSessionId: string | undefined): VaultSession {
  const who = p.apiKeyId ? `key:${p.apiKeyId}` : p.userId ? `user:${p.userId}` : "anonymous";
  const id = createHash("sha256").update(`${p.organizationId}\0${who}\0${clientSessionId ?? randomUUID()}`).digest("hex").slice(0, 40);
  return { id, ephemeral: clientSessionId === undefined };
}
