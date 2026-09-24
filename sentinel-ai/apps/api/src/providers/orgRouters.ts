import { AiRouter, AnthropicProvider, GeminiProvider, OpenAIProvider, type AIProvider } from "@sentinelai/ai-router";
import type { ProviderRepository, ProviderRow } from "../repositories/providerRepository.js";
import type { CredentialCipher } from "../security/credentialCipher.js";

/** Providers an organization may bring its own key for. Ollama is excluded: its endpoint is operator infrastructure (SSRF). */
export const TENANT_KEYED_PROVIDERS = ["gemini", "openai", "anthropic"] as const;
export type TenantKeyedProvider = (typeof TENANT_KEYED_PROVIDERS)[number];
export const isTenantKeyed = (p: string): p is TenantKeyedProvider => (TENANT_KEYED_PROVIDERS as readonly string[]).includes(p);

/** Where a request for an organization is routed. */
export interface RouterSource {
  /** Throws when the organization's configuration cannot be loaded or decrypted: callers must fail closed. */
  routerFor(orgId: string): Promise<AiRouter>;
  invalidate(orgId: string): void;
}

/** Operator configuration only (no per-organization settings): every organization shares one router. */
export class StaticRouterSource implements RouterSource {
  constructor(private readonly router: AiRouter) {}
  async routerFor(): Promise<AiRouter> { return this.router; }
  invalidate(): void { /* nothing cached */ }
}

export interface OrgRouterDeps {
  platform: AiRouter;
  repo: ProviderRepository;
  /** Absent: stored credentials cannot be opened, so an organization that has one is failed closed for that provider. */
  cipher: CredentialCipher | undefined;
  fetch?: typeof fetch;
  ttlMs?: number;
  now?: () => number;
}

/**
 * Per-organization routing. For each provider, in order:
 *   1. the organization disabled it          -> not registered (requests are blocked as unknown_provider);
 *   2. the organization stored its own key   -> a provider instance built with THAT key (never shared with another org);
 *   3. otherwise                             -> the operator-configured (platform) provider, if any.
 * If an organization's stored key cannot be decrypted (key removed, ciphertext tampered or moved to another org), routerFor
 * throws instead of quietly falling back to the platform key: spending the operator's account on a request the organization
 * meant to bill to its own key, or silently switching data processors, is not an acceptable degradation.
 *
 * Results are cached per organization for `ttlMs` (default 30s) and invalidated immediately on this replica when settings
 * change; other replicas pick the change up within the TTL.
 */
export class OrgRouterSource implements RouterSource {
  private readonly cache = new Map<string, { at: number; router: AiRouter }>();
  private readonly ttlMs: number;
  private readonly now: () => number;
  constructor(private readonly d: OrgRouterDeps) { this.ttlMs = d.ttlMs ?? 30_000; this.now = d.now ?? Date.now; }

  invalidate(orgId: string): void { this.cache.delete(orgId); }

  async routerFor(orgId: string): Promise<AiRouter> {
    const hit = this.cache.get(orgId);
    if (hit && this.now() - hit.at < this.ttlMs) return hit.router;
    const router = this.build(orgId, await this.d.repo.list(orgId));
    this.cache.set(orgId, { at: this.now(), router });
    if (this.cache.size > 10_000) this.cache.delete(this.cache.keys().next().value!);
    return router;
  }

  private build(orgId: string, rows: ProviderRow[]): AiRouter {
    const byName = new Map(rows.map((r) => [r.provider, r]));
    const router = new AiRouter();
    for (const id of this.d.platform.ids()) {
      const row = byName.get(id);
      if (row && !row.enabled) continue;
      if (row?.sealed && isTenantKeyed(id)) continue;           // replaced by the organization's own key below
      router.register(this.d.platform.resolve(id));
    }
    for (const row of rows) {
      if (!row.enabled || !row.sealed || !isTenantKeyed(row.provider)) continue;
      if (!this.d.cipher) throw new Error(`organization credential for ${row.provider} exists but no PROVIDER_CREDENTIAL_KEYS are configured`);
      const apiKey = this.d.cipher.open(orgId, row.provider, row.sealed.keyId, row.sealed.blob);
      router.register(makeProvider(row.provider, apiKey, this.d.fetch));
    }
    return router;
  }
}

function makeProvider(id: TenantKeyedProvider, apiKey: string, fetchImpl?: typeof fetch): AIProvider {
  const f = fetchImpl ? { fetch: fetchImpl } : {};
  switch (id) {
    case "gemini": return new GeminiProvider({ apiKey, ...f });
    case "openai": return new OpenAIProvider({ apiKey, ...f });
    case "anthropic": return new AnthropicProvider({ apiKey, ...f });
  }
}
