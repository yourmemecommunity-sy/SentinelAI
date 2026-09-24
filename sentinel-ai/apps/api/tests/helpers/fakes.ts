import { ProviderError, type AIProvider, type ChatRequest, type ChatResponse, type StreamChunk } from "@sentinelai/ai-router";
import type { Action, Policy, ScanRequest, ScanResult } from "@sentinelai/shared-types";
import type { AppConfig } from "../../src/config/env.js";
import type { TestDb } from "./testDb.js";
import type { Queryable, TenantDb } from "../../src/db/tenantDb.js";
import type { PolicyRepository } from "../../src/repositories/policyRepository.js";
import type { ApiKeyAuthenticator } from "../../src/security/apiKeys.js";
import type { Principal } from "../../src/security/rbac.js";
import type { SecurityScanner } from "../../src/security/securityClient.js";

export const TEST_CONFIG: AppConfig = {
  nodeEnv: "test", port: 0, corsOrigins: ["https://dash.example.test"], apiKeyPepper: "p".repeat(40),
  securityEngineUrl: "http://engine.test", securityEngineToken: undefined, securityTimeoutMs: 500,
  databaseUrl: undefined, geminiApiKey: undefined, openaiApiKey: undefined, anthropicApiKey: undefined, ollama: undefined, maxInputChars: 5_000, documentScanner: undefined, maxFileBytes: 200_000, vault: undefined, stream: { holdBackChars: 256, minSegmentChars: 64, idleTimeoutMs: 30_000, maxDurationMs: 300_000, maxOutputChars: 200_000, maxConcurrent: 10 }, rateLimitPerMinute: 1000,
  jwtAccessSecret: "j".repeat(40), accessTtlSeconds: 900, refreshTtlSeconds: 86_400, signupEnabled: true, providerCredentialKeys: undefined,
};

export function makeScan(decision: Action, over: Partial<ScanResult> = {}): ScanResult {
  const withheld = decision === "BLOCK" || decision === "QUARANTINE";
  return {
    request_id: `req-${Math.random().toString(36).slice(2)}`, decision, failed_closed: false, fail_closed_reason: null,
    detections: [], entity_actions: [],
    risk: { risk_score: withheld ? 90 : 5, risk_level: withheld ? "CRITICAL" : "LOW", decision, factors: [] },
    sanitized_text: withheld ? null : "", policy_id: "sentinelai-baseline", detector_version: "test", latency_ms: 1, ...over,
  };
}

/**
 * Scanner double that behaves like the engine on marker strings:
 *   "BADSECRET" -> BLOCK (CRITICAL detection); "a@b.co" -> MASK (replaced); "SPLIT-" + "KEY" across text -> BLOCK.
 * Records every request so tests can assert exactly what was scanned.
 */
export class FakeScanner implements SecurityScanner {
  readonly requests: ScanRequest[] = [];
  down = false;
  isReady = true;
  override?: (req: ScanRequest) => ScanResult;
  async scan(req: ScanRequest): Promise<ScanResult> {
    this.requests.push(req);
    if (this.down) return makeScan("BLOCK", { failed_closed: true, fail_closed_reason: "engine_unreachable", sanitized_text: null });
    if (this.override) return this.override(req);
    const t = req.text;
    if (t.includes("BADSECRET") || /SPLIT-\s*KEY/.test(t)) {
      return makeScan("BLOCK", { detections: [{ entity: "API_KEY", confidence: 0.99, severity: "CRITICAL", location: { start: 0, end: 3 }, detector: "t", detector_version: "1", value_digest: "abc" }] });
    }
    if (t.includes("a@b.co")) return makeScan("MASK", { sanitized_text: t.replaceAll("a@b.co", "a***@b.co"), risk: { risk_score: 20, risk_level: "LOW", decision: "MASK", factors: [] } });
    return makeScan("ALLOW", { sanitized_text: t });
  }
  async ready() { return this.isReady; }
}

export class FakeProvider implements AIProvider {
  readonly id: string;
  readonly received: ChatRequest[] = [];
  reply: (req: ChatRequest) => string = () => "a harmless reply";
  error: Error | null = null;
  constructor(id = "gemini") { this.id = id; }
  async chat(req: ChatRequest): Promise<ChatResponse> {
    this.received.push(req);
    if (this.error) throw this.error;
    return { model: req.model ?? "fake-model", content: this.reply(req) };
  }
  generate(): Promise<ChatResponse> { throw new Error("unused"); }
  // ---- streaming controls (a stream is a list of text chunks by default: the reply, in one piece)
  streamPlan: (req: ChatRequest) => string[] = (req) => [this.reply(req)];
  chunkDelayMs = 0;
  /** Throw a ProviderError instead of yielding chunk number N (0-based). */
  failAtChunk: number | null = null;
  /** After the planned chunks, never finish (until aborted): simulates a provider that stalls. */
  stallAtEnd = false;
  streamsOpened = 0;
  streamsClosed = 0;
  sawAbort = false;
  async *stream(req: ChatRequest): AsyncGenerator<StreamChunk> {
    this.received.push(req);
    this.streamsOpened++;
    const abortable = (ms: number) => new Promise<void>((resolve, reject) => {
      const t = setTimeout(resolve, ms);
      req.signal?.addEventListener("abort", () => { clearTimeout(t); this.sawAbort = true; reject(new DOMException("aborted", "AbortError")); }, { once: true });
    });
    try {
      const parts = this.streamPlan(req);
      for (let i = 0; i < parts.length; i++) {
        if (req.signal?.aborted) { this.sawAbort = true; throw new DOMException("aborted", "AbortError"); }
        if (this.chunkDelayMs) await abortable(this.chunkDelayMs);
        if (this.failAtChunk === i) throw new ProviderError(this.id, "unavailable", "stream broke");
        yield { delta: parts[i]!, done: false };
      }
      if (this.stallAtEnd) await new Promise<void>((_, reject) => req.signal?.addEventListener("abort", () => { this.sawAbort = true; reject(new DOMException("aborted", "AbortError")); }, { once: true }));
      yield { delta: "", done: true };
    } finally { this.streamsClosed++; }
  }
  async validate() { return true; }
  async getModels() { return []; }
}

export class MemoryPolicies implements PolicyRepository {
  policy: Policy | undefined;
  fail = false;
  async getEffectivePolicy(): Promise<Policy | undefined> { if (this.fail) throw new Error("db down"); return this.policy; }
  async list() { return []; }
  async get() { return null; }
  async createVersion() { return 1; }
  async deactivate() { return false; }
}

export const ORG_A = "11111111-1111-4111-8111-111111111111";
export const ORG_B = "22222222-2222-4222-8222-222222222222";
export const principal = (over: Partial<Principal> = {}): Principal =>
  ({ organizationId: ORG_A, role: "DEVELOPER", apiKeyId: "key-1", userId: null, ...over });

/** Authenticator double: token -> principal. */
export class FakeAuth implements ApiKeyAuthenticator {
  constructor(private readonly tokens: Record<string, Principal>) {}
  async authenticate(raw: string | undefined) { return raw ? this.tokens[raw] ?? null : null; }
}

/** TenantDb over a test Postgres (PGlite or a real server), running as the RLS-restricted app role like production does. */
export class PgliteTenantDb implements TenantDb {
  constructor(private readonly db: TestDb) {}
  private run<T>(org: string, fn: (q: Queryable) => Promise<T>): Promise<T> {
    return this.db.transaction(async (tx) => {
      await tx.exec("SET LOCAL ROLE sentinel_app");
      await tx.query("SELECT set_config('app.org_id', $1, true)", [org]);
      return fn(tx as unknown as Queryable);
    });
  }
  withTenant<T>(orgId: string, fn: (q: Queryable) => Promise<T>) { return this.run(orgId, fn); }
  withoutTenant<T>(fn: (q: Queryable) => Promise<T>) { return this.run("", fn); }
  async ping() { return true; }
  async close() {}
}
