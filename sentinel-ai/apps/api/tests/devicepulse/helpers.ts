import type { FastifyInstance, LightMyRequestResponse } from "fastify";
import { AiRouter, ProviderError, type AIProvider, type ChatRequest, type ChatResponse, type StreamChunk } from "@sentinelai/ai-router";
import type { ExplainRequest } from "@sentinelai/devicepulse-contracts";
import { buildApp } from "../../src/app.js";
import type { AppConfig } from "../../src/config/env.js";
import { DevicePulseService } from "../../src/devicepulse/devicePulseService.js";
import { InMemoryAuditLog } from "../../src/events/auditLog.js";
import { InMemoryEventSink } from "../../src/events/eventSink.js";
import type { RateLimiter } from "../../src/middleware/hardening.js";
import { StaticRouterSource, type RouterSource } from "../../src/providers/orgRouters.js";
import { InMemoryDevicePulseRepository } from "../../src/repositories/devicePulseRepository.js";
import type { ApiKeyAuthenticator } from "../../src/security/apiKeys.js";
import type { Principal } from "../../src/security/rbac.js";
import { SecureAiService } from "../../src/services/secureAiService.js";
import { FakeProvider, FakeScanner, MemoryPolicies, ORG_A, ORG_B, TEST_CONFIG } from "../helpers/fakes.js";

export const CONSENT_VERSION = "2026-10-01";
const ago = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString();

/** A valid battery_drain request with timestamps relative to now. Aliases sent to the model: E1..E4, L1..L2. */
export function explainRequest(): ExplainRequest {
  return {
    schema_version: "1.0", diagnostic_type: "battery_drain", locale: "en-US",
    consent: { cloud_analysis: true, consent_version: CONSENT_VERSION, granted_at: ago(60 * 24 * 10) },
    client: { app_version: "1.4.0", android_api_level: 34 },
    observations: [
      { evidence_id: "ev_drain", metric: "battery_drain_rate", value: 14.5, unit: "percent_per_hour", observed_at: ago(30) },
      { evidence_id: "ev_screen", metric: "screen_on_time_24h", value: 410, unit: "minutes", observed_at: ago(30) },
      { evidence_id: "ev_wake", metric: "wakelock_time_24h", value: 185, unit: "minutes", observed_at: ago(30) },
      { evidence_id: "ev_temp", metric: "battery_temperature", value: 41.2, unit: "celsius", observed_at: ago(30) },
    ],
    local_findings: [
      { finding_id: "lf_drain", code: "high_drain_rate", severity: "high", evidence_ids: ["ev_drain"] },
      { finding_id: "lf_wake", code: "excessive_wakelocks", severity: "medium", evidence_ids: ["ev_wake", "ev_screen"] },
    ],
  };
}

/** A well-formed model reply for explainRequest(). Override any field. */
export function modelReply(over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    status: "completed",
    summary: "Your battery drains quickly, mostly because background activity keeps the phone awake.",
    overall_confidence: 0.66,
    findings: [
      { title: "Background activity keeps the phone awake", explanation: "The phone stayed awake for about three hours without screen use.",
        severity: "high", confidence: 0.72, evidence: ["E3", "E1"], local_findings: ["L2", "L1"] },
      { title: "Long screen-on time", explanation: "Almost seven hours of screen time adds to the drain.",
        severity: "medium", confidence: 0.55, evidence: ["E2"], local_findings: [] },
    ],
    limitation_codes: ["no_historical_baseline"],
    action_ids: ["review_background_usage", "enable_battery_saver"],
    ...over,
  });
}

/** Provider that never answers until the request's deadline aborts it (like the real adapters, abort -> `timeout`). */
export class HangingProvider implements AIProvider {
  readonly id = "gemini";
  sawSignal = false;
  calls = 0;
  async chat(req: ChatRequest): Promise<ChatResponse> {
    this.calls++;
    this.sawSignal = !!req.signal;
    return new Promise((_, reject) => {
      const fail = () => reject(new ProviderError(this.id, "timeout", "request timed out"));
      if (req.signal?.aborted) return fail();
      req.signal?.addEventListener("abort", fail, { once: true });
    });
  }
  generate(): Promise<ChatResponse> { throw new Error("unused"); }
  async *stream(): AsyncGenerator<StreamChunk> { throw new Error("unused"); }
  async validate() { return true; }
  async getModels() { return []; }
}

/** Authenticator double whose credentials can be revoked or made unverifiable mid-test. */
export class MutableAuth implements ApiKeyAuthenticator {
  down = false;
  constructor(readonly keys: Map<string, Principal>) {}
  async authenticate(raw: string | undefined): Promise<Principal | null> {
    if (this.down) throw new Error("credential store unavailable");
    return raw ? this.keys.get(raw) ?? null : null;
  }
}

export const KEYS: Record<string, Principal> = {
  dc_a: { organizationId: ORG_A, role: "DEVICE_CLIENT", apiKeyId: null, userId: "aaaaaaaa-0000-4000-8000-000000000001" },
  dc_a2: { organizationId: ORG_A, role: "DEVICE_CLIENT", apiKeyId: null, userId: "aaaaaaaa-0000-4000-8000-000000000002" },
  dc_b: { organizationId: ORG_B, role: "DEVICE_CLIENT", apiKeyId: null, userId: "bbbbbbbb-0000-4000-8000-000000000003" },
  dc_key: { organizationId: ORG_A, role: "DEVICE_CLIENT", apiKeyId: "key-device-1", userId: null },
  admin: { organizationId: ORG_A, role: "ADMIN", apiKeyId: "key-admin", userId: null },
  dev: { organizationId: ORG_A, role: "DEVELOPER", apiKeyId: "key-dev", userId: null },
  viewer: { organizationId: ORG_A, role: "VIEWER", apiKeyId: "key-viewer", userId: null },
};
export const H = (k: string) => ({ authorization: `Bearer ${k}` });

export interface Harness {
  app: FastifyInstance; scanner: FakeScanner; provider: AIProvider; events: InMemoryEventSink; audit: InMemoryAuditLog;
  policies: MemoryPolicies; repo: InMemoryDevicePulseRepository; auth: MutableAuth; config: AppConfig;
}

export function harness(o: {
  provider?: AIProvider; configured?: string | undefined; routers?: RouterSource; limiter?: RateLimiter; timeoutMs?: number;
} = {}): Harness {
  const scanner = new FakeScanner();
  const provider = o.provider ?? new FakeProvider("gemini");
  const events = new InMemoryEventSink(); const audit = new InMemoryAuditLog(); const policies = new MemoryPolicies();
  const repo = new InMemoryDevicePulseRepository();
  const auth = new MutableAuth(new Map(Object.entries(KEYS)));
  const router = new AiRouter({ sleep: async () => {} }).register(provider);
  const routers = o.routers ?? new StaticRouterSource(router);
  const config: AppConfig = {
    ...TEST_CONFIG,
    devicepulse: { ...TEST_CONFIG.devicepulse, provider: "configured" in o ? o.configured : "gemini", timeoutMs: o.timeoutMs ?? 2_000 },
  };
  const secureAi = new SecureAiService({ scanner, router, routers, policies, events });
  const service = new DevicePulseService({ config: config.devicepulse, secureAi, routers, scanner, repo });
  const app = buildApp({
    config, scanner, events, policies, auditLog: audit, auth, ping: async () => true, service: secureAi,
    devicepulse: { service, repo, ...(o.limiter ? { limiter: o.limiter } : {}) },
  }, { logger: false });
  return { app, scanner, provider, events, audit, policies, repo, auth, config };
}

export const explain = (h: Harness, key: string | null, payload: unknown = explainRequest()): Promise<LightMyRequestResponse> =>
  h.app.inject({ method: "POST", url: "/v1/devicepulse/diagnostics/explain", headers: key ? H(key) : {}, payload: payload as object });
