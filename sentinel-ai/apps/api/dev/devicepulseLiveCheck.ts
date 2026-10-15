/**
 * Live check: DevicePulse explanations through the REAL security engine and a REAL local Ollama model.
 * Measures how often a real model's reply passes DevicePulse's output validation; prints one line per request.
 *
 *   OLLAMA_MODEL=qwen2.5:1.5b [OLLAMA_BASE_URL=http://127.0.0.1:11434] [ROUNDS=1] \
 *     apps/api/node_modules/.bin/tsx apps/api/dev/devicepulseLiveCheck.ts
 *
 * Needs services/security-engine/.venv (or SENTINEL_E2E_PYTHON). Nothing is persisted (in-memory stores).
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AiRouter, OllamaProvider } from "@sentinelai/ai-router";
import { DIAGNOSTIC_TYPES, ExplainResponseSchema, validateExplainRequest, type DiagnosticType, type ExplainRequest } from "@sentinelai/devicepulse-contracts";
import { DevicePulseService } from "../src/devicepulse/devicePulseService.js";
import { InMemoryEventSink } from "../src/events/eventSink.js";
import { StaticRouterSource } from "../src/providers/orgRouters.js";
import { InMemoryDevicePulseRepository } from "../src/repositories/devicePulseRepository.js";
import type { PolicyRepository } from "../src/repositories/policyRepository.js";
import { HttpSecurityClient } from "../src/security/securityClient.js";
import { SecureAiService } from "../src/services/secureAiService.js";

const MODEL = process.env.OLLAMA_MODEL;
if (!MODEL) { console.error("set OLLAMA_MODEL"); process.exit(2); }
const BASE = process.env.OLLAMA_BASE_URL ?? "http://127.0.0.1:11434";
const ROUNDS = Number(process.env.ROUNDS ?? 1);
const ENGINE_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../../services/security-engine");
const PY = process.env.SENTINEL_E2E_PYTHON ?? resolve(ENGINE_DIR, process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python");
if (!existsSync(PY)) { console.error(`no engine python at ${PY}`); process.exit(2); }

const ago = (m: number) => new Date(Date.now() - m * 60_000).toISOString();
const consent = { cloud_analysis: true as const, consent_version: "2026-10-01", granted_at: ago(60 * 24) };
const obs = (id: string, metric: string, value: number, unit: string) => ({ evidence_id: id, metric, value, unit, observed_at: ago(20) });
const SAMPLES: Record<DiagnosticType, Pick<ExplainRequest, "observations" | "local_findings">> = {
  battery_drain: { observations: [obs("d", "battery_drain_rate", 14.5, "percent_per_hour"), obs("w", "wakelock_time_24h", 185, "minutes"), obs("s", "screen_on_time_24h", 410, "minutes")],
    local_findings: [{ finding_id: "f1", code: "high_drain_rate", severity: "high", evidence_ids: ["d"] }, { finding_id: "f2", code: "excessive_wakelocks", severity: "medium", evidence_ids: ["w"] }] },
  thermal: { observations: [obs("c", "cpu_temperature", 88, "celsius"), obs("t", "thermal_status", 3, "level"), obs("u", "cpu_usage", 92, "percent")],
    local_findings: [{ finding_id: "f1", code: "thermal_throttling", severity: "high", evidence_ids: ["t", "c"] }] },
  storage: { observations: [obs("f", "storage_free_ratio", 3, "percent"), obs("c", "cache_size_total", 4200, "megabytes")],
    local_findings: [{ finding_id: "f1", code: "low_free_storage", severity: "high", evidence_ids: ["f"] }] },
  memory: { observations: [obs("a", "ram_available", 180, "megabytes"), obs("t", "ram_total", 4096, "megabytes"), obs("l", "low_memory_events_24h", 37, "count")],
    local_findings: [{ finding_id: "f1", code: "frequent_low_memory_events", severity: "medium", evidence_ids: ["l"] }] },
  network: { observations: [obs("l", "network_latency", 850, "milliseconds"), obs("p", "packet_loss", 12, "percent"), obs("w", "wifi_signal", -82, "dbm")],
    local_findings: [{ finding_id: "f1", code: "weak_wifi_signal", severity: "medium", evidence_ids: ["w"] }] },
  performance: { observations: [obs("a", "anr_count_24h", 6, "count"), obs("f", "frame_drop_ratio", 18, "percent"), obs("u", "uptime", 410, "hours")],
    local_findings: [{ finding_id: "f1", code: "frequent_anrs", severity: "high", evidence_ids: ["a"] }] },
};

const freePort = () => new Promise<number>((res) => { const s = createServer(); s.listen(0, "127.0.0.1", () => { const p = (s.address() as { port: number }).port; s.close(() => res(p)); }); });

const port = await freePort();
const token = "live-check-internal-token-123456";
const engine = spawn(PY, ["-m", "uvicorn", "app.main:app", "--port", String(port), "--log-level", "warning"],
  { cwd: ENGINE_DIR, env: { ...process.env, SECURITY_ENGINE_TOKEN: token, SENTINEL_ENV: "development" }, stdio: "ignore" });
try {
  const scanner = new HttpSecurityClient({ baseUrl: `http://127.0.0.1:${port}`, token, timeoutMs: 3000 });
  for (let i = 0; i < 100 && !(await scanner.ready()); i++) await new Promise((r) => setTimeout(r, 300));
  const router = new AiRouter().register(new OllamaProvider({ baseUrl: BASE, defaultModel: MODEL }));
  const routers = new StaticRouterSource(router);
  const policies: PolicyRepository = { getEffectivePolicy: async () => undefined } as unknown as PolicyRepository;
  const config = { provider: "ollama", model: MODEL, timeoutMs: 90_000, explainPerMinute: 1000, consentVersions: ["2026-10-01"], retentionDays: 1 };
  const service = new DevicePulseService({ config, routers, scanner, repo: new InMemoryDevicePulseRepository(),
    secureAi: new SecureAiService({ scanner, router, routers, policies, events: new InMemoryEventSink() }) });
  const principal = { organizationId: "11111111-1111-4111-8111-111111111111", role: "DEVICE_CLIENT" as const, apiKeyId: null, userId: "live-check" };

  console.log(`# DevicePulse live check ${new Date().toISOString()} model=${MODEL} rounds=${ROUNDS}`);
  let ok = 0; let total = 0;
  for (let r = 0; r < ROUNDS; r++) {
    for (const type of DIAGNOSTIC_TYPES) {
      const raw = { schema_version: "1.0", diagnostic_type: type, locale: "en-US", consent, client: { app_version: "1.0.0", android_api_level: 34 }, ...SAMPLES[type] };
      const v = validateExplainRequest(raw, { now: new Date(), acceptedConsentVersions: config.consentVersions });
      if (!v.ok) { console.log(`${type}\tREQUEST_INVALID\t${v.error}`); continue; }
      const t0 = Date.now();
      const out = await service.explain(principal, { type: "user", id: "live-check" }, v.value);
      const ms = Date.now() - t0; total++;
      if (out.kind === "ok") {
        ok++;
        const valid = ExplainResponseSchema.safeParse(out.response).success;
        console.log(`${type}\tOK\t${ms}ms\tcontract=${valid}\tstatus=${out.response.status}\tfindings=${out.response.findings.length}\tactions=${out.response.recommended_action_ids.join(",") || "-"}`);
      } else {
        console.log(`${type}\t${out.error}\t${ms}ms\t${out.detail ?? ""}`);
      }
    }
  }
  console.log(`# valid explanations: ${ok}/${total}`);
} finally {
  engine.kill();
}
