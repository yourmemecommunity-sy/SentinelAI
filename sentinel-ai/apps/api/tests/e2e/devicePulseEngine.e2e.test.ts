/**
 * End-to-end: DevicePulse through the real gateway + REAL Python security engine (subprocess) + Postgres (PGlite) + real
 * API-key authentication. Only the model is a double (no provider key exists on this machine).
 *
 * What only this suite proves: the prompts DevicePulse builds pass the real detectors for every diagnostic type, even
 * with the largest allowed values (a false positive would make the feature unusable), and real detections in a model reply
 * (credentials, personal data) are enforced before the app sees the reply.
 *
 * Needs a Python with the engine's dependencies: set SENTINEL_E2E_PYTHON, or create services/security-engine/.venv.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AiRouter } from "@sentinelai/ai-router";
import { DIAGNOSTICS, DIAGNOSTIC_TYPES, ExplainResponseSchema, METRICS, type ExplainRequest } from "@sentinelai/devicepulse-contracts";
import { buildApp } from "../../src/app.js";
import { DevicePulseService } from "../../src/devicepulse/devicePulseService.js";
import { PgAuditLogWriter } from "../../src/events/auditLog.js";
import { PgEventSink } from "../../src/events/eventSink.js";
import { StaticRouterSource } from "../../src/providers/orgRouters.js";
import { PgDevicePulseRepository } from "../../src/repositories/devicePulseRepository.js";
import { PgPolicyRepository } from "../../src/repositories/policyRepository.js";
import { DbApiKeyAuthenticator, createApiKey } from "../../src/security/apiKeys.js";
import { HttpSecurityClient } from "../../src/security/securityClient.js";
import { SecureAiService } from "../../src/services/secureAiService.js";
import { FakeProvider, PgliteTenantDb, TEST_CONFIG } from "../helpers/fakes.js";
import { createMigratedDb, type TestDb } from "../helpers/testDb.js";
import { explainRequest, modelReply } from "../devicepulse/helpers.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE_DIR = resolve(HERE, "../../../../services/security-engine");
const VENV_PY = resolve(ENGINE_DIR, process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python");
const PYTHON = process.env.SENTINEL_E2E_PYTHON ?? (existsSync(VENV_PY) ? VENV_PY : undefined);
const INTERNAL_TOKEN = "e2e-internal-token-1234567890";
const PEPPER = "d".repeat(40);
// Secret-shaped value assembled at runtime; not a real credential.
const AWS_KEY = "AK" + "IA" + "QWERTYUIOPASDFGH";
const EMAIL = "jane.doe@example.com";

let PORT = 0; let engine: ChildProcess; let db: TestDb; let app: FastifyInstance; let provider: FakeProvider;
let device: string; let developer: string;

function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const srv = createServer();
    srv.once("error", rej);
    srv.listen(0, "127.0.0.1", () => { const { port } = srv.address() as { port: number }; srv.close(() => res(port)); });
  });
}
async function waitReady(): Promise<void> {
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(`http://127.0.0.1:${PORT}/ready`)).ok) return; } catch { /* still starting */ }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error("security engine did not become ready");
}

const H = (k: string) => ({ "x-sentinel-api-key": k });
const explain = (payload: unknown, key = device) =>
  app.inject({ method: "POST", url: "/v1/devicepulse/diagnostics/explain", headers: H(key), payload: payload as object });

/** A request for one diagnostic type that uses EVERY metric of that type at its largest allowed value (worst case for detectors). */
function worstCase(type: (typeof DIAGNOSTIC_TYPES)[number]): ExplainRequest {
  const base = explainRequest();
  const at = base.observations[0]!.observed_at;
  const observations = DIAGNOSTICS[type].metrics.map((m, i) => ({ evidence_id: `ev_${i}`, metric: m, value: METRICS[m].max, unit: METRICS[m].unit, observed_at: at }));
  const local_findings = DIAGNOSTICS[type].localFindingCodes.map((code, i) => ({ finding_id: `lf_${i}`, code, severity: "high" as const, evidence_ids: ["ev_0"] }));
  return { ...base, diagnostic_type: type, observations, local_findings };
}
const genericReply = () => modelReply({
  findings: [{ title: "Measurements are outside the usual range", explanation: "Several readings are at their highest possible values.",
    severity: "medium", confidence: 0.5, evidence: ["E1"], local_findings: [] }],
  action_ids: [], limitation_codes: [],
});

describe.skipIf(!PYTHON)("DevicePulse + real security engine (e2e)", () => {
  beforeAll(async () => {
    PORT = await freePort();
    engine = spawn(PYTHON!, ["-m", "uvicorn", "app.main:app", "--port", String(PORT), "--log-level", "warning"], {
      cwd: ENGINE_DIR, env: { ...process.env, SECURITY_ENGINE_TOKEN: INTERNAL_TOKEN, SENTINEL_ENV: "development" }, stdio: ["ignore", "ignore", "pipe"],
    });
    let engineErr = "";
    engine.stderr?.on("data", (d) => { engineErr = (engineErr + String(d)).slice(-2000); });
    await waitReady().catch(() => { throw new Error(`engine failed to start. stderr: ${engineErr || "(none)"}`); });

    db = await createMigratedDb();
    const tdb = new PgliteTenantDb(db);
    const org = (await db.query<{ id: string }>("INSERT INTO organizations (name, slug, zero_retention) VALUES ('dp-e2e','dp-e2e', false) RETURNING id")).rows[0]!.id;
    device = (await createApiKey(tdb, PEPPER, { organizationId: org, name: "phone", role: "DEVICE_CLIENT" })).key;
    developer = (await createApiKey(tdb, PEPPER, { organizationId: org, name: "dev", role: "DEVELOPER" })).key;

    provider = new FakeProvider("gemini");
    const scanner = new HttpSecurityClient({ baseUrl: `http://127.0.0.1:${PORT}`, token: INTERNAL_TOKEN, timeoutMs: 3000 });
    const router = new AiRouter({ sleep: async () => {} }).register(provider);
    const routers = new StaticRouterSource(router);
    const events = new PgEventSink(tdb); const policies = new PgPolicyRepository(tdb); const repo = new PgDevicePulseRepository(tdb);
    const secureAi = new SecureAiService({ scanner, router, routers, policies, events });
    const dpConfig = { ...TEST_CONFIG.devicepulse, provider: "gemini" };
    app = buildApp({
      config: { ...TEST_CONFIG, apiKeyPepper: PEPPER, devicepulse: dpConfig }, scanner, events, policies, auditLog: new PgAuditLogWriter(tdb),
      auth: new DbApiKeyAuthenticator(tdb, PEPPER), service: secureAi, ping: () => tdb.ping(),
      devicepulse: { service: new DevicePulseService({ config: dpConfig, secureAi, routers, scanner, repo }), repo },
    }, { logger: false });
  }, 90_000);

  afterAll(async () => { await app?.close(); engine?.kill(); await db?.close(); });

  it("health reports remote analysis available with the real engine", async () => {
    expect((await app.inject({ method: "GET", url: "/v1/devicepulse/health" })).json()).toMatchObject({ status: "ok", remote_analysis: "available" });
  });

  it.each(DIAGNOSTIC_TYPES)("%s: the worst-case prompt passes the real detectors and the reply is returned", async (type) => {
    provider.received.length = 0;
    provider.reply = genericReply;
    const res = await explain(worstCase(type));
    expect(res.statusCode, res.body).toBe(200);
    expect(ExplainResponseSchema.safeParse(res.json()).success).toBe(true);
    expect(provider.received).toHaveLength(1);
    const { rows } = await db.query<{ action: string; application: string }>(
      "SELECT action, application FROM security_events WHERE event_type = 'ai_request' ORDER BY \"timestamp\" DESC LIMIT 1");
    expect(rows[0]).toEqual({ action: "ALLOW", application: "devicepulse" });
  });

  it("a credential in the model's reply is blocked by the real engine and never reaches the app", async () => {
    provider.reply = () => modelReply({ summary: `Use the key ${AWS_KEY} to unlock battery mode.` });
    const res = await explain(explainRequest());
    expect(res.statusCode).toBe(422);
    expect(res.json().error).toBe("blocked_by_security_policy");
    expect(res.body).not.toContain(AWS_KEY);
  });

  it("personal data in the model's reply never reaches the app", async () => {
    // Measured behaviour: the baseline policy MASKs the email to "j***@example.com"; the masked form still contains a domain,
    // which the model-output rules forbid (no web addresses in app-facing text), so the whole reply is discarded.
    provider.reply = () => modelReply({ summary: `Email ${EMAIL} to book a battery check.` });
    const res = await explain(explainRequest());
    expect(res.statusCode).toBe(502);
    expect(res.json().error).toBe("model_response_invalid");
    expect(res.body).not.toContain(EMAIL);
    expect(res.body).not.toContain("example.com");
  });

  it("feedback and erasure work against real authentication and Postgres", async () => {
    provider.reply = () => modelReply();
    const id = (await explain(explainRequest())).json().request_id as string;
    const fb = await app.inject({ method: "POST", url: "/v1/devicepulse/diagnostics/feedback", headers: H(device),
      payload: { schema_version: "1.0", request_id: id, rating: "helpful", consent_to_store: true } });
    expect(fb.statusCode).toBe(201);
    const del = await app.inject({ method: "DELETE", url: "/v1/devicepulse/data", headers: H(device) });
    expect(del.statusCode).toBe(200);
    expect(del.json().deleted.feedback).toBe(1);
    expect(del.json().deleted.requests).toBeGreaterThanOrEqual(1);
    expect(Number((await db.query<{ n: number }>("SELECT count(*)::int AS n FROM devicepulse_requests")).rows[0]!.n)).toBe(0);
    const { rows } = await db.query<{ action: string; metadata: Record<string, unknown> }>("SELECT action, metadata FROM audit_logs WHERE action = 'devicepulse.data_deleted'");
    expect(rows).toHaveLength(1);
  });

  it("a DEVICE_CLIENT key is refused by the general AI proxy; a DEVELOPER key is refused by DevicePulse", async () => {
    const chat = await app.inject({ method: "POST", url: "/v1/ai/chat", headers: H(device), payload: { provider: "gemini", messages: [{ role: "user", content: "hi" }] } });
    expect(chat.statusCode).toBe(403);
    expect((await explain(explainRequest(), developer)).statusCode).toBe(403);
  });

  it("FAILS CLOSED when the engine dies: 503 security_unavailable and the model is not called", async () => {
    engine.kill();
    await new Promise((r) => setTimeout(r, 500));
    provider.received.length = 0;
    const res = await explain(explainRequest());
    expect(res.statusCode).toBe(503);
    expect(res.json()).toMatchObject({ error: "security_unavailable", retryable: true });
    expect(provider.received).toHaveLength(0);
  });
});
