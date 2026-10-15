import { describe, expect, it } from "vitest";
import { loadConfig } from "../../src/config/env.js";
import { disclaimersFor } from "../../src/devicepulse/devicePulseService.js";
import { buildPrompt, MODEL_LIMITATION_CODES } from "../../src/devicepulse/prompt.js";
import { explainRequest } from "./helpers.js";

describe("prompt minimization", () => {
  it("replaces every client id with an alias and keeps the mapping", () => {
    const req = explainRequest();
    const { messages, aliases } = buildPrompt(req, new Date());
    expect([...aliases.evidence.entries()]).toEqual([["E1", "ev_drain"], ["E2", "ev_screen"], ["E3", "ev_wake"], ["E4", "ev_temp"]]);
    expect([...aliases.localFindings.entries()]).toEqual([["L1", "lf_drain"], ["L2", "lf_wake"]]);
    const data = JSON.parse(messages[1]!.content) as { observations: { id: string; age_minutes: number }[]; local_findings: { evidence: string[] }[] };
    expect(data.local_findings[1]!.evidence).toEqual(["E3", "E2"]);
    expect(data.observations[0]).toMatchObject({ id: "E1", metric: "battery_drain_rate", value: 14.5, unit: "percent_per_hour" });
    expect(data.observations[0]!.age_minutes).toBeGreaterThanOrEqual(29);
    expect(Object.keys(data).sort()).toEqual(["allowed_action_ids", "allowed_limitation_codes", "android_api_level", "diagnostic_type", "local_findings", "observations"]);
  });

  it("rounds values and never lets the model pick the server-only limitation codes", () => {
    const req = explainRequest(); req.observations[0]!.value = 14.123456;
    const data = JSON.parse(buildPrompt(req, new Date()).messages[1]!.content) as { observations: { value: number }[] };
    expect(data.observations[0]!.value).toBe(14.123);
    expect(MODEL_LIMITATION_CODES).not.toContain("model_generated_explanation");
  });

  it("asks for the requested language", () => {
    const req = explainRequest(); req.locale = "hi-IN";
    expect(buildPrompt(req, new Date()).messages[0]!.content).toContain("Hindi");
  });
});

describe("disclaimers", () => {
  it("adds the safety warning at the temperature and thermal-status thresholds", () => {
    const r = explainRequest();
    expect(disclaimersFor(r, [])).toEqual(["ai_generated_content", "not_professional_repair_advice"]);
    r.observations[3]!.value = 45;
    expect(disclaimersFor(r, [])).toContain("battery_safety_warning");
    const t = explainRequest(); t.local_findings[0]!.code = "high_battery_temperature";
    expect(disclaimersFor(t, [])).toContain("battery_safety_warning");
  });
});

describe("configuration", () => {
  const base = { API_KEY_HASH_PEPPER: "x" };
  it("remote analysis is off unless a provider is named; defaults are conservative", () => {
    const c = loadConfig(base).devicepulse;
    expect(c).toEqual({ provider: undefined, model: undefined, timeoutMs: 20_000, explainPerMinute: 10, consentVersions: ["2026-10-01"], retentionDays: 30 });
    expect(loadConfig({ ...base, DEVICEPULSE_AI_PROVIDER: "" }).devicepulse.provider).toBeUndefined();
  });
  it("parses and validates the DevicePulse settings", () => {
    const c = loadConfig({ ...base, DEVICEPULSE_AI_PROVIDER: "ollama", DEVICEPULSE_AI_MODEL: "qwen2:0.5b", DEVICEPULSE_CONSENT_VERSIONS: "2026-10-01,2027-01-15",
      DEVICEPULSE_TIMEOUT_MS: "5000", DEVICEPULSE_RETENTION_DAYS: "7" }).devicepulse;
    expect(c).toMatchObject({ provider: "ollama", model: "qwen2:0.5b", consentVersions: ["2026-10-01", "2027-01-15"], timeoutMs: 5000, retentionDays: 7 });
    for (const bad of [{ DEVICEPULSE_AI_PROVIDER: "../x" }, { DEVICEPULSE_CONSENT_VERSIONS: "latest" }, { DEVICEPULSE_TIMEOUT_MS: "10" },
      { DEVICEPULSE_RETENTION_DAYS: "0" }, { DEVICEPULSE_AI_MODEL: "bad model" }]) {
      expect(() => loadConfig({ ...base, ...bad }), JSON.stringify(bad)).toThrow();
    }
  });
});
