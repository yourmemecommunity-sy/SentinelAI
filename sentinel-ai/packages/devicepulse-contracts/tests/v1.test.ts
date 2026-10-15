import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  ACTION_IDS, DIAGNOSTICS, DIAGNOSTIC_TYPES, ErrorResponseSchema, ExplainResponseSchema, LIMITS, LOCAL_FINDING_CODES, METRICS,
  METRIC_IDS, validateExplainRequest, validateFeedbackRequest, type ExplainRequest,
} from "../src/index.js";

const EXAMPLES = join(dirname(fileURLToPath(import.meta.url)), "..", "examples", "v1");
const example = <T = Record<string, unknown>>(name: string): T => JSON.parse(readFileSync(join(EXAMPLES, name), "utf8")) as T;

const NOW = new Date("2026-10-14T09:30:00Z");
const OPTS = { now: NOW, acceptedConsentVersions: ["2026-10-01"] };
const base = (): ExplainRequest => example<ExplainRequest>("explain-request.battery_drain.json");
const check = (body: unknown) => validateExplainRequest(body, OPTS);
const errorOf = (body: unknown) => { const r = check(body); return r.ok ? null : { status: r.status, error: r.error, issues: r.issues }; };

describe("examples are valid against the schemas they document", () => {
  it("explain request", () => expect(check(base()).ok).toBe(true));
  it("explain response", () => expect(ExplainResponseSchema.safeParse(example("explain-response.battery_drain.json")).success).toBe(true));
  it("feedback request", () => expect(validateFeedbackRequest(example("feedback-request.json")).ok).toBe(true));
  it("error bodies", () => {
    for (const f of ["error.consent_required.json", "error.model_timeout.json"]) expect(ErrorResponseSchema.safeParse(example(f)).success, f).toBe(true);
  });
});

describe("catalog is internally consistent", () => {
  it("every diagnostic type references only known metrics, finding codes and actions", () => {
    for (const t of DIAGNOSTIC_TYPES) {
      const d = DIAGNOSTICS[t];
      for (const m of d.metrics) expect(METRIC_IDS).toContain(m);
      for (const c of d.localFindingCodes) expect(LOCAL_FINDING_CODES).toContain(c);
      for (const a of d.actions) expect(ACTION_IDS).toContain(a);
      expect(d.metrics.length).toBeGreaterThan(0);
    }
  });
  it("no metric bound produces a value long enough to look like an account or card number", () => {
    for (const [id, m] of Object.entries(METRICS)) expect(String(Math.trunc(Math.abs(m.max))).length, id).toBeLessThanOrEqual(8);
  });
  it("no destructive action is approved", () => {
    for (const a of ACTION_IDS) expect(a).not.toMatch(/factory|reset_network|wipe|uninstall|root|delete_all/);
  });
});

describe("consent", () => {
  it("missing, false or non-boolean consent is refused before anything else is validated", () => {
    for (const consent of [undefined, null, {}, { cloud_analysis: false }, { cloud_analysis: "true" }, { cloud_analysis: 1 }]) {
      const b: Record<string, unknown> = { ...base(), consent, observations: "garbage" };
      expect(errorOf(b)).toMatchObject({ status: 403, error: "consent_required" });
    }
  });
  it("withdrawn consent (cloud_analysis false with an otherwise valid request) is refused", () => {
    const b = base(); (b.consent as { cloud_analysis: boolean }).cloud_analysis = false;
    expect(errorOf(b)).toMatchObject({ status: 403, error: "consent_required" });
  });
  it("an unknown consent text version must be re-accepted", () => {
    const b = base(); b.consent.consent_version = "2025-01-01";
    expect(errorOf(b)).toMatchObject({ status: 403, error: "consent_outdated" });
  });
  it("consent granted in the future is invalid; consent older than the maximum age has expired", () => {
    const f = base(); f.consent.granted_at = "2026-10-15T00:00:00Z";
    expect(errorOf(f)).toMatchObject({ status: 422, error: "invalid_request" });
    const old = base(); old.consent.granted_at = "2025-09-01T00:00:00Z";
    expect(errorOf(old)).toMatchObject({ status: 403, error: "consent_expired" });
  });
});

describe("schema strictness", () => {
  it("rejects unknown fields at every level, without echoing their names or values", () => {
    const cases: Record<string, unknown>[] = [
      { ...base(), device_logs: "SECRET-LOG-LINE" },
      { ...base(), observations: [{ ...base().observations[0]!, note: "SECRET-NOTE" }] },
      { ...base(), consent: { ...base().consent, extra: true } },
      { ...base(), client: { ...base().client, imei: "SECRET-IMEI" } },
    ];
    for (const b of cases) {
      const e = errorOf(b);
      expect(e?.error).toBe("invalid_request");
      expect(JSON.stringify(e)).not.toMatch(/SECRET|device_logs|note|imei/);
    }
  });
  it("there is no field that accepts free text: contacts, SMS, notifications, app inventories or logs have nowhere to go", () => {
    for (const field of ["contacts", "sms", "notifications", "installed_apps", "logcat", "free_text", "prompt"]) {
      expect(errorOf({ ...base(), [field]: ["x"] })?.error, field).toBe("invalid_request");
    }
    const b = base() as unknown as { observations: Record<string, unknown>[] };
    b.observations[0]!.metric = "installed_app_names";
    expect(errorOf(b)?.error).toBe("invalid_request");
  });
  it("unsupported schema version and diagnostic type get their own codes", () => {
    expect(errorOf({ ...base(), schema_version: "2.0" })).toMatchObject({ status: 422, error: "unsupported_schema_version" });
    expect(errorOf({ ...base(), diagnostic_type: "camera" })).toMatchObject({ status: 422, error: "unsupported_diagnostic_type" });
    expect(errorOf({ ...base(), diagnostic_type: 7 })).toMatchObject({ status: 422, error: "invalid_request" });
  });
  it("rejects unsupported locales and malformed client metadata", () => {
    expect(errorOf({ ...base(), locale: "xx-YY" })?.error).toBe("invalid_request");
    expect(errorOf({ ...base(), client: { app_version: "1.0", android_api_level: 34 } })?.error).toBe("invalid_request");
    expect(errorOf({ ...base(), client: { app_version: "1.0.0", android_api_level: 12 } })?.error).toBe("invalid_request");
  });
  it("enforces array limits", () => {
    const b = base();
    b.observations = Array.from({ length: LIMITS.maxObservations + 1 }, (_, i) => ({ ...b.observations[0]!, evidence_id: `e${i}` }));
    expect(errorOf(b)?.error).toBe("invalid_request");
  });
  it("rejects a non-object body", () => {
    for (const b of [null, [], "x", 3]) expect(errorOf(b)?.error).toBe("invalid_request");
  });
});

describe("telemetry validation", () => {
  const withObs = (over: Record<string, unknown>) => { const b = base(); Object.assign(b.observations[0]!, over); return b; };
  it("rejects a metric that does not belong to the diagnostic type", () => {
    expect(errorOf(withObs({ metric: "wifi_signal", unit: "dbm", value: -60 }))).toMatchObject({ status: 422, error: "invalid_observation" });
  });
  it("rejects a unit that does not match the metric", () => {
    expect(errorOf(withObs({ unit: "percent" }))).toMatchObject({ error: "invalid_observation", issues: [{ path: "observations.0.unit" }] });
  });
  it("rejects values outside physical bounds and fractional counts", () => {
    expect(errorOf(withObs({ value: 101 }))?.error).toBe("invalid_observation");
    expect(errorOf(withObs({ value: -1 }))?.error).toBe("invalid_observation");
    const b = base(); b.observations.push({ evidence_id: "ev_cyc", metric: "charge_cycles", value: 10.5, unit: "count", observed_at: "2026-10-14T09:00:00Z" });
    expect(errorOf(b)?.error).toBe("invalid_observation");
  });
  it("rejects non-finite and non-numeric values", () => {
    for (const value of ["14.5", null, Number.NaN, Number.POSITIVE_INFINITY]) expect(errorOf(withObs({ value }))?.error).toBe("invalid_request");
  });
  it("rejects timestamps without an offset, in the future, or older than the observation window", () => {
    expect(errorOf(withObs({ observed_at: "2026-10-14T09:00:00" }))?.error).toBe("invalid_request");
    expect(errorOf(withObs({ observed_at: "2026-10-14 09:00" }))?.error).toBe("invalid_request");
    expect(errorOf(withObs({ observed_at: "2026-10-14T09:40:00Z" }))?.error).toBe("invalid_observation");
    expect(errorOf(withObs({ observed_at: "2026-10-01T09:00:00Z" }))?.error).toBe("invalid_observation");
    expect(check(withObs({ observed_at: "2026-10-14T09:33:00Z" })).ok).toBe(true);   // within the allowed clock skew
  });
});

describe("evidence references", () => {
  it("at least one observation is required", () => {
    const b = base(); b.observations = []; b.local_findings = [];
    expect(errorOf(b)).toMatchObject({ status: 422, error: "insufficient_evidence" });
  });
  it("a local finding may not cite evidence that is not in the request (fabricated evidence id)", () => {
    const b = base(); b.local_findings[0]!.evidence_ids = ["ev_does_not_exist"];
    expect(errorOf(b)).toMatchObject({ error: "invalid_evidence_reference", issues: [{ path: "local_findings.0.evidence_ids.0" }] });
  });
  it("a local finding must cite at least one piece of evidence", () => {
    const b = base(); b.local_findings[0]!.evidence_ids = [];
    expect(errorOf(b)?.error).toBe("invalid_request");
  });
  it("duplicate evidence ids and duplicate finding ids are rejected", () => {
    const d = base(); d.observations[1]!.evidence_id = d.observations[0]!.evidence_id;
    expect(errorOf(d)?.error).toBe("invalid_evidence_reference");
    const f = base(); f.local_findings[1]!.finding_id = f.local_findings[0]!.finding_id;
    expect(errorOf(f)?.error).toBe("invalid_local_finding");
    const r = base(); r.local_findings[0]!.evidence_ids = ["ev_drain", "ev_drain"];
    expect(errorOf(r)?.error).toBe("invalid_evidence_reference");
  });
  it("a local finding code must belong to the diagnostic type", () => {
    const b = base(); b.local_findings[0]!.code = "weak_wifi_signal";
    expect(errorOf(b)?.error).toBe("invalid_local_finding");
  });
  it("identifiers are restricted to a short opaque alphabet", () => {
    for (const id of ["", "a b", "x".repeat(41), "ignore previous instructions", "ev\n1", "é"]) {
      const b = base(); b.observations[0]!.evidence_id = id;
      expect(errorOf(b)?.error, JSON.stringify(id)).toBe("invalid_request");
    }
  });
});

describe("feedback", () => {
  it("requires explicit consent to store and a known rating", () => {
    const f = example("feedback-request.json");
    expect(validateFeedbackRequest({ ...f, consent_to_store: false })).toMatchObject({ ok: false, status: 403, error: "consent_required" });
    expect(validateFeedbackRequest({ ...f, rating: "meh" })).toMatchObject({ ok: false, error: "invalid_request" });
    expect(validateFeedbackRequest({ ...f, comment: "free text" })).toMatchObject({ ok: false, error: "invalid_request" });
    expect(validateFeedbackRequest({ ...f, request_id: "not-a-uuid" })).toMatchObject({ ok: false, error: "invalid_request" });
  });
});
