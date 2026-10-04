import type { TestDb } from "../helpers/testDb.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Explanation } from "@sentinelai/shared-types";
import { PgEventSink, type SecurityEventInput } from "../../src/events/eventSink.js";
import { PgPolicyRepository } from "../../src/repositories/policyRepository.js";
import { createMigratedDb } from "../helpers/testDb.js";
import { PgliteTenantDb } from "../helpers/fakes.js";

let db: TestDb; let tdb: PgliteTenantDb; let org: string;

const explanation: Explanation = {
  decided_by: "judge", tier: 3, detectors_fired: [{ detector: "llm_judge", entity: "JAILBREAK", count: 1, max_confidence: 0.9, tier: 3 }],
  classifier: { model: "clf", score: 0.5, threshold: 0.5, band_low: 0.2, band_high: 0.9, band: "uncertain" },
  judge: { called: true, cached: false, skipped_reason: null, verdict: "attack", category: "jailbreak", confidence: 0.9,
    reason: "the text asks to ignore its rules", model: "claude-haiku-4-5", prompt_version: "judge-2026.10.1", latency_ms: 700 },
  policy: { policy_id: "sentinelai-baseline", policy_version: 1, deciding_entity: "JAILBREAK", deciding_action: "BLOCK", source: "baseline" },
  versions: { engine: "2026.10.1-cascade" }, content_hmac: "b".repeat(64),
};
const event = (over: Partial<SecurityEventInput> = {}): SecurityEventInput => ({
  organizationId: org, userId: null, apiKeyId: null, requestId: "r1", application: null, provider: null, model: null,
  direction: "INPUT", eventType: "scan", riskLevel: "CRITICAL", riskScore: 95, action: "BLOCK", entityTypes: ["JAILBREAK"],
  policyId: "sentinelai-baseline", failedClosed: false, failClosedReason: null, detectorVersion: "v", latencyMs: 3, ...over,
});

beforeAll(async () => {
  db = await createMigratedDb({ allowRealServer: true }); tdb = new PgliteTenantDb(db);
  org = (await db.query<{ id: string }>("INSERT INTO organizations (name, slug) VALUES ('ai-org','ai-org') RETURNING id")).rows[0]!.id;
});
afterAll(async () => { await db.close(); });

describe("explanations in security_events", () => {
  it("are stored without the judge's free-text reason and returned with the event", async () => {
    const sink = new PgEventSink(tdb);
    const id = await sink.record(event({ explanation }));
    const ev = await sink.get(org, id);
    expect(ev?.explanation?.decided_by).toBe("judge");
    expect(ev?.explanation?.judge?.reason).toBeNull();
    expect(JSON.stringify(ev)).not.toContain("ignore its rules");
  });

  it("the database itself refuses an explanation that carries a judge reason", async () => {
    await expect(db.query(
      `INSERT INTO security_events (organization_id, request_id, direction, event_type, risk_level, risk_score, action, policy_id, detector_version, explanation)
       VALUES ($1,'r','INPUT','scan','LOW',1,'ALLOW','p','v',$2)`, [org, JSON.stringify(explanation)])).rejects.toThrow(/explanation_no_judge_reason/);
  });
});

describe("organization switch and recorded policies", () => {
  it("the judge switch defaults on and travels with the effective policy when off", async () => {
    const repo = new PgPolicyRepository(tdb);
    expect(await repo.getExternalJudge(org)).toBe(true);
    expect(await repo.getEffectivePolicy(org)).toBeUndefined(); // baseline, judge allowed: nothing to send
    await repo.setExternalJudge(org, false);
    expect(await repo.getEffectivePolicy(org)).toMatchObject({ policy_id: "sentinelai-baseline", rules: [], external_judge: false });
    await repo.createVersion(org, "acme", [{ entity: "EMAIL", action: "REDACT" }], null);
    expect(await repo.getEffectivePolicy(org)).toMatchObject({ policy_id: "acme@1", external_judge: false });
    await repo.setExternalJudge(org, true);
    expect((await repo.getEffectivePolicy(org))?.external_judge).toBeUndefined();
  });

  it("rebuilds the exact recorded policy versions, even after newer versions exist", async () => {
    const repo = new PgPolicyRepository(tdb);
    await repo.createVersion(org, "acme", [{ entity: "EMAIL", action: "BLOCK" }], null); // acme@2 is now active
    expect(await repo.getRecorded(org, "acme@1")).toMatchObject({ policy_id: "acme@1", rules: [{ entity: "EMAIL", action: "REDACT" }] });
    expect(await repo.getRecorded(org, "sentinelai-baseline")).toBeUndefined();
    expect(await repo.getRecorded(org, "acme@9")).toBeNull();
    expect(await repo.getRecorded(org, "not-a-recorded-id")).toBeNull();
  });
});

describe("red_team_rounds", () => {
  it("is append-only evidence whose counts must add up", async () => {
    const insert = (round: number, blocked: number, slipped: number) => tdb.withTenant(org, (q) => q.query(
      `INSERT INTO red_team_rounds (organization_id, round, dataset_version, generator_model, engine_version, attacks, blocked, slipped, per_category)
       VALUES ($1,$2,'rt-v1','offline-seed','e',$3,$4,$5,'{}')`, [org, round, blocked + slipped, blocked, slipped]));
    await insert(1, 8, 2);
    await expect(tdb.withTenant(org, (q) => q.query(
      `INSERT INTO red_team_rounds (organization_id, round, dataset_version, generator_model, engine_version, attacks, blocked, slipped, per_category)
       VALUES ($1,2,'rt-v1','g','e',10,8,1,'{}')`, [org]))).rejects.toThrow();
    await expect(tdb.withTenant(org, (q) => q.query("UPDATE red_team_rounds SET blocked = 10, slipped = 0"))).rejects.toThrow();
  });
});
