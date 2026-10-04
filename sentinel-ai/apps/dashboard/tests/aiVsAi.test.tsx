// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AsrTrend } from "@/components/charts/AsrTrend";
import { ExplanationPanel, summarize } from "@/components/security-events/ExplanationPanel";
import { isAllowedProxy } from "@/lib/api/bff";
import type { Explanation, RedTeamRound } from "@/types/api";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const U = "11111111-1111-4111-8111-111111111111";
const expl = (over: Partial<Explanation> = {}): Explanation => ({
  decided_by: "judge", tier: 3, detectors_fired: [{ detector: "llm_judge", entity: "JAILBREAK", count: 1, max_confidence: 0.9, tier: 3 }],
  classifier: { model: "clf", score: 0.512, threshold: 0.5, band_low: 0.2, band_high: 0.9, band: "uncertain" },
  judge: { called: true, cached: false, skipped_reason: null, verdict: "attack", category: "jailbreak", confidence: 0.9, reason: null,
    model: "claude-haiku-4-5", prompt_version: "judge-2026.10.1", latency_ms: 700 },
  policy: { policy_id: "sentinelai-baseline", policy_version: 1, deciding_entity: "JAILBREAK", deciding_action: "BLOCK", source: "baseline" },
  versions: { engine: "2026.10.1-cascade", classifier: "clf" }, content_hmac: "a".repeat(64), ...over,
});

describe("why was this blocked", () => {
  it("says in one sentence which tier decided and where the action came from", () => {
    expect(summarize(expl(), "BLOCK")).toMatch(/BLOCK by the AI judge, after the local classifier was unsure: JAILBREAK was detected.*baseline/);
    expect(summarize(expl({ decided_by: "classifier", tier: 2 }), "BLOCK")).toContain("local prompt-injection classifier");
    expect(summarize(expl({ decided_by: "fail_closed", tier: 3 }), "BLOCK")).toContain("fails closed");
  });

  it("renders tiers, scores, the judge verdict and the recorded versions", () => {
    render(<ExplanationPanel eventId={U} explanation={expl()} action="BLOCK" />);
    expect(screen.getByText("AI judge (tier 3) - decided")).toBeTruthy();
    expect(screen.getByText("0.512")).toBeTruthy();
    expect(screen.getByText(/only Sentinel's masked text was sent/)).toBeTruthy();
    expect(screen.getByText("2026.10.1-cascade")).toBeTruthy();
  });

  it("replays with the pasted text and reports a hash mismatch honestly", async () => {
    const fetch = vi.fn(async () => new Response(JSON.stringify({ event_id: U, content_matches: false, identical: false, recorded_decision: "BLOCK",
      replayed_decision: null, recorded_decided_by: "judge", replayed_decided_by: null, differences: [], versions: [], versions_identical: false,
      judge_source: "not_needed" }), { status: 200 }));
    vi.stubGlobal("fetch", fetch);
    render(<ExplanationPanel eventId={U} explanation={expl()} action="BLOCK" />);
    fireEvent.change(screen.getByLabelText("Original text"), { target: { value: "some other text" } });
    fireEvent.click(screen.getByRole("button", { name: "Replay" }));
    await waitFor(() => expect(screen.getByText(/does not match this event's recorded content hash/)).toBeTruthy());
    expect(fetch).toHaveBeenCalledWith(`/api/proxy/events/${U}/replay`, expect.objectContaining({ method: "POST", body: JSON.stringify({ text: "some other text" }) }));
  });
});

describe("red team trend", () => {
  it("draws one point per round with an accessible text alternative", () => {
    const r = (round: number, slipped: number): RedTeamRound => ({ round, dataset_version: "v", generator_model: "g", engine_version: "e",
      attacks: 10, blocked: 10 - slipped, slipped, per_category: {}, examples: [], cost_usd: 0 });
    const { container } = render(<AsrTrend rounds={[r(2, 3), r(1, 6)]} />);
    expect(container.querySelectorAll("circle")).toHaveLength(2);
    expect(screen.getByText(/Round 1: 60.0% of 10 attacks slipped through; Round 2: 30.0%/)).toBeTruthy();
  });
});

describe("proxy allow-list for AI vs AI routes", () => {
  it("exposes exactly replay, red-team rounds (read) and the judge switch", () => {
    for (const [m, p] of [["POST", `events/${U}/replay`], ["GET", "red-team/rounds"], ["GET", "organization/ai-judge"], ["PUT", "organization/ai-judge"]] as const) {
      expect(isAllowedProxy(m, p), `${m} ${p}`).toBe(true);
    }
    // posting rounds is for the red-team harness's API key, not for browsers; no replay on other paths
    for (const [m, p] of [["POST", "red-team/rounds"], ["GET", `events/${U}/replay`], ["POST", "events/x/replay"], ["POST", `events/${U}/../replay`]] as const) {
      expect(isAllowedProxy(m, p), `${m} ${p}`).toBe(false);
    }
  });
});
