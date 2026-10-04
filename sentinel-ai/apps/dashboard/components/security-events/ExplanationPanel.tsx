"use client";
import { useState } from "react";
import { Button, Card, Chip, Notice } from "@/components/ui/primitives";
import { api, ApiError } from "@/lib/api/client";
import type { Explanation, ReplayResponse } from "@/types/api";

const TIER_LABEL: Record<number, string> = { 1: "Rules + NER (tier 1)", 2: "Local classifier (tier 2)", 3: "AI judge (tier 3)" };
const SOURCE_LABEL: Record<Explanation["policy"]["source"], string> = {
  policy_rule: "a rule in your organization's policy", baseline: "SentinelAI's baseline policy",
  risk_escalation: "risk scoring, which raised the action above the policy's", no_detection: "nothing being detected",
  fail_closed: "a fail-closed safety rule (a component could not give a trustworthy answer)",
};

/** One plain-language sentence: what decided, and why. */
export function summarize(e: Explanation, action: string): string {
  if (e.decided_by === "fail_closed") return `Blocked because a component could not give a trustworthy answer (tier ${e.tier}); SentinelAI fails closed.`;
  const who = e.decided_by === "rules" ? "the rule and NER detectors" : e.decided_by === "classifier"
    ? "the local prompt-injection classifier" : "the AI judge, after the local classifier was unsure";
  const what = e.policy.deciding_entity ? `${e.policy.deciding_entity} was detected` : "nothing risky was detected";
  return `${action} by ${who}: ${what}, and the action came from ${SOURCE_LABEL[e.policy.source]}.`;
}

export function ExplanationPanel({ eventId, explanation: e, action }: { eventId: string; explanation: Explanation; action: string }) {
  return (
    <Card title={action === "ALLOW" ? "Why was this allowed?" : "Why was this decided?"}>
      <p className="mb-3 text-sm">{summarize(e, action)}</p>
      <ol className="mb-4 flex flex-wrap gap-2 text-xs" aria-label="Detection tiers">
        {[1, 2, 3].map((t) => (
          <li key={t} className={`rounded border px-2 py-1 ${t === e.tier ? "border-indigo-500 bg-indigo-50 font-medium text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300" : "border-slate-200 text-slate-500 dark:border-slate-700"}`}>
            {TIER_LABEL[t]}{t === e.tier ? " - decided" : ""}
          </li>
        ))}
      </ol>
      <dl className="grid gap-2 text-sm md:grid-cols-2">
        <div>
          <dt className="text-slate-500">Detectors that fired</dt>
          <dd>{e.detectors_fired.length ? (
            <ul>{e.detectors_fired.map((d) => <li key={`${d.detector}:${d.entity}`}><Chip>{d.entity}</Chip> {d.detector} &times;{d.count}, confidence {d.max_confidence.toFixed(2)} (tier {d.tier})</li>)}</ul>
          ) : "none"}</dd>
        </div>
        {e.classifier && (
          <div>
            <dt className="text-slate-500">Classifier score</dt>
            <dd>
              <span className="font-mono">{e.classifier.score.toFixed(3)}</span> ({e.classifier.band})
              <span className="block text-xs text-slate-500">
                {e.classifier.band_low !== null ? `uncertain band [${e.classifier.band_low}, ${e.classifier.band_high}) goes to the judge` : `decides alone at ${e.classifier.threshold}`}
              </span>
              {(e.classifier.windows_total ?? 1) > (e.classifier.windows_scored ?? 1) && (
                <span className="block text-xs text-amber-700">long text: the classifier read the start and end ({e.classifier.windows_scored} of {e.classifier.windows_total} windows); rules and NER read all of it</span>
              )}
            </dd>
          </div>
        )}
        {e.judge && (
          <div>
            <dt className="text-slate-500">AI judge</dt>
            <dd>{e.judge.verdict
              ? <>{e.judge.verdict} ({e.judge.category}), confidence {e.judge.confidence?.toFixed(2)}{e.judge.cached ? ", cached verdict" : ""}
                  <span className="block text-xs text-slate-500">only Sentinel's masked text was sent; the judge's wording is not stored</span></>
              : `not called (${e.judge.skipped_reason?.replaceAll("_", " ")})`}</dd>
          </div>
        )}
        <div>
          <dt className="text-slate-500">Policy</dt>
          <dd>{e.policy.policy_id} (v{e.policy.policy_version}): {SOURCE_LABEL[e.policy.source]}</dd>
        </div>
      </dl>
      <details className="mt-3 text-sm">
        <summary className="cursor-pointer text-slate-500">Versions recorded with this decision</summary>
        <dl className="mt-2">{Object.entries(e.versions).map(([k, v]) => (
          <div key={k} className="grid grid-cols-3 gap-2 py-0.5"><dt className="text-slate-500">{k}</dt><dd className="col-span-2 break-all font-mono text-xs">{v}</dd></div>
        ))}</dl>
      </details>
      <Replay eventId={eventId} />
    </Card>
  );
}

function Replay({ eventId }: { eventId: string }) {
  const [text, setText] = useState(""); const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ReplayResponse | null>(null); const [error, setError] = useState<string | null>(null);
  const run = async () => {
    setBusy(true); setError(null); setResult(null);
    try { setResult(await api.post<ReplayResponse>(`events/${eventId}/replay`, { text })); }
    catch (err) { setError(err instanceof ApiError ? `${err.code}${err.message !== err.code ? `: ${err.message}` : ""}` : "Replay failed."); }
    finally { setBusy(false); }
  };
  return (
    <details className="mt-4 border-t border-slate-100 pt-3 dark:border-slate-800">
      <summary className="cursor-pointer text-sm font-medium">Replay this decision</summary>
      <p className="my-2 text-xs text-slate-500">SentinelAI does not keep the original text. Paste it to re-run the decision with the recorded policy, model versions and judge verdict; it is checked against the recorded hash and is not stored.</p>
      <label htmlFor="replay-text" className="sr-only">Original text</label>
      <textarea id="replay-text" value={text} onChange={(ev) => setText(ev.target.value)} rows={4}
        className="w-full rounded border border-slate-300 p-2 text-sm dark:border-slate-700 dark:bg-slate-900" />
      <Button onClick={run} disabled={busy || text.length === 0} className="mt-2">{busy ? "Replaying..." : "Replay"}</Button>
      {error && <Notice>{error}</Notice>}
      {result && (
        <div className="mt-2 text-sm" role="status">
          {!result.content_matches ? <Notice>The text does not match this event's recorded content hash, so nothing was replayed.</Notice> : (
            <>
              <p className={result.identical ? "font-medium text-emerald-700" : "font-medium text-amber-700"}>
                {result.identical ? "Identical decision" : "Different decision"}: recorded {result.recorded_decision} ({result.recorded_decided_by}),
                replayed {result.replayed_decision} ({result.replayed_decided_by}); judge verdict {result.judge_source}.
              </p>
              {result.differences.length > 0 && <ul className="list-disc pl-5">{result.differences.map((d) => <li key={d}>{d}</li>)}</ul>}
              {!result.versions_identical && <p className="text-slate-500">Changed since recording: {result.versions.filter((v) => !v.same).map((v) => v.name).join(", ")}</p>}
            </>
          )}
        </div>
      )}
    </details>
  );
}
