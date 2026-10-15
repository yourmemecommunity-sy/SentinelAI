import { z } from "zod";
import {
  ACTION_IDS, DIAGNOSTICS, FINDING_SEVERITIES, LIMITS, PROCESSING_STATUSES, type ActionId, type DiagnosticType, type ExplainFinding,
  type LimitationCode, type ProcessingStatus,
} from "@sentinelai/devicepulse-contracts";
import { isCleanText } from "../validators/schemas.js";
import { MODEL_LIMITATION_CODES, type Aliases } from "./prompt.js";

/**
 * What the model must return (see prompt.ts). Unknown keys are dropped, never forwarded. Text limits are the response
 * limits; anything longer is rejected rather than truncated (a truncated sentence can change its meaning).
 */
const Text = (max: number) => z.string().transform((s) => s.replace(/\s+/g, " ").trim()).pipe(z.string().min(1).max(max));
const ModelOutputSchema = z.object({
  status: z.enum(PROCESSING_STATUSES),
  summary: Text(LIMITS.summaryMaxChars),
  overall_confidence: z.number().min(0).max(1),
  findings: z.array(z.object({
    title: Text(LIMITS.findingTitleMaxChars),
    explanation: Text(LIMITS.findingExplanationMaxChars),
    severity: z.enum(FINDING_SEVERITIES),
    confidence: z.number().min(0).max(1),
    evidence: z.array(z.string()).min(1).max(LIMITS.maxEvidenceIdsPerFinding),
    local_findings: z.array(z.string()).max(LIMITS.maxLocalFindings).default([]),
  })).max(LIMITS.maxResponseFindings),
  limitation_codes: z.array(z.string()).max(10).default([]),
  // Up to the size of the largest approved list; trimmed to the response limit after every id has been checked.
  action_ids: z.array(z.string()).max(ACTION_IDS.length).default([]),
});

export interface ValidatedExplanation {
  status: ProcessingStatus;
  summary: string;
  overallConfidence: number;
  findings: ExplainFinding[];
  limitations: LimitationCode[];
  actions: ActionId[];
}

/** Why a model reply was rejected. Internal: logged as a reason code, never returned to the client in detail. */
export type RejectReason =
  | "not_json" | "schema" | "unsafe_text" | "fabricated_evidence" | "unknown_local_finding" | "unapproved_action"
  | "unknown_limitation" | "no_findings";

/** Links, web addresses and markup are never shown in the app: a manipulated model could use them for phishing. */
const UNSAFE = /(https?:|ftp:|www\.|<\/?[a-z!]|\]\(|```|\b[a-z0-9-]+\.(?:com|net|org|io|app|info|biz|xyz|ru|cn|ly|gl|me)\b)/i;
const safe = (s: string): boolean => isCleanText(s) && !UNSAFE.test(s);

function unwrapJson(raw: string): string {
  const t = raw.trim();
  const fenced = /^```(?:json)?\s*\n?([\s\S]*?)\n?```$/i.exec(t);   // one optional code fence around the whole reply
  return fenced ? fenced[1]!.trim() : t;
}

/**
 * Validates the (already output-scanned) model reply against what was actually sent. The whole reply is rejected on the
 * first violation: a model that cites evidence it was never given, or proposes an action outside the approved list, is not
 * trusted for the rest of its answer either.
 */
export function validateModelOutput(raw: string, type: DiagnosticType, aliases: Aliases):
  { ok: true; value: ValidatedExplanation } | { ok: false; reason: RejectReason } {
  let json: unknown;
  try { json = JSON.parse(unwrapJson(raw)); } catch { return { ok: false, reason: "not_json" }; }
  const parsed = ModelOutputSchema.safeParse(json);
  if (!parsed.success) return { ok: false, reason: "schema" };
  const o = parsed.data;

  if (![o.summary, ...o.findings.flatMap((f) => [f.title, f.explanation])].every(safe)) return { ok: false, reason: "unsafe_text" };
  if (o.status === "completed" && o.findings.length === 0) return { ok: false, reason: "no_findings" };

  const findings: ExplainFinding[] = [];
  for (const [i, f] of o.findings.entries()) {
    const evidence = [...new Set(f.evidence)];
    if (!evidence.every((a) => aliases.evidence.has(a))) return { ok: false, reason: "fabricated_evidence" };
    const local = [...new Set(f.local_findings)];
    if (!local.every((a) => aliases.localFindings.has(a))) return { ok: false, reason: "unknown_local_finding" };
    findings.push({
      finding_id: `f${i + 1}`, title: f.title, explanation: f.explanation, severity: f.severity, confidence: round2(f.confidence),
      evidence_ids: evidence.map((a) => aliases.evidence.get(a)!),
      related_local_finding_ids: local.map((a) => aliases.localFindings.get(a)!),
    });
  }

  const allowedActions: readonly string[] = DIAGNOSTICS[type].actions;
  const actions = [...new Set(o.action_ids)];
  if (!actions.every((a) => allowedActions.includes(a) && (ACTION_IDS as readonly string[]).includes(a))) return { ok: false, reason: "unapproved_action" };
  // Every id is approved; keeping the model's first N only shortens the list (small models tend to return all of them).
  actions.splice(LIMITS.maxRecommendedActions);

  const modelLimits = [...new Set(o.limitation_codes)];
  if (!modelLimits.every((c) => (MODEL_LIMITATION_CODES as readonly string[]).includes(c))) return { ok: false, reason: "unknown_limitation" };
  const limitations: LimitationCode[] = ["model_generated_explanation", "model_confidence_uncalibrated", ...(modelLimits as LimitationCode[])];
  if (o.status === "insufficient_data" && !limitations.includes("insufficient_observations")) limitations.push("insufficient_observations");

  return {
    ok: true,
    value: { status: o.status, summary: o.summary, overallConfidence: round2(o.overall_confidence), findings, limitations, actions: actions as ActionId[] },
  };
}

const round2 = (v: number): number => Math.round(v * 100) / 100;
