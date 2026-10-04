import { z } from "zod";
import {
  ACTIONS, ENTITY_TYPES, SEVERITIES, type Action, type Direction, type Explanation, type Policy, type RequestContext,
  type ScanRequest, type ScanResult,
} from "@sentinelai/shared-types";

/** Input to the engine's /v1/replay (see services/security-engine/app/replay.py). Read-only on the engine side. */
export interface ReplayRequest {
  text: string;
  organization_id: string;
  direction: Direction;
  context?: RequestContext;
  policy?: Policy;
  recorded: { decision: Action; explanation: Explanation };
  live_judge?: boolean;
}

export interface ReplayResult {
  content_matches: boolean;
  identical: boolean;
  recorded_decision: Action;
  replayed_decision: Action | null;
  recorded_decided_by: string;
  replayed_decided_by: string | null;
  differences: string[];
  versions: { name: string; recorded: string | null; current: string | null; same: boolean }[];
  versions_identical: boolean;
  judge_source: string;
  explanation: Explanation | null;
}

export interface SecurityScanner {
  /** Never throws and never returns unsafe output: any failure becomes a fail-closed BLOCK result. */
  scan(req: ScanRequest): Promise<ScanResult>;
  ready(): Promise<boolean>;
  /** Re-runs a recorded decision. Throws on failure (replay is a diagnostic, nothing fails open). Optional. */
  replay?(req: ReplayRequest): Promise<ReplayResult>;
}

const ExplanationSchema = z.object({
  decided_by: z.enum(["rules", "classifier", "judge", "fail_closed"]),
  tier: z.number().int().min(1).max(3),
  detectors_fired: z.array(z.object({ detector: z.string(), entity: z.enum(ENTITY_TYPES), count: z.number().int(),
    max_confidence: z.number(), tier: z.number().int() })),
  classifier: z.object({ model: z.string(), score: z.number(), threshold: z.number(), band_low: z.number().nullable(),
    band_high: z.number().nullable(), band: z.enum(["attack", "uncertain", "benign"]),
    windows_scored: z.number().int().min(0).optional(), windows_total: z.number().int().min(0).optional() }).nullable().optional(),
  judge: z.object({ called: z.boolean(), cached: z.boolean(), skipped_reason: z.string().nullable(),
    verdict: z.enum(["attack", "benign"]).nullable(), category: z.string().nullable(), confidence: z.number().nullable(),
    reason: z.string().nullable().optional(), model: z.string().nullable(), prompt_version: z.string().nullable(),
    latency_ms: z.number().nullable() }).nullable().optional(),
  policy: z.object({ policy_id: z.string(), policy_version: z.number().int(), deciding_entity: z.enum(ENTITY_TYPES).nullable(),
    deciding_action: z.enum(ACTIONS), source: z.enum(["policy_rule", "baseline", "risk_escalation", "no_detection", "fail_closed"]) }),
  versions: z.record(z.string()),
  content_hmac: z.string().regex(/^[0-9a-f]{64}$/),
});

const WITHHOLDING: ReadonlySet<Action> = new Set<Action>(["BLOCK", "QUARANTINE"]);
export const withholdsContent = (a: Action): boolean => WITHHOLDING.has(a);

const ResultSchema = z.object({
  request_id: z.string(),
  decision: z.enum(ACTIONS),
  failed_closed: z.boolean(),
  fail_closed_reason: z.string().nullable().optional(),
  detections: z.array(z.object({
    entity: z.enum(ENTITY_TYPES), confidence: z.number().min(0).max(1), severity: z.enum(SEVERITIES),
    location: z.object({ start: z.number().int().min(0), end: z.number().int().min(0) }),
    detector: z.string(), detector_version: z.string(), value_digest: z.string().nullable().optional(),
  })),
  entity_actions: z.array(z.object({ entity: z.enum(ENTITY_TYPES), action: z.enum(ACTIONS), count: z.number().int() })),
  risk: z.object({
    risk_score: z.number().int().min(0).max(100), risk_level: z.enum(SEVERITIES), decision: z.enum(ACTIONS),
    factors: z.array(z.object({ name: z.string(), contribution: z.number(), detail: z.string() })),
  }),
  sanitized_text: z.string().nullable(),
  policy_id: z.string(),
  detector_version: z.string(),
  latency_ms: z.number(),
  // Optional for compatibility with engines older than 2026.10; a malformed explanation fails the whole result closed.
  explanation: ExplanationSchema.nullable().optional(),
});

/** A synthetic BLOCK used whenever the gateway cannot obtain a trustworthy decision. */
export function failClosedResult(reason: string, policyId = "unknown"): ScanResult {
  return {
    request_id: `gateway-${crypto.randomUUID()}`, decision: "BLOCK", failed_closed: true, fail_closed_reason: reason,
    detections: [], entity_actions: [],
    risk: { risk_score: 100, risk_level: "CRITICAL", decision: "BLOCK", factors: [{ name: "fail_closed", contribution: 100, detail: reason }] },
    sanitized_text: null, policy_id: policyId, detector_version: "gateway", latency_ms: 0,
  };
}

export interface HttpSecurityClientOptions {
  baseUrl: string;
  token?: string | undefined;
  timeoutMs: number;
  /**
   * Extra time per 1,000 characters of text. The engine's NER layer costs time in proportion to length, and the engine's
   * own budget grows the same way (SECURITY_TIME_BUDGET_PER_KCHAR_MS); this allowance is larger so the engine gives up
   * first and answers with a clear fail-closed reason instead of the gateway timing out. Default 60.
   */
  timeoutPerKcharMs?: number;
  /**
   * Allowance for the engine's tier-2 classifier: per estimated 512-token window (~1,500 characters, rounded up), at most
   * `classifierMaxWindows` windows (the engine scores no more). Defaults 1,800 ms and 4: slightly above the engine's own
   * per-window budget (SENTINEL_CLASSIFIER_MS_PER_WINDOW=1600), so the engine fails closed first with a clear reason.
   */
  classifierMsPerWindow?: number;
  classifierMaxWindows?: number;
  /** Allowance for the engine's optional AI judge (its own timeout is 4 s). Default 4,500 ms. */
  judgeAllowanceMs?: number;
  fetch?: typeof fetch;
}

export class HttpSecurityClient implements SecurityScanner {
  private readonly f: typeof fetch;
  constructor(private readonly o: HttpSecurityClientOptions) { this.f = o.fetch ?? fetch; }

  async scan(req: ScanRequest): Promise<ScanResult> {
    const policyId = (req.policy as Policy | undefined)?.policy_id ?? "sentinelai-baseline";
    let res: Response;
    try {
      res = await this.f(`${this.o.baseUrl}/v1/scan`, {
        method: "POST",
        headers: { "content-type": "application/json", ...(this.o.token ? { "x-internal-token": this.o.token } : {}) },
        body: JSON.stringify(req),
        signal: AbortSignal.timeout(this.timeoutFor(req.text.length)),
      });
    } catch (err) {
      const timeout = err instanceof DOMException && (err.name === "TimeoutError" || err.name === "AbortError");
      return failClosedResult(timeout ? "engine_timeout" : "engine_unreachable", policyId);
    }
    if (!res.ok) return failClosedResult(`engine_http_${res.status}`, policyId);

    let parsed: z.SafeParseReturnType<unknown, z.infer<typeof ResultSchema>>;
    try { parsed = ResultSchema.safeParse(await res.json()); } catch { return failClosedResult("engine_invalid_response", policyId); }
    if (!parsed.success) return failClosedResult("engine_invalid_response", policyId);

    const r = parsed.data;
    // Invariants the engine must uphold; a violation means we cannot trust the response.
    const withheld = withholdsContent(r.decision);
    if (withheld && r.sanitized_text !== null) return failClosedResult("engine_invariant_violation", policyId);
    if (!withheld && r.sanitized_text === null) return failClosedResult("engine_invariant_violation", policyId);
    if (r.failed_closed && r.decision !== "BLOCK") return failClosedResult("engine_invariant_violation", policyId);
    return r as unknown as ScanResult;
  }

  /** Engine time budget mirrored here: base + NER per 1,000 chars + classifier per window (capped). */
  timeoutFor(chars: number): number {
    const windows = Math.min(this.o.classifierMaxWindows ?? 4, Math.max(1, Math.ceil(chars / 1500)));
    return this.o.timeoutMs + (this.o.timeoutPerKcharMs ?? 60) * Math.ceil(chars / 1000) + (this.o.classifierMsPerWindow ?? 1800) * windows
      + (this.o.judgeAllowanceMs ?? 4500);
  }

  async replay(req: ReplayRequest): Promise<ReplayResult> {
    const res = await this.f(`${this.o.baseUrl}/v1/replay`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(this.o.token ? { "x-internal-token": this.o.token } : {}) },
      body: JSON.stringify(req),
      // A replay may call the judge (live_judge) and runs the full pipeline: allow the scan budget plus the judge timeout.
      signal: AbortSignal.timeout(this.timeoutFor(req.text.length) + 5000),
    });
    if (!res.ok) throw new Error(`engine_http_${res.status}`);
    return (await res.json()) as ReplayResult;
  }

  async ready(): Promise<boolean> {
    try {
      const res = await this.f(`${this.o.baseUrl}/ready`, { signal: AbortSignal.timeout(this.o.timeoutMs) });
      return res.ok;
    } catch { return false; }
  }
}
