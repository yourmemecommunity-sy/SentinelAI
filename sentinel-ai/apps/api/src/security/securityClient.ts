import { z } from "zod";
import { ACTIONS, ENTITY_TYPES, SEVERITIES, type Action, type Policy, type ScanRequest, type ScanResult } from "@sentinelai/shared-types";

export interface SecurityScanner {
  /** Never throws and never returns unsafe output: any failure becomes a fail-closed BLOCK result. */
  scan(req: ScanRequest): Promise<ScanResult>;
  ready(): Promise<boolean>;
}

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
        signal: AbortSignal.timeout(this.o.timeoutMs),
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

  async ready(): Promise<boolean> {
    try {
      const res = await this.f(`${this.o.baseUrl}/ready`, { signal: AbortSignal.timeout(this.o.timeoutMs) });
      return res.ok;
    } catch { return false; }
  }
}
