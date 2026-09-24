import type { Action, Direction, Policy, RequestContext, ScanRequest, ScanResult } from "@sentinelai/shared-types";
import { ProviderError, UnknownProviderError, type AiRouter, type ChatMessage } from "@sentinelai/ai-router";
import { eventFromScan, type EventSink, type EventType } from "../events/eventSink.js";
import type { PolicyRepository } from "../repositories/policyRepository.js";
import { findTokens, hydrateText } from "../streaming/tokenWindow.js";
import type { TokenVault } from "../security/tokenVault.js";
import type { Principal } from "../security/rbac.js";
import { failClosedResult, withholdsContent, type SecurityScanner } from "../security/securityClient.js";
import type { RouterSource } from "../providers/orgRouters.js";

export interface RequestMeta {
  application?: string | undefined; team?: string | undefined; environment?: string | undefined;
  model?: string | undefined; ip?: string | undefined;
  /** Token-vault session id (already derived from the principal). Present -> TOKENIZE actions are reversible within this session. */
  vaultSession?: string | undefined;
}

export interface ScanOutcome { scan: ScanResult; eventId: string | null; auditFailed: boolean }

export type ChatOutcome =
  | { kind: "ok"; provider: string; model: string; content: string; input: OutcomeSummary; output: OutcomeSummary; hydration?: "applied" | "degraded" }
  | { kind: "blocked"; stage: "input" | "output"; decision: Action; failedClosed: boolean; reason: string | null; eventId: string | null }
  | { kind: "provider_error"; code: string; eventId: string | null }
  | { kind: "audit_unavailable"; stage: "input" | "output" };

export interface OutcomeSummary { decision: Action; riskLevel: string; eventId: string }

const RESTRICTIVENESS: Action[] = ["ALLOW", "HASH", "MASK", "TOKENIZE", "REDACT", "QUARANTINE", "BLOCK"];
const rank = (a: Action) => RESTRICTIVENESS.indexOf(a);

/** Combine several scans (one per message) into one: worst decision/risk, union of detections, no text. */
export function aggregate(scans: ScanResult[]): ScanResult {
  // Worst = most restrictive decision, ties broken by higher risk score.
  const worst = scans.reduce((a, b) => (rank(b.decision) - rank(a.decision) || b.risk.risk_score - a.risk.risk_score) > 0 ? b : a);
  const failed = scans.find((s) => s.failed_closed);
  return {
    ...worst, failed_closed: !!failed, fail_closed_reason: failed?.fail_closed_reason ?? null,
    detections: scans.flatMap((s) => s.detections),
    entity_actions: scans.flatMap((s) => s.entity_actions),
    sanitized_text: null,
    latency_ms: scans.reduce((n, s) => n + s.latency_ms, 0),
  };
}

export interface SecureAiDeps {
  scanner: SecurityScanner;
  /** Operator-configured providers. Used for every organization unless `routers` is given. */
  router: AiRouter;
  /** Per-organization routing (organization keys / disabled providers). Overrides `router` when present. */
  routers?: RouterSource | undefined;
  policies: PolicyRepository;
  events: EventSink;
  /** Token vault for hydrating tokens in replies. Absent -> replies are returned exactly as scanned. */
  vault?: TokenVault | undefined;
}

/** Result of the input half of the pipeline (shared by chat and streaming). */
export type Screened =
  | { kind: "ready"; sanitized: ChatMessage[]; policy: Policy | undefined; inScan: ScanResult; inEventId: string; router: AiRouter }
  | Extract<ChatOutcome, { kind: "blocked" | "audit_unavailable" }>;

export class SecureAiService {
  constructor(private readonly d: SecureAiDeps) {}

  private async policyFor(orgId: string): Promise<{ policy?: Policy; failed?: string }> {
    try {
      const policy = await this.d.policies.getEffectivePolicy(orgId);
      return policy ? { policy } : {};
    } catch { return { failed: "policy_unavailable" }; }
  }

  private scanRequest(p: Principal, text: string, direction: Direction, meta: RequestMeta, provider: string | null, policy?: Policy): ScanRequest {
    return {
      text, direction, organization_id: p.organizationId,
      context: {
        user_id: p.userId ?? (p.apiKeyId ? `api_key:${p.apiKeyId}` : undefined),
        ...(meta.application ? { application: meta.application } : {}), ...(meta.team ? { team: meta.team } : {}),
        ...(provider ? { provider } : {}), ...(meta.model ? { model: meta.model } : {}),
        ...(meta.environment ? { environment: meta.environment } : {}), ...(meta.ip ? { ip: meta.ip } : {}),
      } as RequestContext,
      ...(policy ? { policy } : {}),
      // Only prompts write to the vault: model output is never tokenized (it is scanned as-is, then hydrated).
      ...(meta.vaultSession && direction === "INPUT" ? { vault_session: meta.vaultSession } : {}),
    };
  }

  private async audit(p: Principal, scan: ScanResult, direction: Direction, type: EventType, meta: RequestMeta, provider: string | null): Promise<string | null> {
    try {
      return await this.d.events.record(eventFromScan({
        organizationId: p.organizationId, userId: p.userId, apiKeyId: p.apiKeyId, application: meta.application ?? null,
        provider, model: meta.model ?? null, direction, eventType: scan.failed_closed ? "fail_closed" : type,
      }, scan));
    } catch { return null; }
  }

  /** Direct scan API (`/v1/security/scan`, `/check`). */
  async scanText(p: Principal, text: string, direction: Direction, meta: RequestMeta): Promise<ScanOutcome> {
    const { policy, failed } = await this.policyFor(p.organizationId);
    const scan = failed ? failClosedResult(failed) : await this.d.scanner.scan(this.scanRequest(p, text, direction, meta, null, policy));
    const eventId = await this.audit(p, scan, direction, "scan", meta, null);
    // Unauditable scan => fail closed: never hand back sanitized text we could not record.
    if (eventId === null) return { scan: failClosedResult("audit_unavailable", scan.policy_id), eventId: null, auditFailed: true };
    return { scan, eventId, auditFailed: false };
  }

  /**
   * The input half of the pipeline: unknown-provider check, policy fetch, per-message (+ joined) scan, audit. Returns the sanitized
   * messages only when every message has a clean verdict and the event was recorded. Shared by `chat` and streaming.
   */
  async screenInput(p: Principal, provider: string, messages: ChatMessage[], meta: RequestMeta): Promise<Screened> {
    // 0. Resolve this organization's providers. If its configuration cannot be loaded or its stored key cannot be decrypted,
    //    fail closed (never fall back to the operator's key or another processor) and audit it.
    let router: AiRouter;
    try {
      router = this.d.routers ? await this.d.routers.routerFor(p.organizationId) : this.d.router;
    } catch {
      const scan = failClosedResult("provider_config_unavailable");
      const eventId = await this.audit(p, scan, "INPUT", "ai_request", meta, provider);
      return { kind: "blocked", stage: "input", decision: "BLOCK", failedClosed: true, reason: "provider_config_unavailable", eventId };
    }

    // 1. Unknown provider is a security failure, not a 404: block and audit before anything is scanned or sent.
    if (!router.has(provider)) {
      const scan = failClosedResult("unknown_provider");
      const eventId = await this.audit(p, scan, "INPUT", "ai_request", meta, null);
      return { kind: "blocked", stage: "input", decision: "BLOCK", failedClosed: true, reason: "unknown_provider", eventId };
    }

    // 2. Scan every message with the org's policy. Multi-message requests are also scanned joined, so a secret
    //    split across messages is still seen.
    const { policy, failed } = await this.policyFor(p.organizationId);
    const perMessage: ScanResult[] = [];
    let joined: ScanResult | null = null;
    if (failed) perMessage.push(failClosedResult(failed));
    else {
      for (const m of messages) perMessage.push(await this.d.scanner.scan(this.scanRequest(p, m.content, "INPUT", meta, provider, policy)));
      if (messages.length > 1) {
        joined = await this.d.scanner.scan(this.scanRequest(p, messages.map((m) => m.content).join("\n"), "INPUT", meta, provider, policy));
      }
    }
    const inScan = aggregate(joined ? [...perMessage, joined] : perMessage);
    const inDecision = inScan.decision;
    const inEventId = await this.audit(p, inScan, "INPUT", "ai_request", meta, provider);
    if (inEventId === null) return { kind: "audit_unavailable", stage: "input" };
    if (withholdsContent(inDecision) || perMessage.some((s) => s.sanitized_text === null) || (joined !== null && joined.sanitized_text === null)) {
      return { kind: "blocked", stage: "input", decision: withholdsContent(inDecision) ? inDecision : "BLOCK", failedClosed: inScan.failed_closed, reason: inScan.fail_closed_reason ?? null, eventId: inEventId };
    }

    // 3. Only sanitized content leaves the boundary.
    return { kind: "ready", sanitized: messages.map((m, i) => ({ role: m.role, content: perMessage[i]!.sanitized_text as string })), policy, inScan, inEventId, router };
  }

  /** The OUTPUT scan for a given request context (used per segment when streaming). Never throws: failures are fail-closed BLOCKs. */
  outputScanner(p: Principal, provider: string, model: string, meta: RequestMeta, policy: Policy | undefined): (text: string) => Promise<ScanResult> {
    return (text) => this.d.scanner.scan(this.scanRequest(p, text, "OUTPUT", { ...meta, model }, provider, policy));
  }

  /** Records the OUTPUT event. Null when the audit store is unavailable. */
  auditOutput(p: Principal, scan: ScanResult, provider: string, model: string, meta: RequestMeta): Promise<string | null> {
    return this.audit(p, scan, "OUTPUT", "ai_response", { ...meta, model }, provider);
  }

  /** Replaces tokens in already-scanned text with this session's values. Degrades to leaving tokens in place if the vault is down. */
  async hydrate(p: Principal, vaultSession: string, text: string): Promise<{ text: string; degraded: boolean }> {
    const vault = this.d.vault;
    if (!vault || findTokens(text).length === 0) return { text, degraded: false };
    return hydrateText(text, (tokens) => vault.resolve(p.organizationId, vaultSession, tokens));
  }

  async chat(p: Principal, provider: string, messages: ChatMessage[], meta: RequestMeta, opts: { maxOutputTokens?: number; temperature?: number; hydrate?: boolean } = {}): Promise<ChatOutcome> {
    const screened = await this.screenInput(p, provider, messages, meta);
    if (screened.kind !== "ready") return screened;
    const { sanitized, policy, inScan, inEventId, router } = screened;

    let content: string; let model: string;
    try {
      const res = await router.chat(provider, { messages: sanitized, ...(meta.model ? { model: meta.model } : {}), ...(opts.maxOutputTokens !== undefined ? { maxOutputTokens: opts.maxOutputTokens } : {}), ...(opts.temperature !== undefined ? { temperature: opts.temperature } : {}) });
      content = res.content; model = res.model;
    } catch (err) {
      if (err instanceof UnknownProviderError) return { kind: "blocked", stage: "input", decision: "BLOCK", failedClosed: true, reason: "unknown_provider", eventId: inEventId };
      const code = err instanceof ProviderError ? err.code : "unavailable";
      return { kind: "provider_error", code, eventId: inEventId };
    }

    // 4. Scan the model's response before the caller sees it.
    const outScan = await this.outputScanner(p, provider, model, meta, policy)(content);
    const outEventId = await this.auditOutput(p, outScan, provider, model, meta);
    if (outEventId === null) return { kind: "audit_unavailable", stage: "output" };
    if (withholdsContent(outScan.decision) || outScan.sanitized_text === null) {
      return { kind: "blocked", stage: "output", decision: withholdsContent(outScan.decision) ? outScan.decision : "BLOCK", failedClosed: outScan.failed_closed, reason: outScan.fail_closed_reason ?? null, eventId: outEventId };
    }

    // 5. Hydrate AFTER the scan: the scan saw tokens, not the caller's own data, and hydrated values are never rescanned
    //    (rescanning would block or mask exactly what the policy chose to tokenize for this caller).
    let text = outScan.sanitized_text; let hydration: "applied" | "degraded" | undefined;
    if (meta.vaultSession && this.d.vault && opts.hydrate !== false) {
      const h = await this.hydrate(p, meta.vaultSession, text);
      text = h.text; hydration = h.degraded ? "degraded" : "applied";
    }
    return {
      kind: "ok", provider, model, content: text,
      input: { decision: inScan.decision, riskLevel: inScan.risk.risk_level, eventId: inEventId },
      output: { decision: outScan.decision, riskLevel: outScan.risk.risk_level, eventId: outEventId },
      ...(hydration ? { hydration } : {}),
    };
  }
}
