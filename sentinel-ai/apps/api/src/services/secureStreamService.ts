import type { Action } from "@sentinelai/shared-types";
import { ProviderError, UnknownProviderError, type AiRouter, type ChatMessage, type StreamChunk } from "@sentinelai/ai-router";
import type { Principal } from "../security/rbac.js";
import { withholdsContent } from "../security/securityClient.js";
import type { TokenVault } from "../security/tokenVault.js";
import { OutputScreen } from "../streaming/outputScreen.js";
import { TokenWindow } from "../streaming/tokenWindow.js";
import type { ChatOutcome, OutcomeSummary, RequestMeta, SecureAiService } from "./secureAiService.js";

export interface StreamLimits {
  /** Look-ahead characters kept back so a split secret is seen whole before its first half is released. */
  holdBackChars: number;
  minSegmentChars: number;
  /** Abort if the provider goes silent this long between chunks. */
  idleTimeoutMs: number;
  /** Hard cap on one stream's lifetime. */
  maxDurationMs: number;
  maxOutputChars: number;
}

export const DEFAULT_STREAM_LIMITS: StreamLimits = { holdBackChars: 256, minSegmentChars: 64, idleTimeoutMs: 30_000, maxDurationMs: 300_000, maxOutputChars: 200_000 };

export type StreamEvent =
  | { type: "delta"; text: string }
  | { type: "done"; provider: string; model: string; security: { input: OutcomeSummary; output: OutcomeSummary }; hydration: "off" | "applied" | "degraded" }
  | { type: "error"; error: "blocked"; stage: "output"; decision: Action; failedClosed: boolean; reason: string | null; eventId: string | null }
  | { type: "error"; error: "provider_error"; code: string; eventId: string | null }
  | { type: "error"; error: "audit_unavailable" | "idle_timeout" | "max_duration" };

export interface StreamOptions {
  maxOutputTokens?: number | undefined; temperature?: number | undefined;
  /** Hydrate tokens in the reply (default true when a vault session exists). */
  hydrate?: boolean | undefined;
  /** "buffered" releases nothing until the whole reply has been scanned. */
  mode?: "holdback" | "buffered" | undefined;
  /** Aborted when the client disconnects. */
  signal: AbortSignal;
  /** Vault session for this stream, and whether it should be deleted afterwards. */
  vaultSession?: { id: string; ephemeral: boolean } | undefined;
}

export type OpenOutcome =
  | Extract<ChatOutcome, { kind: "blocked" | "audit_unavailable" }>
  | { kind: "stream"; events: AsyncGenerator<StreamEvent, void, void>; dispose: () => Promise<void> };

class IdleTimeout extends Error {}

/** Next chunk, or IdleTimeout if the provider stays silent. */
async function nextWithIdle<T>(it: AsyncIterator<T>, ms: number): Promise<IteratorResult<T>> {
  let timer: NodeJS.Timeout | undefined;
  const idle = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new IdleTimeout()), ms); });
  const next = it.next();
  next.catch(() => undefined);      // if the idle timer wins, a later rejection (e.g. from the abort we trigger) must not go unhandled
  try { return await Promise.race([next, idle]); } finally { clearTimeout(timer); }
}

/** The provider is resolved per request by `service.screenInput` (per-organization routing); `router` is no longer consulted. */
export interface SecureStreamDeps { service: SecureAiService; router?: AiRouter; vault?: TokenVault | undefined; limits?: Partial<StreamLimits> }

/**
 * Streaming variant of the secure pipeline:
 *   input screening (identical to chat) -> provider stream -> output hold-back scan -> token hydration -> client.
 * Text is scanned BEFORE it is hydrated, and hydrated values are never rescanned.
 */
export class SecureStreamService {
  private readonly limits: StreamLimits;
  constructor(private readonly d: SecureStreamDeps) { this.limits = { ...DEFAULT_STREAM_LIMITS, ...d.limits }; }

  async open(p: Principal, provider: string, messages: ChatMessage[], meta: RequestMeta, opts: StreamOptions): Promise<OpenOutcome> {
    const screened = await this.d.service.screenInput(p, provider, messages, meta);
    if (screened.kind !== "ready") return screened;
    let disposed = false;
    const dispose = async (): Promise<void> => {
      if (disposed) return;
      disposed = true;
      const s = opts.vaultSession;
      if (s?.ephemeral && this.d.vault) await this.d.vault.deleteSession(p.organizationId, s.id).catch(() => undefined);
    };
    return { kind: "stream", events: this.run(p, provider, meta, screened, opts, dispose), dispose };
  }

  private async *run(
    p: Principal, provider: string, meta: RequestMeta, screened: Extract<import("./secureAiService.js").Screened, { kind: "ready" }>,
    opts: StreamOptions, dispose: () => Promise<void>,
  ): AsyncGenerator<StreamEvent, void, void> {
    const { sanitized, policy, inScan, inEventId, router } = screened;
    // Provisional until the provider reports what it actually used (adapters resolve their own default when the caller names none).
    let model = meta.model ?? "default";
    const providerCtl = new AbortController();
    const onClientAbort = (): void => providerCtl.abort();
    opts.signal.addEventListener("abort", onClientAbort, { once: true });
    let deadlineHit = false;
    const deadline = setTimeout(() => { deadlineHit = true; providerCtl.abort(); }, this.limits.maxDurationMs);

    const hydrating = opts.hydrate !== false && !!this.d.vault && !!opts.vaultSession;
    const screen = new OutputScreen(this.d.service.outputScanner(p, provider, model, meta, policy), {
      holdBack: opts.mode === "buffered" ? Number.POSITIVE_INFINITY : this.limits.holdBackChars,
      minSegment: this.limits.minSegmentChars, maxChars: this.limits.maxOutputChars,
    });
    const window = hydrating
      ? new TokenWindow((tokens) => this.d.vault!.resolve(p.organizationId, opts.vaultSession!.id, tokens, providerCtl.signal), { signal: providerCtl.signal })
      : null;
    const emit = async (text: string): Promise<string> => (window ? window.push(text) : text);

    let iterator: AsyncIterator<StreamChunk> | undefined;
    let ended: StreamEvent | null = null;
    let outEventId: string | null = null;
    let audited = false;
    // The output event is recorded exactly once, whichever way the stream ends (done, blocked, error, client gone).
    const auditOnce = async (): Promise<void> => {
      if (audited) return;
      audited = true;
      const summary = screen.summary();
      if (summary) outEventId = await this.d.service.auditOutput(p, summary, provider, model, meta);
    };

    try {
      try {
        iterator = router.stream(provider, {
          messages: sanitized, ...(meta.model ? { model: meta.model } : {}), signal: providerCtl.signal,
          ...(opts.maxOutputTokens !== undefined ? { maxOutputTokens: opts.maxOutputTokens } : {}), ...(opts.temperature !== undefined ? { temperature: opts.temperature } : {}),
        })[Symbol.asyncIterator]();

        for (;;) {
          const r = await nextWithIdle(iterator, this.limits.idleTimeoutMs);
          if (r.done || providerCtl.signal.aborted) break;
          if (r.value.model) model = r.value.model;
          const released = await screen.push(r.value.delta);
          if (released.kind === "blocked") { ended = this.blocked(released.scan, null); break; }
          const text = released.text ? await emit(released.text) : "";
          if (text) yield { type: "delta", text };
          if (r.value.done) break;
        }

        if (ended === null && !providerCtl.signal.aborted) {
          const last = await screen.finish();
          if (last.kind === "blocked") ended = this.blocked(last.scan, null);
          else {
            const tail = window ? await window.push(last.text, true) : last.text;     // final: releases any held partial token literally
            if (tail) yield { type: "delta", text: tail };
          }
        }
      } catch (err) {
        if (err instanceof IdleTimeout) ended = { type: "error", error: "idle_timeout" };
        else if (deadlineHit) ended = { type: "error", error: "max_duration" };
        else if (providerCtl.signal.aborted) ended = null;                          // client went away: nothing to tell it
        else if (err instanceof UnknownProviderError) ended = this.blocked(null, "unknown_provider");
        else ended = { type: "error", error: "provider_error", code: err instanceof ProviderError ? err.code : "unavailable", eventId: inEventId };
      } finally {
        clearTimeout(deadline);
        opts.signal.removeEventListener("abort", onClientAbort);
        providerCtl.abort();                                                        // cancels the upstream request (idempotent)
        // Not awaited: a provider that ignores the abort must not be able to hold this stream (and its connection) open.
        void iterator?.return?.().catch(() => undefined);
      }
      if (deadlineHit && ended === null) ended = { type: "error", error: "max_duration" };

      await auditOnce();
      if (opts.signal.aborted && ended === null) return;                            // disconnected: no one to write to
      if (ended?.type === "error" && ended.error === "blocked") { yield { ...ended, eventId: outEventId }; return; }
      if (ended) { yield ended; return; }
      if (outEventId === null) { yield { type: "error", error: "audit_unavailable" }; return; }
      const summary = screen.summary()!;
      yield {
        type: "done", provider, model,
        security: { input: { decision: inScan.decision, riskLevel: inScan.risk.risk_level, eventId: inEventId }, output: { decision: summary.decision, riskLevel: summary.risk.risk_level, eventId: outEventId } },
        hydration: window ? (window.degraded ? "degraded" : "applied") : "off",
      };
    } finally {
      // Runs on normal end AND when the consumer stops early (client disconnect at a yield): audit what was scanned, drop the session.
      await auditOnce();
      await dispose();
    }
  }

  private blocked(scan: import("@sentinelai/shared-types").ScanResult | null, reason: string | null): StreamEvent {
    const decision: Action = scan && withholdsContent(scan.decision) ? scan.decision : "BLOCK";
    return { type: "error", error: "blocked", stage: "output", decision, failedClosed: scan?.failed_closed ?? true, reason: scan?.fail_closed_reason ?? reason, eventId: null };
  }
}
