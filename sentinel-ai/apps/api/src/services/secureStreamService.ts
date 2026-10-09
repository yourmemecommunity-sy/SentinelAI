import type { Action, ScanResult } from "@sentinelai/shared-types";
import { ProviderError, UnknownProviderError, type AiRouter, type ChatMessage, type StreamChunk } from "@sentinelai/ai-router";
import type { AuditLogWriter } from "../events/auditLog.js";
import type { Principal } from "../security/rbac.js";
import type { RevocationReason } from "../security/revocationWatcher.js";
import { failClosedResult, withholdsContent } from "../security/securityClient.js";
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
  /** After a mid-stream revocation, may a clean quarantined reply still be released? false = always drop. */
  quarantineRelease: boolean;
}

export const DEFAULT_STREAM_LIMITS: StreamLimits = {
  holdBackChars: 256, minSegmentChars: 64, idleTimeoutMs: 30_000, maxDurationMs: 300_000, maxOutputChars: 200_000, quarantineRelease: true,
};

export type StreamEvent =
  | { type: "delta"; text: string }
  | { type: "done"; provider: string; model: string; security: { input: OutcomeSummary; output: OutcomeSummary }; hydration: "off" | "applied" | "degraded" }
  | { type: "error"; error: "blocked"; stage: "output"; decision: Action; failedClosed: boolean; reason: string | null; eventId: string | null }
  | { type: "error"; error: "provider_error"; code: string; eventId: string | null }
  | { type: "error"; error: "audit_unavailable" | "idle_timeout" | "max_duration" }
  /** The key was revoked (or could not be re-checked) mid-stream: the rest of the reply was held and scanned whole. */
  | { type: "error"; error: "stream_quarantined"; reason: RevocationReason; outcome: "released" | "dropped"; detail: string | null; eventId: string | null };

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
  /** Subscribes to "this stream's credential stopped being valid"; returns the unsubscribe function (RevocationWatcher.watch). */
  watchRevocation?: ((onRevoked: (reason: RevocationReason) => void) => () => void) | undefined;
}

export type OpenOutcome =
  | Extract<ChatOutcome, { kind: "blocked" | "audit_unavailable" }>
  | { kind: "stream"; events: AsyncGenerator<StreamEvent, void, void>; dispose: () => Promise<void> };

class IdleTimeout extends Error {}

/** Set (once) by the revocation watcher; the stream checks it before every release. */
interface Revocation { current: { reason: RevocationReason; at: number } | null }

/** Next chunk, or IdleTimeout if the provider stays silent. */
async function nextWithIdle<T>(it: AsyncIterator<T>, ms: number): Promise<IteratorResult<T>> {
  let timer: NodeJS.Timeout | undefined;
  const idle = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new IdleTimeout()), ms); });
  const next = it.next();
  next.catch(() => undefined);      // if the idle timer wins, a later rejection (e.g. from the abort we trigger) must not go unhandled
  try { return await Promise.race([next, idle]); } finally { clearTimeout(timer); }
}

/** The provider is resolved per request by `service.screenInput` (per-organization routing); `router` is no longer consulted. */
export interface SecureStreamDeps {
  service: SecureAiService; router?: AiRouter; vault?: TokenVault | undefined; limits?: Partial<StreamLimits>;
  /** Records every quarantine outcome. Without it a quarantined reply is never released (it cannot be audited). */
  auditLog?: AuditLogWriter | undefined;
}

/**
 * Streaming variant of the secure pipeline:
 *   input screening (identical to chat) -> provider stream -> output hold-back scan -> token hydration -> client.
 * Text is scanned BEFORE it is hydrated, and hydrated values are never rescanned.
 *
 * Quarantine on revoke: if the stream's API key is revoked mid-stream (or can no longer be checked), nothing more is released.
 * The provider is allowed to finish into a server-side buffer, the WHOLE reply is scanned once with the output checks, and the
 * remainder is then either released (clean, and `quarantineRelease`) or dropped, followed by a terminal `stream_quarantined`
 * event. Every limit still applies; any error, limit or audit failure drops it. Every outcome is written to the audit log.
 */
export class SecureStreamService {
  private readonly limits: StreamLimits;
  constructor(private readonly d: SecureStreamDeps) { this.limits = { ...DEFAULT_STREAM_LIMITS, ...d.limits }; }

  async open(p: Principal, provider: string, messages: ChatMessage[], meta: RequestMeta, opts: StreamOptions): Promise<OpenOutcome> {
    const screened = await this.d.service.screenInput(p, provider, messages, meta);
    if (screened.kind !== "ready") return screened;
    // Subscribe now, not when the caller starts reading: a revocation in between must not be missed. (An object, because the
    // callback writes it asynchronously: a plain `let` would be narrowed to null by the compiler.)
    const revocation: Revocation = { current: null };
    const unwatch = opts.watchRevocation?.((reason) => { revocation.current ??= { reason, at: Date.now() }; });
    let disposed = false;
    const dispose = async (): Promise<void> => {
      unwatch?.();
      if (disposed) return;
      disposed = true;
      const s = opts.vaultSession;
      if (s?.ephemeral && this.d.vault) await this.d.vault.deleteSession(p.organizationId, s.id).catch(() => undefined);
    };
    return { kind: "stream", events: this.run(p, provider, meta, screened, opts, dispose, revocation), dispose };
  }

  private async *run(
    p: Principal, provider: string, meta: RequestMeta, screened: Extract<import("./secureAiService.js").Screened, { kind: "ready" }>,
    opts: StreamOptions, dispose: () => Promise<void>, revocation: Revocation,
  ): AsyncGenerator<StreamEvent, void, void> {
    const { sanitized, policy, inScan, inEventId, router } = screened;
    // Provisional until the provider reports what it actually used (adapters resolve their own default when the caller names none).
    let model = meta.model ?? "default";
    const providerCtl = new AbortController();
    // Hydration has its own signal: the upstream request is closed as soon as the provider is done, but a quarantined reply is
    // released (and hydrated) after that. Both stop when the client leaves or the deadline passes.
    const hydrateCtl = new AbortController();
    const onClientAbort = (): void => { providerCtl.abort(); hydrateCtl.abort(); };
    opts.signal.addEventListener("abort", onClientAbort, { once: true });
    let deadlineHit = false;
    const deadline = setTimeout(() => { deadlineHit = true; providerCtl.abort(); hydrateCtl.abort(); }, this.limits.maxDurationMs);

    let releasedRaw = "";                    // scanned, sanitized text handed to the client (before hydration)
    let quarantine: string | null = null;    // non-null once quarantined: the reply the caller has not seen yet
    let quarantineLimit: string | null = null;

    const hydrating = opts.hydrate !== false && !!this.d.vault && !!opts.vaultSession;
    const scanOutput = this.d.service.outputScanner(p, provider, model, meta, policy);
    const screen = new OutputScreen(scanOutput, {
      holdBack: opts.mode === "buffered" ? Number.POSITIVE_INFINITY : this.limits.holdBackChars,
      minSegment: this.limits.minSegmentChars, maxChars: this.limits.maxOutputChars,
    });
    const window = hydrating
      ? new TokenWindow((tokens) => this.d.vault!.resolve(p.organizationId, opts.vaultSession!.id, tokens, hydrateCtl.signal), { signal: hydrateCtl.signal })
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
          if (revocation.current !== null && quarantine === null) quarantine = screen.takeHeld();
          if (quarantine !== null) {
            // Quarantined: keep reading into the server-side buffer, within the same output cap.
            quarantine += r.value.delta;
            if (releasedRaw.length + quarantine.length > this.limits.maxOutputChars) { quarantineLimit = "output_too_large"; break; }
            if (r.value.done) break;
            continue;
          }
          const released = await screen.push(r.value.delta);
          if (released.kind === "blocked") { ended = this.blocked(released.scan, null); break; }
          if (revocation.current !== null) {                                        // revoked while that segment was being scanned
            quarantine = released.text + screen.takeHeld();
            if (r.value.done) break;
            continue;
          }
          releasedRaw += released.text;
          const text = released.text ? await emit(released.text) : "";
          if (text) yield { type: "delta", text };
          if (r.value.done) break;
        }

        if (ended === null && !providerCtl.signal.aborted && quarantineLimit === null) {
          if (revocation.current !== null && quarantine === null) quarantine = screen.takeHeld();  // revoked after the last chunk
          if (quarantine === null) {
            const last = await screen.finish();
            if (last.kind === "blocked") ended = this.blocked(last.scan, null);
            else {
              releasedRaw += last.text;
              const tail = window ? await window.push(last.text, true) : last.text;   // final: releases any held partial token literally
              if (tail) yield { type: "delta", text: tail };
            }
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

      const revoked = revocation.current;
      if (quarantine !== null && revoked !== null) {
        const why: string | null = quarantineLimit
          ?? (opts.signal.aborted && ended === null ? "client_disconnected" : null)
          ?? (ended?.type === "error" ? ended.error : null);
        const q = await this.settleQuarantine(p, provider, meta, scanOutput, screen, releasedRaw, quarantine, revoked, why);
        await auditOnce();
        if (opts.signal.aborted) return;                                            // disconnected: no one to write to
        if (q.text) {
          const tail = window ? await window.push(q.text, true) : q.text;
          if (tail) yield { type: "delta", text: tail };
        }
        yield { type: "error", error: "stream_quarantined", reason: revoked.reason, outcome: q.outcome, detail: q.detail, eventId: outEventId };
        return;
      }

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

  /**
   * Decides a quarantined reply: scan the WHOLE reply (released part + held part) once with the output checks, then release
   * the unseen remainder only if the verdict is clean, the released part is unchanged by the rescan, release is allowed and the
   * outcome could be audited. Everything else drops it. `failure` (limit, timeout, provider error, disconnect) always drops.
   */
  private async settleQuarantine(
    p: Principal, provider: string, meta: RequestMeta, scanOutput: (text: string) => Promise<ScanResult>, screen: OutputScreen,
    releasedRaw: string, held: string, revoked: { reason: RevocationReason; at: number }, failure: string | null,
  ): Promise<{ outcome: "released" | "dropped"; detail: string | null; text: string }> {
    let outcome: "released" | "dropped" = "dropped";
    let detail: string | null = failure;
    let text = "";
    if (failure === null) {
      let scan: ScanResult;
      try { scan = await scanOutput(releasedRaw + held); } catch { scan = failClosedResult("quarantine_scan_failed"); }
      screen.record(scan);
      const clean = !withholdsContent(scan.decision) && scan.sanitized_text !== null;
      if (!clean) detail = scan.failed_closed ? (scan.fail_closed_reason ?? "fail_closed") : `policy_${scan.decision.toLowerCase()}`;
      else if (!scan.sanitized_text!.startsWith(releasedRaw)) detail = "rescan_changed_released_text";
      else if (!this.limits.quarantineRelease) detail = "release_disabled";
      else if (!this.d.auditLog) detail = "audit_unavailable";
      else { outcome = "released"; text = scan.sanitized_text!.slice(releasedRaw.length); }
    }
    const record = (o: "released" | "dropped", why: string | null) => this.d.auditLog?.record({
      organizationId: p.organizationId, actorId: null, actorType: "system", action: "stream.quarantine", target: p.apiKeyId ?? p.userId,
      metadata: { outcome: o, reason: revoked.reason, detail: why, provider, application: meta.application ?? null,
        chars_held: held.length, chars_released_before: releasedRaw.length, chars_released_after: o === "released" ? text.length : 0,
        ms_since_revocation: Date.now() - revoked.at },
    });
    try { await record(outcome, detail); } catch {
      // Fail closed: an outcome that cannot be audited is not released. Try to record the drop (best effort; the store is likely down).
      if (outcome === "released") { outcome = "dropped"; detail = "audit_unavailable"; text = ""; await record(outcome, detail)?.catch(() => undefined); }
    }
    return { outcome, detail, text };
  }

  private blocked(scan: ScanResult | null, reason: string | null): StreamEvent {
    const decision: Action = scan && withholdsContent(scan.decision) ? scan.decision : "BLOCK";
    return { type: "error", error: "blocked", stage: "output", decision, failedClosed: scan?.failed_closed ?? true, reason: scan?.fail_closed_reason ?? reason, eventId: null };
  }
}
