import type { ScanRequest, ScanResult } from "@sentinelai/shared-types";
import { AiRouter } from "@sentinelai/ai-router";
import { describe, expect, it } from "vitest";
import { InMemoryAuditLog, type AuditLogEntry, type AuditLogWriter } from "../../src/events/auditLog.js";
import { InMemoryEventSink } from "../../src/events/eventSink.js";
import { eventFrame } from "../../src/routes/streamRoutes.js";
import { RevocationWatcher, type RevocationReason, type RevocationSource } from "../../src/security/revocationWatcher.js";
import type { SecurityScanner } from "../../src/security/securityClient.js";
import { SecureAiService } from "../../src/services/secureAiService.js";
import { SecureStreamService, type StreamEvent, type StreamLimits, type StreamOptions } from "../../src/services/secureStreamService.js";
import { FakeProvider, MemoryPolicies, makeScan, principal } from "../helpers/fakes.js";

const P = principal();

/** Engine double: BADSECRET blocks; "SCANFAIL" fails closed; everything else passes unchanged. Records every OUTPUT text. */
class Engine implements SecurityScanner {
  outputs: string[] = [];
  async scan(req: ScanRequest): Promise<ScanResult> {
    if (req.direction === "OUTPUT") this.outputs.push(req.text);
    if (req.text.includes("BADSECRET")) return makeScan("BLOCK");
    if (req.text.includes("SCANFAIL")) return makeScan("BLOCK", { failed_closed: true, fail_closed_reason: "engine_unavailable", sanitized_text: null });
    return makeScan("ALLOW", { sanitized_text: req.text });
  }
  async ready() { return true; }
}

class FailingAudit implements AuditLogWriter { calls = 0; async record(): Promise<void> { this.calls++; throw new Error("audit store down"); } }

/** A trigger the test fires; it stands in for RevocationWatcher.watch. */
class Trigger {
  private cb: ((r: RevocationReason) => void) | null = null;
  unsubscribed = false;
  readonly watch: NonNullable<StreamOptions["watchRevocation"]> = (cb) => { this.cb = cb; return () => { this.unsubscribed = true; }; };
  fire(reason: RevocationReason = "key_revoked") { this.cb?.(reason); }
}

function build(limits: Partial<StreamLimits> = {}, audit: AuditLogWriter | null = new InMemoryAuditLog()) {
  const engine = new Engine(); const provider = new FakeProvider(); const events = new InMemoryEventSink();
  const router = new AiRouter().register(provider);
  const service = new SecureAiService({ scanner: engine, router, policies: new MemoryPolicies(), events });
  const svc = new SecureStreamService({ service, router, ...(audit ? { auditLog: audit } : {}), limits: { holdBackChars: 8, minSegmentChars: 2, ...limits } });
  return { svc, engine, provider, audit };
}

const words = (n: number, from = 0) => Array.from({ length: n }, (_, i) => `w${from + i} `);

/** Drains the stream; calls `onDelta(index)` after each delta is received (so a test can revoke mid-stream). */
async function drain(svc: SecureStreamService, trigger: Trigger | null, onDelta: (i: number) => void = () => undefined, signal = new AbortController().signal) {
  const open = await svc.open(P, "gemini", [{ role: "user", content: "go" }], {}, { signal, ...(trigger ? { watchRevocation: trigger.watch } : {}) });
  if (open.kind !== "stream") throw new Error(open.kind);
  const evs: StreamEvent[] = [];
  let deltas = 0;
  for await (const e of open.events) {
    evs.push(e);
    if (e.type === "delta") onDelta(deltas++);
  }
  return { evs, text: evs.flatMap((e) => (e.type === "delta" ? [e.text] : [])).join(""), last: evs.at(-1)! };
}
const auditOf = (a: AuditLogWriter | null) => (a as InMemoryAuditLog).entries.filter((e: AuditLogEntry) => e.action === "stream.quarantine");

describe("quarantine on revoke", () => {
  it("after revocation nothing more is streamed; the whole reply is scanned once and the clean remainder is released with a final quarantine event", async () => {
    const { svc, engine, provider, audit } = build();
    provider.streamPlan = () => words(40);
    const t = new Trigger();
    let deltasAtRevoke = -1;
    const { evs, text, last } = await drain(svc, t, (i) => { if (i === 1) { t.fire(); deltasAtRevoke = 2; } });
    const deltas = evs.filter((e) => e.type === "delta");
    expect(deltas.length).toBe(deltasAtRevoke + 1);                // exactly one more delta: the release after the scan
    expect(text).toBe(words(40).join(""));                          // nothing lost, nothing duplicated
    expect(last).toMatchObject({ type: "error", error: "stream_quarantined", reason: "key_revoked", outcome: "released", detail: null });
    expect(engine.outputs.at(-1)).toBe(words(40).join(""));        // the quarantine scan saw the COMPLETE reply
    const [a] = auditOf(audit);
    expect(a).toMatchObject({ actorType: "system", target: "key-1", metadata: { outcome: "released", reason: "key_revoked", detail: null } });
    expect(JSON.stringify(a)).not.toContain("w39");                 // audit metadata never contains content
    expect(t.unsubscribed).toBe(true);
  });

  it("drops the remainder when the complete reply fails the output checks: the blocked value never reaches the caller", async () => {
    const { svc, provider, audit } = build();
    provider.streamPlan = () => [...words(10), "BADSECRET ", ...words(10, 10)];
    const t = new Trigger();
    const { text, last } = await drain(svc, t, (i) => { if (i === 0) t.fire(); });
    expect(text).not.toContain("BADSECRET");
    expect(text).not.toContain("w15");
    expect(last).toMatchObject({ error: "stream_quarantined", outcome: "dropped", detail: "policy_block" });
    expect(auditOf(audit)[0]!.metadata).toMatchObject({ outcome: "dropped", detail: "policy_block", chars_released_after: 0 });
  });

  it("a fail-closed engine during the quarantine scan drops the reply", async () => {
    const { svc, provider } = build();
    provider.streamPlan = () => [...words(6), "SCANFAIL ", ...words(4, 6)];
    const t = new Trigger();
    const { text, last } = await drain(svc, t, (i) => { if (i === 0) t.fire(); });
    expect(text).not.toContain("SCANFAIL");
    expect(last).toMatchObject({ outcome: "dropped", detail: "engine_unavailable" });
  });

  it("STREAM_QUARANTINE_RELEASE=false always drops, even a clean reply", async () => {
    const { svc, provider, audit } = build({ quarantineRelease: false });
    provider.streamPlan = () => words(20);
    const t = new Trigger();
    const { last } = await drain(svc, t, (i) => { if (i === 0) t.fire(); });
    expect(last).toMatchObject({ outcome: "dropped", detail: "release_disabled" });
    expect(auditOf(audit)[0]!.metadata.outcome).toBe("dropped");
  });

  it("is fail-closed on audit: no audit log configured, or the audit write fails, means the reply is dropped", async () => {
    for (const audit of [null, new FailingAudit()]) {
      const { svc, provider } = build({}, audit);
      provider.streamPlan = () => words(20);
      const t = new Trigger();
      const { text, last } = await drain(svc, t, (i) => { if (i === 0) t.fire(); });
      expect(last).toMatchObject({ outcome: "dropped", detail: "audit_unavailable" });
      expect(text).not.toContain("w19");
    }
  });

  it("respects the output cap while quarantined (dropped, upstream closed)", async () => {
    const { svc, provider } = build({ maxOutputChars: 60 });
    provider.streamPlan = () => words(40);
    const t = new Trigger();
    const { last } = await drain(svc, t, (i) => { if (i === 0) t.fire(); });
    expect(last).toMatchObject({ outcome: "dropped", detail: "output_too_large" });
    expect(provider.streamsClosed).toBe(1);                          // the upstream stream was closed, not read to the end
  });

  it("respects the idle timeout and provider errors while quarantined (dropped, never released)", async () => {
    const idle = build({ idleTimeoutMs: 50 });
    idle.provider.streamPlan = () => words(10); idle.provider.stallAtEnd = true;
    const t1 = new Trigger();
    const a = await drain(idle.svc, t1, (i) => { if (i === 0) t1.fire(); });
    expect(a.last).toMatchObject({ outcome: "dropped", detail: "idle_timeout" });

    const broken = build();
    broken.provider.streamPlan = () => words(10); broken.provider.failAtChunk = 6;
    const t2 = new Trigger();
    const b = await drain(broken.svc, t2, (i) => { if (i === 0) t2.fire(); });
    expect(b.last).toMatchObject({ outcome: "dropped", detail: "provider_error" });
    expect(auditOf(broken.audit)[0]!.metadata).toMatchObject({ outcome: "dropped", detail: "provider_error" });
  });

  it("respects the maximum duration while quarantined", async () => {
    const { svc, provider } = build({ maxDurationMs: 80 });
    provider.streamPlan = () => words(30); provider.chunkDelayMs = 10;
    const t = new Trigger();
    const { last } = await drain(svc, t, (i) => { if (i === 0) t.fire(); });
    expect(last).toMatchObject({ outcome: "dropped", detail: "max_duration" });
  });

  it("a client that disconnects during quarantine gets nothing more, and the drop is still audited", async () => {
    const { svc, provider, audit } = build();
    provider.streamPlan = () => words(30); provider.chunkDelayMs = 5;
    const t = new Trigger(); const ctl = new AbortController();
    const { evs } = await drain(svc, t, (i) => { if (i === 0) { t.fire(); setTimeout(() => ctl.abort(), 30); } }, ctl.signal);
    expect(evs.filter((e) => e.type === "error")).toEqual([]);
    expect(auditOf(audit)[0]!.metadata).toMatchObject({ outcome: "dropped", detail: "client_disconnected" });
  });

  it("revoked before the first byte: nothing is streamed until the whole reply has been scanned", async () => {
    const { svc, provider } = build();
    provider.streamPlan = () => words(12);
    const t = new Trigger();
    const open = await svc.open(P, "gemini", [{ role: "user", content: "go" }], {}, { signal: new AbortController().signal, watchRevocation: t.watch });
    if (open.kind !== "stream") throw new Error(open.kind);
    t.fire();
    const evs: StreamEvent[] = [];
    for await (const e of open.events) evs.push(e);
    expect(evs.map((e) => e.type)).toEqual(["delta", "error"]);
    expect(evs[1]).toMatchObject({ outcome: "released" });
  });

  it("an unverifiable key (revocation check failed) is quarantined the same way, with its own reason", async () => {
    const { svc, provider } = build();
    provider.streamPlan = () => words(20);
    const t = new Trigger();
    const { last } = await drain(svc, t, (i) => { if (i === 0) t.fire("revocation_check_failed"); });
    expect(last).toMatchObject({ reason: "revocation_check_failed", outcome: "released" });
  });

  it("without a revocation the stream is unchanged (final done) and the subscription is released", async () => {
    const { svc, provider, audit } = build();
    provider.streamPlan = () => words(20);
    const t = new Trigger();
    const { text, last } = await drain(svc, t);
    expect(text).toBe(words(20).join(""));
    expect(last.type).toBe("done");
    expect(auditOf(audit)).toEqual([]);
    expect(t.unsubscribed).toBe(true);
  });

  it("a revocation after the stream completed changes nothing", async () => {
    const { svc, provider } = build();
    provider.streamPlan = () => words(5);
    const t = new Trigger();
    const { evs } = await drain(svc, t);
    t.fire();
    expect(evs.at(-1)!.type).toBe("done");
  });

  it("wire format: one JSON terminal event with reason, outcome and detail", () => {
    expect(eventFrame({ type: "error", error: "stream_quarantined", reason: "key_revoked", outcome: "dropped", detail: "policy_block", eventId: "e1" }))
      .toBe('event: error\ndata: {"error":"stream_quarantined","reason":"key_revoked","outcome":"dropped","detail":"policy_block","event_id":"e1"}\n\n');
  });
});

describe("RevocationWatcher", () => {
  class Source implements RevocationSource {
    revoked = new Set<string>(); fail = false; calls: [string, string[]][] = [];
    async revokedAmong(org: string, ids: string[]) { this.calls.push([org, ids]); if (this.fail) throw new Error("db down"); return ids.filter((i) => this.revoked.has(i)); }
  }

  it("notify() tells every stream on that key immediately, once", () => {
    const w = new RevocationWatcher(undefined, 1000);
    const got: string[] = [];
    w.watch("o1", "k1", (r) => got.push(`a:${r}`)); w.watch("o1", "k1", (r) => got.push(`b:${r}`)); w.watch("o1", "k2", (r) => got.push(`c:${r}`));
    w.notify("k1"); w.notify("k1");
    expect(got).toEqual(["a:key_revoked", "b:key_revoked"]);
    expect(w.watching).toBe(1);
  });

  it("the poll catches revocations made elsewhere, with one query per organization", async () => {
    const src = new Source(); const w = new RevocationWatcher(src, 60_000);
    const got: string[] = [];
    w.watch("o1", "k1", () => got.push("k1")); w.watch("o1", "k2", () => got.push("k2")); w.watch("o2", "k3", () => got.push("k3"));
    src.revoked.add("k2");
    await w.pollOnce();
    expect(got).toEqual(["k2"]);
    expect(src.calls.map((c) => c[0]).sort()).toEqual(["o1", "o2"]);
    w.stop();
  });

  it("fails closed: if the check fails, the streams it covers are told the key could not be verified", async () => {
    const src = new Source(); src.fail = true;
    const w = new RevocationWatcher(src, 60_000);
    const got: RevocationReason[] = [];
    w.watch("o1", "k1", (r) => got.push(r));
    await w.pollOnce();
    expect(got).toEqual(["revocation_check_failed"]);
  });

  it("unsubscribing stops notifications and the poll timer", async () => {
    const src = new Source(); const w = new RevocationWatcher(src, 60_000);
    const got: string[] = [];
    const off = w.watch("o1", "k1", () => got.push("k1"));
    off();
    src.revoked.add("k1");
    await w.pollOnce(); w.notify("k1");
    expect(got).toEqual([]);
    expect(src.calls).toEqual([]);
  });

  it("a throwing subscriber does not stop the others", () => {
    const w = new RevocationWatcher(undefined, 1000);
    const got: string[] = [];
    w.watch("o1", "k1", () => { throw new Error("boom"); }); w.watch("o1", "k1", () => got.push("second"));
    w.notify("k1");
    expect(got).toEqual(["second"]);
  });
});

