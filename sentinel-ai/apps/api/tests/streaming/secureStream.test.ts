import type { ScanRequest, ScanResult } from "@sentinelai/shared-types";
import { AiRouter } from "@sentinelai/ai-router";
import { beforeEach, describe, expect, it } from "vitest";
import { InMemoryEventSink } from "../../src/events/eventSink.js";
import type { TokenVault } from "../../src/security/tokenVault.js";
import { VaultUnavailableError } from "../../src/security/tokenVault.js";
import type { SecurityScanner } from "../../src/security/securityClient.js";
import { SecureAiService } from "../../src/services/secureAiService.js";
import { SecureStreamService, type StreamEvent, type StreamLimits, type StreamOptions } from "../../src/services/secureStreamService.js";
import { FakeProvider, MemoryPolicies, makeScan, principal } from "../helpers/fakes.js";

const EMAIL = "jane@x.co";
const P = principal();

/** Engine double: BADSECRET blocks; on INPUT with a vault session the email becomes a token; everything else passes. */
class Engine implements SecurityScanner {
  requests: ScanRequest[] = [];
  async scan(req: ScanRequest): Promise<ScanResult> {
    this.requests.push(req);
    if (req.text.includes("BADSECRET")) return makeScan("BLOCK");
    if (req.direction === "INPUT" && req.vault_session && req.text.includes(EMAIL)) return makeScan("TOKENIZE", { sanitized_text: req.text.replaceAll(EMAIL, "[TOK_EMAIL_1]") });
    return makeScan("ALLOW", { sanitized_text: req.text });
  }
  async ready() { return true; }
}

class FakeVault implements TokenVault {
  values = new Map<string, string>([["[TOK_EMAIL_1]", EMAIL], ["[TOK_NAME_1]", "John Doe"]]);
  down = false;
  calls: { org: string; session: string; tokens: string[] }[] = [];
  deleted: { org: string; session: string }[] = [];
  async resolve(org: string, session: string, tokens: string[]) {
    this.calls.push({ org, session, tokens: [...tokens] });
    if (this.down) throw new VaultUnavailableError();
    return new Map(tokens.filter((t) => this.values.has(t)).map((t) => [t, this.values.get(t)!]));
  }
  async deleteSession(org: string, session: string) { this.deleted.push({ org, session }); }
  async ready() { return !this.down; }
}

let engine: Engine; let events: InMemoryEventSink; let provider: FakeProvider; let vault: FakeVault; let ctl: AbortController;

function build(limits: Partial<StreamLimits> = {}, withVault = true) {
  engine = new Engine(); events = new InMemoryEventSink(); provider = new FakeProvider(); vault = new FakeVault(); ctl = new AbortController();
  const router = new AiRouter().register(provider);
  const service = new SecureAiService({ scanner: engine, router, policies: new MemoryPolicies(), events, vault: withVault ? vault : undefined });
  return new SecureStreamService({ service, router, vault: withVault ? vault : undefined, limits: { holdBackChars: 24, minSegmentChars: 4, ...limits } });
}

const chunks = (s: string, n: number) => Array.from({ length: Math.ceil(s.length / n) }, (_, i) => s.slice(i * n, i * n + n));
const SESSION = { id: "sess-abc", ephemeral: true };

async function drain(svc: SecureStreamService, prompt: string, over: Partial<StreamOptions> = {}, meta = {}) {
  const open = await svc.open(P, "gemini", [{ role: "user", content: prompt }], { vaultSession: SESSION.id, ...meta }, { signal: ctl.signal, vaultSession: SESSION, ...over });
  if (open.kind !== "stream") return { open, evs: [] as StreamEvent[], text: "" };
  const evs: StreamEvent[] = [];
  for await (const e of open.events) evs.push(e);
  return { open, evs, text: evs.flatMap((e) => (e.type === "delta" ? [e.text] : [])).join("") };
}

let svc: SecureStreamService;
beforeEach(() => { svc = build(); });

describe("happy path", () => {
  it("the provider only ever sees the tokenized prompt; the caller receives the hydrated reply; both stages are audited", async () => {
    provider.streamPlan = (req) => chunks(`Sure, I will write to ${(req.messages.at(-1)!.content.match(/\[TOK_EMAIL_1\]/) ?? ["?"])[0]} today.`, 4);
    const { evs, text } = await drain(svc, `please email ${EMAIL} about the invoice`);
    expect(provider.received[0]!.messages[0]!.content).toBe("please email [TOK_EMAIL_1] about the invoice");
    expect(JSON.stringify(provider.received)).not.toContain(EMAIL);
    expect(text).toBe(`Sure, I will write to ${EMAIL} today.`);
    const done = evs.at(-1)!;
    expect(done).toMatchObject({ type: "done", provider: "gemini", hydration: "applied" });
    expect(events.events.map((e) => [e.eventType, e.direction]).reverse()).toEqual([["ai_request", "INPUT"], ["ai_response", "OUTPUT"]]);
  });

  it("the OUTPUT scanner only ever sees tokens, never the hydrated plaintext (hydration happens after the scan)", async () => {
    provider.streamPlan = () => chunks("Contact [TOK_EMAIL_1] or [TOK_NAME_1] soon.", 3);
    const { text } = await drain(svc, "hello");
    expect(text).toBe(`Contact ${EMAIL} or John Doe soon.`);
    const outScans = engine.requests.filter((r) => r.direction === "OUTPUT");
    expect(outScans.length).toBeGreaterThan(0);
    for (const r of outScans) { expect(r.text).not.toContain(EMAIL); expect(r.text).not.toContain("John Doe"); }
  });

  it("hydrated values are not rescanned: a caller's own tokenized data is returned even if it looks like a secret", async () => {
    vault.values.set("[TOK_NAME_1]", "BADSECRET");
    provider.streamPlan = () => ["Your value is [TOK_NAME_1]."];
    const { evs, text } = await drain(svc, "hi");
    expect(text).toBe("Your value is BADSECRET.");
    expect(evs.at(-1)!.type).toBe("done");
  });

  it("a token split across provider chunks (at every position) is hydrated exactly once", async () => {
    const reply = "Dear [TOK_NAME_1], see [TOK_EMAIL_1]!";
    for (let i = 1; i < reply.length; i++) {
      const s = build();
      provider.streamPlan = () => [reply.slice(0, i), reply.slice(i)];
      const { text } = await drain(s, "hello");
      expect(text, `split ${i}`).toBe(`Dear John Doe, see ${EMAIL}!`);
    }
  });

  it("text is released while the provider stream is still open (not buffered to the end)", async () => {
    provider.streamPlan = () => chunks("word ".repeat(200), 10);
    provider.chunkDelayMs = 1;
    const open = await svc.open(P, "gemini", [{ role: "user", content: "go" }], {}, { signal: ctl.signal });
    if (open.kind !== "stream") throw new Error("expected stream");
    let closedAtFirstDelta = -1; let released = 0;
    for await (const e of open.events) {
      if (e.type !== "delta") continue;
      if (closedAtFirstDelta < 0) closedAtFirstDelta = provider.streamsClosed;
      released += e.text.length;
    }
    expect(closedAtFirstDelta).toBe(0);                                  // the provider stream was still open when the first text reached the client
    expect(released).toBe(1000);
  });
});

describe("modes and options", () => {
  it("buffered mode emits nothing until the reply has been fully scanned", async () => {
    provider.streamPlan = () => chunks("a reply in pieces ".repeat(20), 7);
    const { evs } = await drain(svc, "go", { mode: "buffered" });
    expect(evs[0]!.type).toBe("delta");
    expect(evs.filter((e) => e.type === "delta")).toHaveLength(1);       // one release, at the end
    expect(evs.at(-1)!.type).toBe("done");
  });

  it("buffered mode blocks a secret with nothing having been released", async () => {
    provider.streamPlan = () => chunks("fine text ".repeat(20) + "BADSECRET" + " more".repeat(20), 7);
    const { evs, text } = await drain(svc, "go", { mode: "buffered" });
    expect(text).toBe("");
    expect(evs).toHaveLength(1);
    expect(evs[0]).toMatchObject({ type: "error", error: "blocked", stage: "output" });
  });

  it("hydrate:false leaves tokens in place and reports hydration off", async () => {
    provider.streamPlan = () => ["mail [TOK_EMAIL_1]"];
    const { evs, text } = await drain(svc, "hi", { hydrate: false });
    expect(text).toBe("mail [TOK_EMAIL_1]");
    expect(evs.at(-1)).toMatchObject({ type: "done", hydration: "off" });
    expect(vault.calls).toEqual([]);
  });

  it("without a vault nothing is hydrated and the session is ignored", async () => {
    const s = build({}, false);
    provider.streamPlan = () => ["mail [TOK_EMAIL_1]"];
    const { evs, text } = await drain(s, "hi", { vaultSession: undefined });
    expect(text).toBe("mail [TOK_EMAIL_1]");
    expect(evs.at(-1)).toMatchObject({ hydration: "off" });
  });

  it("session_id semantics: an ephemeral session is deleted when the stream ends, a caller-named one is kept", async () => {
    provider.streamPlan = () => ["ok"];
    await drain(svc, "hi", { vaultSession: { id: "eph", ephemeral: true } });
    expect(vault.deleted).toEqual([{ org: P.organizationId, session: "eph" }]);
    vault.deleted.length = 0;
    await drain(svc, "hi", { vaultSession: { id: "kept", ephemeral: false } });
    expect(vault.deleted).toEqual([]);
  });
});

describe("before the stream starts", () => {
  it("blocked input returns a blocked outcome and never contacts the provider", async () => {
    const open = await svc.open(P, "gemini", [{ role: "user", content: "leak BADSECRET" }], {}, { signal: ctl.signal });
    expect(open).toMatchObject({ kind: "blocked", stage: "input", decision: "BLOCK" });
    expect(provider.streamsOpened).toBe(0);
  });

  it("an unauditable input returns audit_unavailable and never contacts the provider", async () => {
    events.failNext = true;
    const open = await svc.open(P, "gemini", [{ role: "user", content: "hello" }], {}, { signal: ctl.signal });
    expect(open).toEqual({ kind: "audit_unavailable", stage: "input" });
    expect(provider.streamsOpened).toBe(0);
  });

  it("an unknown provider is a fail-closed block", async () => {
    const open = await svc.open(P, "nope", [{ role: "user", content: "hello" }], {}, { signal: ctl.signal });
    expect(open).toMatchObject({ kind: "blocked", failedClosed: true, reason: "unknown_provider" });
  });
});

describe("output problems mid-stream", () => {
  it("a secret in the reply terminates the stream with a blocked error; the first half is never released; the provider is closed; the block is audited", async () => {
    provider.streamPlan = () => chunks("Here is some harmless text first, then BADSECRET and the rest of it.", 3);
    const { evs, text } = await drain(svc, "go");
    expect(text).not.toContain("BAD");
    expect(text.length).toBeGreaterThan(0);
    expect(evs.at(-1)).toMatchObject({ type: "error", error: "blocked", stage: "output", decision: "BLOCK" });
    expect(evs.filter((e) => e.type === "done")).toHaveLength(0);
    expect(provider.streamsClosed).toBe(1);
    const out = events.events.find((e) => e.direction === "OUTPUT")!;
    expect(out.action).toBe("BLOCK");
    expect((evs.at(-1) as { eventId: string }).eventId).toBe(out.id);
  });

  it("output beyond the cap is blocked fail-closed", async () => {
    const s = build({ maxOutputChars: 100 });
    provider.streamPlan = () => chunks("x".repeat(500), 20);
    const { evs } = await drain(s, "go");
    expect(evs.at(-1)).toMatchObject({ type: "error", error: "blocked", failedClosed: true, reason: "output_too_large" });
  });

  it("a provider failure after text was released ends with a provider_error event, and what was scanned is audited", async () => {
    provider.streamPlan = () => chunks("some text that goes on for quite a while and more ".repeat(3), 5);
    provider.failAtChunk = 25;
    const { evs, text } = await drain(svc, "go");
    expect(text.length).toBeGreaterThan(0);
    expect(evs.at(-1)).toMatchObject({ type: "error", error: "provider_error", code: "unavailable" });
    expect(provider.streamsClosed).toBe(1);
    expect(events.events.some((e) => e.direction === "OUTPUT")).toBe(true);
  });

  it("a provider failure before anything was released reports the error; there is nothing to audit on the output side", async () => {
    provider.streamPlan = () => chunks("short", 5);
    provider.failAtChunk = 0;
    const { evs, text } = await drain(svc, "go");
    expect(text).toBe("");
    expect(evs).toHaveLength(1);
    expect(evs[0]).toMatchObject({ type: "error", error: "provider_error", eventId: expect.any(String) });   // eventId = the INPUT event
    expect(events.events.filter((e) => e.direction === "OUTPUT")).toHaveLength(0);
  });

  it("a stalled provider is cut off by the idle timeout, and the upstream request is aborted", async () => {
    const s = build({ idleTimeoutMs: 80 });
    provider.streamPlan = () => ["start of a reply. "];
    provider.stallAtEnd = true;
    const t0 = Date.now();
    const { evs } = await drain(s, "go");
    expect(evs.at(-1)).toEqual({ type: "error", error: "idle_timeout" });
    expect(Date.now() - t0).toBeLessThan(2000);
    await new Promise((r) => setTimeout(r, 30));
    expect(provider.sawAbort).toBe(true);
  });

  it("the maximum stream duration is enforced even while the provider keeps sending", async () => {
    const s = build({ maxDurationMs: 120, idleTimeoutMs: 5000 });
    provider.streamPlan = () => Array.from({ length: 1000 }, () => "tick ");
    provider.chunkDelayMs = 20;
    const { evs } = await drain(s, "go");
    expect(evs.at(-1)).toEqual({ type: "error", error: "max_duration" });
    expect(provider.streamsClosed).toBe(1);
  });

  it("if the final output event cannot be recorded the client is told (a stream is not 'done' without its audit record)", async () => {
    provider.streamPlan = () => ["hello there"];
    const open = await svc.open(P, "gemini", [{ role: "user", content: "hi" }], {}, { signal: ctl.signal });
    if (open.kind !== "stream") throw new Error("expected stream");
    events.failNext = true;                                           // the input event is already recorded; the next (output) write fails
    const evs: StreamEvent[] = [];
    for await (const e of open.events) evs.push(e);
    expect(evs.at(-1)).toEqual({ type: "error", error: "audit_unavailable" });
    expect(evs.filter((e) => e.type === "done")).toHaveLength(0);
  });
});

describe("vault outage", () => {
  it("tokens stay un-hydrated (no plaintext, no failure) and the terminal event says hydration was degraded", async () => {
    vault.down = true;
    provider.streamPlan = () => chunks("Contact [TOK_EMAIL_1] please.", 4);
    const { evs, text } = await drain(svc, "hi");
    expect(text).toBe("Contact [TOK_EMAIL_1] please.");
    expect(evs.at(-1)).toMatchObject({ type: "done", hydration: "degraded" });
  });
});

describe("client disconnect and cleanup", () => {
  it("aborting mid-stream stops the provider, audits what was scanned, removes the ephemeral session, and emits nothing further", async () => {
    provider.streamPlan = () => Array.from({ length: 500 }, () => "word ");
    provider.chunkDelayMs = 5;
    const open = await svc.open(P, "gemini", [{ role: "user", content: "go" }], {}, { signal: ctl.signal, vaultSession: SESSION });
    if (open.kind !== "stream") throw new Error("expected stream");
    const seen: StreamEvent[] = [];
    for await (const e of open.events) { seen.push(e); if (seen.length === 3) ctl.abort(); }
    expect(seen.every((e) => e.type === "delta")).toBe(true);           // no done / error for a client that is gone
    expect(provider.sawAbort).toBe(true);
    expect(provider.streamsClosed).toBe(1);
    expect(events.events.filter((e) => e.direction === "OUTPUT")).toHaveLength(1);
    expect(vault.deleted).toEqual([{ org: P.organizationId, session: SESSION.id }]);
  });

  it("stopping iteration early (consumer break) runs the same cleanup exactly once", async () => {
    provider.streamPlan = () => Array.from({ length: 500 }, () => "word ");
    provider.chunkDelayMs = 2;
    const open = await svc.open(P, "gemini", [{ role: "user", content: "go" }], {}, { signal: ctl.signal, vaultSession: SESSION });
    if (open.kind !== "stream") throw new Error("expected stream");
    for await (const e of open.events) { if (e.type === "delta") break; }
    await open.dispose();                                               // idempotent: the route calls it as well
    expect(provider.streamsClosed).toBe(1);
    expect(events.events.filter((e) => e.direction === "OUTPUT")).toHaveLength(1);
    expect(vault.deleted).toHaveLength(1);
  });

  it("a client that leaves before the first chunk still releases the session via dispose()", async () => {
    const open = await svc.open(P, "gemini", [{ role: "user", content: "hi" }], {}, { signal: ctl.signal, vaultSession: SESSION });
    if (open.kind !== "stream") throw new Error("expected stream");
    await open.dispose();
    expect(vault.deleted).toHaveLength(1);
    expect(provider.streamsOpened).toBe(0);
  });

  it("many aborted streams leave no pending timers or listeners behind", async () => {
    const before = process.listenerCount("unhandledRejection");
    for (let i = 0; i < 25; i++) {
      const s = build();
      provider.streamPlan = () => Array.from({ length: 50 }, () => "word ");
      provider.chunkDelayMs = 2;
      const open = await s.open(P, "gemini", [{ role: "user", content: "go" }], {}, { signal: ctl.signal });
      if (open.kind !== "stream") throw new Error("expected stream");
      let n = 0;
      for await (const _e of open.events) { if (++n === 2) ctl.abort(); }
      expect(provider.streamsClosed).toBe(1);
    }
    expect(process.listenerCount("unhandledRejection")).toBe(before);
  });
});

describe("audit trail contains no plaintext", () => {
  it("neither the prompt's nor the reply's sensitive values appear in any recorded event", async () => {
    provider.streamPlan = () => chunks("Contact [TOK_EMAIL_1] or [TOK_NAME_1].", 5);
    await drain(svc, `mail ${EMAIL} now`);
    const dump = JSON.stringify(events.events);
    expect(dump).not.toContain(EMAIL);
    expect(dump).not.toContain("John Doe");
    expect(events.events).toHaveLength(2);
  });
});

describe("non-streaming chat with a vault session", () => {
  it("hydrates the scanned reply once, and degrades safely when the vault is down", async () => {
    const router = new AiRouter().register(provider);
    const service = new SecureAiService({ scanner: engine, router, policies: new MemoryPolicies(), events, vault });
    provider.reply = () => "Contact [TOK_EMAIL_1].";
    const ok = await service.chat(P, "gemini", [{ role: "user", content: `mail ${EMAIL}` }], { vaultSession: "s1" });
    expect(ok).toMatchObject({ kind: "ok", content: `Contact ${EMAIL}.`, hydration: "applied" });
    vault.down = true;
    const degraded = await service.chat(P, "gemini", [{ role: "user", content: "hi" }], { vaultSession: "s1" });
    expect(degraded).toMatchObject({ kind: "ok", content: "Contact [TOK_EMAIL_1].", hydration: "degraded" });
    const off = await service.chat(P, "gemini", [{ role: "user", content: "hi" }], { vaultSession: "s1" }, { hydrate: false });
    expect(off).toMatchObject({ kind: "ok", content: "Contact [TOK_EMAIL_1]." });
    expect((off as { hydration?: string }).hydration).toBeUndefined();
    const noSession = await service.chat(P, "gemini", [{ role: "user", content: "hi" }], {});
    expect((noSession as { hydration?: string }).hydration).toBeUndefined();
  });

  it("the output scan precedes hydration in chat too", async () => {
    const router = new AiRouter().register(provider);
    const service = new SecureAiService({ scanner: engine, router, policies: new MemoryPolicies(), events, vault });
    provider.reply = () => "Contact [TOK_EMAIL_1].";
    await service.chat(P, "gemini", [{ role: "user", content: "hi" }], { vaultSession: "s1" });
    expect(engine.requests.filter((r) => r.direction === "OUTPUT").every((r) => !r.text.includes(EMAIL))).toBe(true);
  });
});
