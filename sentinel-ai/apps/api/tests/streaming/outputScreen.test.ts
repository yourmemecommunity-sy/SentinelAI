import type { ScanResult } from "@sentinelai/shared-types";
import { describe, expect, it } from "vitest";
import { OutputScreen, type ScreenOptions, type ScreenResult } from "../../src/streaming/outputScreen.js";
import { makeScan } from "../helpers/fakes.js";

/** Behaves like the engine on markers: BADSECRET -> BLOCK, alice@b.co -> MASK (length changes), anything else ALLOW. */
function fakeEngine() {
  const scanned: string[] = [];
  let down = false;
  const scan = async (text: string): Promise<ScanResult> => {
    scanned.push(text);
    if (down) return makeScan("BLOCK", { failed_closed: true, fail_closed_reason: "engine_unreachable" });
    if (text.includes("BADSECRET")) return makeScan("BLOCK");
    if (text.includes("alice@b.co")) return makeScan("MASK", { sanitized_text: text.replaceAll("alice@b.co", "a***@b.co") });
    return makeScan("ALLOW", { sanitized_text: text });
  };
  return { scan, scanned, setDown: (v: boolean) => { down = v; } };
}

const opts = (over: Partial<ScreenOptions> = {}): ScreenOptions => ({ holdBack: 20, minSegment: 5, maxChars: 10_000, ...over });

async function feed(screen: OutputScreen, chunks: string[]) {
  const released: string[] = [];
  let blocked: ScreenResult | null = null;
  for (const c of chunks) {
    const r = await screen.push(c);
    if (r.kind === "blocked") { blocked = r; break; }
    released.push(r.text);
  }
  if (!blocked) {
    const r = await screen.finish();
    if (r.kind === "blocked") blocked = r; else released.push(r.text);
  }
  return { text: released.join(""), blocked, released };
}

const chunked = (s: string, n: number) => Array.from({ length: Math.ceil(s.length / n) }, (_, i) => s.slice(i * n, i * n + n));

describe("OutputScreen: hold-back", () => {
  it("releases text only once the look-ahead following it has been scanned, and everything by the end", async () => {
    const e = fakeEngine();
    const screen = new OutputScreen(e.scan, opts());
    expect((await screen.push("0123456789")).kind).toBe("text");
    expect(await screen.push("abcde")).toEqual({ kind: "text", text: "" });        // 15 chars buffered, only 5 releasable: under minSegment? no -> 15-20 < 5
    const r = await screen.push("ABCDEFGHIJKLMNO");                                 // 30 chars: releasable = 10
    expect(r).toEqual({ kind: "text", text: "0123456789" });
    expect(screen.held).toBe(20);
    expect(await screen.finish()).toEqual({ kind: "text", text: "abcdeABCDEFGHIJKLMNO" });
  });

  it("the concatenation of everything released equals the input, in order, for any chunking", async () => {
    const input = "The quick brown fox jumps over the lazy dog. ".repeat(20);
    for (const size of [1, 3, 7, 19, 64, 500]) {
      const e = fakeEngine();
      const r = await feed(new OutputScreen(e.scan, opts({ holdBack: 37, minSegment: 11 })), chunked(input, size));
      expect(r.blocked).toBeNull();
      expect(r.text).toBe(input);
    }
  });

  it("a secret split across chunks is caught BEFORE its first half is released", async () => {
    const text = "harmless words then BADSECRET and after";
    const e = fakeEngine();
    const r = await feed(new OutputScreen(e.scan, opts({ holdBack: 20, minSegment: 1 })), chunked(text, 3));
    expect(r.blocked?.kind).toBe("blocked");
    expect(r.text).not.toContain("BAD");
    expect(r.text.length).toBeGreaterThan(0);                       // earlier, clean text did flow
  });

  it("control: with NO look-ahead a split secret passes completely unnoticed (this is why the hold-back exists)", async () => {
    const text = "harmless words then BADSECRET and after";
    const e = fakeEngine();
    const r = await feed(new OutputScreen(e.scan, opts({ holdBack: 0, minSegment: 1 })), chunked(text, 3));
    // Each chunk is scanned and released on its own, so no scan ever sees "BADSECRET" whole.
    expect(r.blocked).toBeNull();
    expect(r.text).toBe(text);
  });

  it("applies the OUTPUT policy: masked text is what is released, the raw value never is, even when split", async () => {
    const text = "contact alice@b.co for details, thanks";
    for (const size of [1, 2, 5, 100]) {
      const e = fakeEngine();
      const r = await feed(new OutputScreen(e.scan, opts({ holdBack: 30, minSegment: 1 })), chunked(text, size));
      expect(r.text).toBe("contact a***@b.co for details, thanks");
      expect(r.text).not.toContain("alice");
      expect(r.blocked).toBeNull();
    }
  });

  it("rescans only sanitized text (the retained tail is the masked form)", async () => {
    const e = fakeEngine();
    await feed(new OutputScreen(e.scan, opts({ holdBack: 40, minSegment: 1 })), ["mail alice@b.co now, and ", "some more words to force ", "another scan of the buffer"]);
    const later = e.scanned.slice(1);
    expect(later.length).toBeGreaterThan(0);
    expect(later.some((t) => t.includes("alice@b.co"))).toBe(false);
  });
});

describe("OutputScreen: blocking", () => {
  it("a policy block withholds everything not yet released and reports the scan", async () => {
    const e = fakeEngine();
    const screen = new OutputScreen(e.scan, opts({ holdBack: 10, minSegment: 1 }));
    const r = await feed(screen, ["clean start of the answer. ", "BADSECRET ", "never seen"]);
    expect(r.blocked).toMatchObject({ kind: "blocked", reason: "policy" });
    expect(r.text).not.toContain("BADSECRET");
    expect(screen.held).toBe(0);
    expect(screen.summary()?.decision).toBe("BLOCK");
  });

  it("an engine failure fails closed (nothing more is released)", async () => {
    const e = fakeEngine();
    const screen = new OutputScreen(e.scan, opts({ holdBack: 5, minSegment: 1 }));
    expect((await screen.push("some words here")).kind).toBe("text");
    e.setDown(true);
    const r = await screen.push("and more words afterwards");
    expect(r).toMatchObject({ kind: "blocked", reason: "policy" });
    expect(screen.summary()).toMatchObject({ decision: "BLOCK", failed_closed: true });
  });

  it("output beyond the cap is blocked without being scanned or released", async () => {
    const e = fakeEngine();
    const screen = new OutputScreen(e.scan, opts({ holdBack: 5, minSegment: 1, maxChars: 50 }));
    expect((await screen.push("x".repeat(40))).kind).toBe("text");
    const before = e.scanned.length;
    const r = await screen.push("y".repeat(40));
    expect(r).toMatchObject({ kind: "blocked", reason: "output_too_large" });
    expect(e.scanned.length).toBe(before);
    expect(screen.summary()).toMatchObject({ decision: "BLOCK", failed_closed: true, fail_closed_reason: "output_too_large" });
  });
});

describe("OutputScreen: buffered mode and edges", () => {
  it("buffered mode releases NOTHING until the whole reply has been scanned once", async () => {
    const e = fakeEngine();
    const screen = new OutputScreen(e.scan, opts({ holdBack: Number.POSITIVE_INFINITY }));
    for (const c of chunked("a fairly long reply that streams in pieces ".repeat(10), 9)) expect(await screen.push(c)).toEqual({ kind: "text", text: "" });
    expect(e.scanned).toHaveLength(0);
    const r = await screen.finish();
    expect(r.kind === "text" && r.text.length).toBe("a fairly long reply that streams in pieces ".repeat(10).length);
    expect(e.scanned).toHaveLength(1);
  });

  it("buffered mode blocks a secret anywhere in the reply with nothing having been released", async () => {
    const e = fakeEngine();
    const screen = new OutputScreen(e.scan, opts({ holdBack: Number.POSITIVE_INFINITY }));
    const r = await feed(screen, chunked("start ".repeat(50) + "BADSECRET" + " end".repeat(50), 7));
    expect(r.blocked?.kind).toBe("blocked");
    expect(r.text).toBe("");
  });

  it("never splits a surrogate pair at the release boundary", async () => {
    const e = fakeEngine();
    const text = "🙂".repeat(30);
    for (const hb of [1, 2, 3, 5, 7]) {
      const r = await feed(new OutputScreen(e.scan, opts({ holdBack: hb, minSegment: 1 })), chunked(text, 1));
      for (const piece of r.released) expect(piece === "" || !/[\ud800-\udbff]$/.test(piece)).toBe(true);
      expect(r.text).toBe(text);
    }
  });

  it("an empty reply is still scanned once (so it is audited) and finish is idempotent", async () => {
    const e = fakeEngine();
    const screen = new OutputScreen(e.scan, opts());
    expect(await screen.finish()).toEqual({ kind: "text", text: "" });
    expect(e.scanned).toEqual([""]);
    expect(await screen.finish()).toEqual({ kind: "text", text: "" });
    expect(e.scanned).toHaveLength(1);
    expect(screen.summary()?.decision).toBe("ALLOW");
  });

  it("the summary reports the worst decision across all segments, with no text", async () => {
    const e = fakeEngine();
    const screen = new OutputScreen(e.scan, opts({ holdBack: 5, minSegment: 1 }));
    await feed(screen, ["hello there friend, ", "write to alice@b.co ", "and again later on"]);
    const s = screen.summary()!;
    expect(s.decision).toBe("MASK");
    expect(s.sanitized_text).toBeNull();
    expect(new OutputScreen(e.scan, opts()).summary()).toBeNull();
  });
});
