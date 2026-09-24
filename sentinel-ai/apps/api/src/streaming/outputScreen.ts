import type { ScanResult } from "@sentinelai/shared-types";
import { failClosedResult, withholdsContent } from "../security/securityClient.js";
import { aggregate } from "../services/secureAiService.js";

/**
 * Scan-before-release for streamed model output.
 *
 * Text is only released once the OUTPUT policy has been applied to it AND to the `holdBack` characters that follow it. The buffer
 * is re-scanned as it grows, so a secret split across chunks is still seen whole before its first half leaves the gateway. The
 * scan returns sanitized text (masking/redaction applied), and it is the sanitized text that is released and retained.
 *
 * `holdBack = Infinity` is "buffered" mode: nothing is released until the stream ends and the whole reply has been scanned at once.
 *
 * Limits (documented in docs/security/streaming.md): a sensitive value longer than `holdBack` that only becomes detectable at its
 * very end could have had its beginning released; buffered mode removes that risk at the cost of latency.
 */
export interface ScreenOptions {
  /** Characters kept back as look-ahead. Larger = safer, more latency. */
  holdBack: number;
  /** Do not bother scanning until at least this many releasable characters have accumulated. */
  minSegment: number;
  /** Total output cap (also bounded by the engine's own input limit). */
  maxChars: number;
}

export type ScreenResult =
  | { kind: "text"; text: string }
  | { kind: "blocked"; scan: ScanResult; reason: "policy" | "output_too_large" };

export type OutputScan = (text: string) => Promise<ScanResult>;

const isHighSurrogate = (code: number): boolean => code >= 0xd800 && code <= 0xdbff;

export class OutputScreen {
  private buf = "";
  private total = 0;
  private readonly scans: ScanResult[] = [];

  constructor(private readonly scan: OutputScan, private readonly o: ScreenOptions) {}

  /** Characters currently held (scanned but not yet released, or not yet scanned). */
  get held(): number { return this.buf.length; }

  async push(delta: string): Promise<ScreenResult> {
    this.total += delta.length;
    if (this.total > this.o.maxChars) return this.tooLarge();
    this.buf += delta;
    if (this.buf.length - this.o.holdBack < this.o.minSegment) return { kind: "text", text: "" };
    return this.release(false);
  }

  /** End of stream: scan what is left and release all of it. Always scans at least once so the reply is always audited. */
  async finish(): Promise<ScreenResult> {
    if (this.buf === "" && this.scans.length > 0) return { kind: "text", text: "" };
    return this.release(true);
  }

  /** One aggregate of every scan performed (worst decision, worst risk, union of detections). Null if nothing was scanned. */
  summary(): ScanResult | null { return this.scans.length === 0 ? null : aggregate(this.scans); }

  private async release(final: boolean): Promise<ScreenResult> {
    const r = await this.scan(this.buf);
    this.scans.push(r);
    // Same invariants as the input path: anything short of a clean, content-bearing verdict withholds everything not yet released.
    if (withholdsContent(r.decision) || r.sanitized_text === null) { this.buf = ""; return { kind: "blocked", scan: r, reason: "policy" }; }
    const s = r.sanitized_text;
    let cut = final ? s.length : Math.max(0, s.length - this.o.holdBack);
    if (cut > 0 && cut < s.length && isHighSurrogate(s.charCodeAt(cut - 1))) cut -= 1;   // never split an emoji in half
    this.buf = s.slice(cut);
    return { kind: "text", text: s.slice(0, cut) };
  }

  private tooLarge(): ScreenResult {
    const scan = failClosedResult("output_too_large");
    this.scans.push(scan);
    this.buf = "";
    return { kind: "blocked", scan, reason: "output_too_large" };
  }
}
