import { createHash } from "node:crypto";
import { z } from "zod";

const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type FindingSeverity = (typeof SEVERITIES)[number];
export interface FileFinding { type: string; severity: FindingSeverity; detail: string }

export interface ExtractResult {
  file: { sha256: string; size: number; detectedType: string | null; mime: string | null };
  verdict: "OK" | "BLOCK";
  blockReason: string | null;
  /** Empty whenever verdict is BLOCK. */
  text: string;
  pages: number | null;
  ocrUsed: boolean;
  findings: FileFinding[];
  /** true when the BLOCK is because scanning infrastructure failed (not because the file itself is dangerous). */
  infrastructureFailure: boolean;
}

export interface DocumentScanner {
  /** Never throws and never returns unsafe output: any failure becomes a BLOCK result. */
  extract(data: Buffer, extension: string | null): Promise<ExtractResult>;
  ready(): Promise<boolean>;
}

const Wire = z.object({
  file: z.object({ sha256: z.string().regex(/^[0-9a-f]{64}$/), size: z.number().int().min(0), detected_type: z.string().nullable(), mime: z.string().nullable() }),
  verdict: z.enum(["OK", "BLOCK"]),
  block_reason: z.string().nullable(),
  text: z.string(),
  text_chars: z.number().int(),
  pages: z.number().int().nullable(),
  ocr_used: z.boolean(),
  findings: z.array(z.object({ type: z.string(), severity: z.enum(SEVERITIES), detail: z.string() })),
});

const sha256 = (b: Buffer) => createHash("sha256").update(b).digest("hex");

/** A BLOCK produced by the gateway itself when it cannot obtain a trustworthy extraction. */
export function scannerFailure(data: Buffer, reason: string): ExtractResult {
  return {
    file: { sha256: sha256(data), size: data.length, detectedType: null, mime: null }, verdict: "BLOCK", blockReason: reason, text: "", pages: null,
    ocrUsed: false, findings: [{ type: "scanner_failure", severity: "HIGH", detail: reason }], infrastructureFailure: true,
  };
}

export interface HttpDocumentScannerOptions { baseUrl: string; token?: string | undefined; timeoutMs: number; fetch?: typeof fetch }

export class HttpDocumentScanner implements DocumentScanner {
  private readonly f: typeof fetch;
  constructor(private readonly o: HttpDocumentScannerOptions) { this.f = o.fetch ?? fetch; }

  async extract(data: Buffer, extension: string | null): Promise<ExtractResult> {
    let res: Response;
    try {
      res = await this.f(`${this.o.baseUrl}/v1/extract`, {
        method: "POST",
        headers: {
          "content-type": "application/octet-stream",
          // A synthetic name: the caller's real filename never leaves the gateway (it can itself contain personal data).
          ...(extension ? { "x-filename": `upload${extension}` } : {}),
          ...(this.o.token ? { "x-internal-token": this.o.token } : {}),
        },
        body: new Uint8Array(data),
        signal: AbortSignal.timeout(this.o.timeoutMs),
      });
    } catch (err) {
      const timeout = err instanceof DOMException && (err.name === "TimeoutError" || err.name === "AbortError");
      return scannerFailure(data, timeout ? "scanner_timeout" : "scanner_unreachable");
    }
    if (!res.ok) return scannerFailure(data, `scanner_http_${res.status}`);

    let parsed: ReturnType<typeof Wire.safeParse>;
    try { parsed = Wire.safeParse(await res.json()); } catch { return scannerFailure(data, "scanner_invalid_response"); }
    if (!parsed.success) return scannerFailure(data, "scanner_invalid_response");
    const w = parsed.data;

    // Integrity + invariants: the scanner must have examined exactly the bytes we sent, and BLOCK must never carry text.
    if (w.file.sha256 !== sha256(data) || w.file.size !== data.length) return scannerFailure(data, "scanner_integrity_mismatch");
    if (w.verdict === "BLOCK" && (w.text !== "" || !w.block_reason)) return scannerFailure(data, "scanner_invariant_violation");
    if (w.verdict === "OK" && w.block_reason !== null) return scannerFailure(data, "scanner_invariant_violation");

    return {
      file: { sha256: w.file.sha256, size: w.file.size, detectedType: w.file.detected_type, mime: w.file.mime },
      verdict: w.verdict, blockReason: w.block_reason, text: w.text, pages: w.pages, ocrUsed: w.ocr_used, findings: w.findings,
      infrastructureFailure: false,
    };
  }

  async ready(): Promise<boolean> {
    try { return (await this.f(`${this.o.baseUrl}/ready`, { signal: AbortSignal.timeout(this.o.timeoutMs) })).ok; } catch { return false; }
  }
}
