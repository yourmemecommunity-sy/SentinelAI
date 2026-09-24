"use client";
import { useRef, useState } from "react";
import { ActionBadge, Button, Card, Chip, Notice, RiskBadge } from "@/components/ui/primitives";
import { describeError, uploadFile } from "@/lib/api/client";
import type { FileScanResponse } from "@/types/api";

/** Advisory only (fast feedback): the gateway and document scanner enforce type and size from the file's content. */
export const ACCEPT = ".pdf,.docx,.xlsx,.csv,.txt,.json,.png,.jpg,.jpeg,.gif,.webp";
export const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;
const PREVIEW_CHARS = 5_000;

/** Plain-language reasons for the scanner's machine codes. Unknown codes are shown as-is (never hidden). */
const REASONS: Record<string, string> = {
  macros_present: "The document contains macros.",
  pdf_active_content: "The PDF contains active content (JavaScript, launch actions or embedded files).",
  active_content: "The file contains active content.",
  embedded_objects: "The document embeds other objects.",
  executable_content: "The file contains executable content.",
  malware_detected: "The malware scan flagged this file.",
  malware_scan_failed: "The malware scan could not complete, so the file was not trusted.",
  extension_mismatch: "The file's content does not match its extension.",
  unsupported_type: "This file type is not supported.",
  encrypted_document: "The document is encrypted and cannot be inspected.",
  zip_bomb: "The archive expands to an unsafe size.",
  zip_anomaly: "The archive structure is malformed or suspicious.",
  xml_attack: "The document contains a malicious XML construct.",
  external_reference: "The document loads content from an external location.",
  file_too_large: "The file is larger than the allowed size.",
  text_too_large: "The file contains more text than can be safely inspected.",
  page_limit: "The document has more pages than can be safely inspected.",
  ocr_unavailable: "Text recognition for images is unavailable, so the image was not trusted.",
  ocr_failed: "Text recognition failed, so the image was not trusted.",
  parse_error: "The file could not be read safely.",
  extraction_timeout: "Reading the file took too long.",
  extraction_crashed: "The file could not be read safely.",
  empty_file: "The file is empty.",
  scanner_unreachable: "The file scanner is unavailable, so nothing was released.",
  scanner_timeout: "The file scanner timed out, so nothing was released.",
};
export const describeReason = (r: string | null): string => (r ? REASONS[r] ?? `Blocked (${r}).` : "Blocked.");

const FINDING_LABELS: Record<string, string> = {
  hidden_text: "Hidden text (invisible to a reader, visible to a model)",
  external_resource: "Loads an external resource",
  external_hyperlink: "Contains external links",
  tracked_deletions: "Contains tracked deletions",
  hidden_sheet: "Contains hidden sheets",
  ocr_no_text: "No text was recognised in this image",
  no_extractable_text: "No text could be extracted",
  malware_scan_baseline_only: "Only the development malware baseline is active (not a real antivirus)",
};

const kb = (n: number) => (n >= 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);

/**
 * Upload a file to be scanned with the organization's real policy. The file is held in memory only (never stored); the
 * resulting event stores metadata, not content. The file's name is never sent, only its extension.
 */
export function FileScanner({ onScanned }: { onScanned?: () => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<FileScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const choose = (f: File | null) => {
    setResult(null); setError(null);
    if (f && f.size === 0) { setFile(null); setError("That file is empty."); return; }
    if (f && f.size > MAX_UPLOAD_BYTES) { setFile(null); setError(`That file is larger than ${kb(MAX_UPLOAD_BYTES)}.`); return; }
    setFile(f);
  };

  const run = async () => {
    if (!file) return;
    setBusy(true); setError(null); setResult(null);
    try { setResult(await uploadFile<FileScanResponse>(file)); onScanned?.(); }
    catch (e) { setError(describeError(e)); }
    finally { setBusy(false); }
  };

  const text = result?.sanitized_text ?? null;
  return (
    <Card title="Scan a file">
      <p className="mb-2 text-xs text-slate-500">
        PDF, DOCX, XLSX, CSV, TXT, JSON and images (up to {kb(MAX_UPLOAD_BYTES)}). The file is checked for malware and hidden or active content, its text is
        extracted and scanned with your organization&apos;s policy, and it is never stored. Only the extension is sent, not the file name. Do not upload real customer data to test.
      </p>
      <label htmlFor="file-input" className="sr-only">File to scan</label>
      <input ref={input} id="file-input" type="file" accept={ACCEPT} onChange={(e) => choose(e.target.files?.[0] ?? null)}
        className="block w-full text-sm file:mr-3 file:rounded-md file:border-0 file:bg-slate-100 file:px-3 file:py-1.5 dark:file:bg-slate-800" />
      <div className="mt-2 flex items-center gap-3">
        <Button onClick={run} disabled={busy || !file}>{busy ? "Scanning..." : "Scan file"}</Button>
        {file && <span className="text-xs text-slate-500">{kb(file.size)} selected</span>}
      </div>
      {error && <div className="mt-3"><Notice>{error}</Notice></div>}

      {result && (
        <div className="mt-3 space-y-3 text-sm" aria-live="polite">
          <div className="flex flex-wrap items-center gap-2">
            <ActionBadge action={result.decision} /> <RiskBadge level={result.risk.risk_level} /> <span className="text-xs text-slate-500">risk {result.risk.risk_score}</span>
            {result.failed_closed && <Notice>Failed closed: nothing could be verified safe.</Notice>}
          </div>

          {result.blocked && <Notice>{describeReason(result.reason)} Nothing from this file would be sent to a model.</Notice>}

          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-4">
            <div><dt className="text-slate-500">Type</dt><dd>{result.file.detected_type ?? "unknown"}</dd></div>
            <div><dt className="text-slate-500">Size</dt><dd>{kb(result.file.size)}</dd></div>
            <div><dt className="text-slate-500">Pages</dt><dd>{result.file.pages ?? "-"}</dd></div>
            <div><dt className="text-slate-500">Text recognition</dt><dd>{result.file.ocr_used ? "used" : "not needed"}</dd></div>
            <div className="col-span-2 sm:col-span-4"><dt className="text-slate-500">SHA-256</dt><dd className="break-all font-mono">{result.file.sha256}</dd></div>
          </dl>

          {result.findings.length > 0 && (
            <div>
              <p className="text-xs font-medium text-slate-500">Findings</p>
              <ul className="list-disc pl-5 text-xs">
                {result.findings.map((f, i) => <li key={i}>{FINDING_LABELS[f.type] ?? f.type} <span className="text-slate-500">({f.severity.toLowerCase()})</span></li>)}
              </ul>
            </div>
          )}

          {result.detections.length > 0 && <div className="flex flex-wrap gap-1">{result.detections.map((d, i) => <Chip key={i}>{d.entity} {(d.confidence * 100).toFixed(0)}%</Chip>)}</div>}

          {text !== null && (
            <div>
              <p className="text-xs font-medium text-slate-500">What the model would receive{text.length > PREVIEW_CHARS ? ` (first ${PREVIEW_CHARS.toLocaleString()} of ${text.length.toLocaleString()} characters)` : ""}</p>
              <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded bg-slate-100 p-2 text-xs dark:bg-slate-800">{text.slice(0, PREVIEW_CHARS)}</pre>
            </div>
          )}

          {result.risk.factors.length > 0 && (
            <details><summary className="cursor-pointer text-xs text-slate-500">Why this risk score</summary>
              <ul className="mt-1 list-disc pl-5 text-xs">{result.risk.factors.map((f) => <li key={f.name}>{f.name}: +{f.contribution} - {f.detail}</li>)}</ul></details>
          )}
        </div>
      )}
    </Card>
  );
}
