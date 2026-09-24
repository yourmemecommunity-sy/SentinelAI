// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ACCEPT, FileScanner, MAX_UPLOAD_BYTES, describeReason } from "@/components/dashboard/FileScanner";
import { ApiError, uploadFile } from "@/lib/api/client";
import type { FileScanResponse } from "@/types/api";

vi.mock("@/lib/api/client", async (orig) => ({ ...(await orig<typeof import("@/lib/api/client")>()), uploadFile: vi.fn() }));
const upload = vi.mocked(uploadFile);
afterEach(() => { cleanup(); upload.mockReset(); });

const RISK = { risk_score: 45, risk_level: "MEDIUM", decision: "REDACT", factors: [{ name: "data_sensitivity", contribution: 30, detail: "EMAIL" }] } as const;
const ok = (over: Partial<FileScanResponse> = {}): FileScanResponse => ({
  event_id: "e1", decision: "REDACT", blocked: false, failed_closed: false, reason: null,
  file: { sha256: "a".repeat(64), size: 2048, detected_type: "docx", mime: "application/x", pages: 3, ocr_used: false },
  findings: [], risk: { ...RISK, factors: [...RISK.factors] }, detections: [], sanitized_text: "Contact [REDACTED] please", policy_id: "p", ...over,
});
const pick = (f: File) => fireEvent.change(screen.getByLabelText("File to scan"), { target: { files: [f] } });
const file = (name = "memo.docx", size = 100) => new File([new Uint8Array(size)], name);
const scanButton = () => screen.getByRole("button", { name: /Scan file|Scanning/ }) as HTMLButtonElement;

describe("FileScanner", () => {
  it("the button is disabled until a file is chosen; it uploads exactly the chosen file and shows the verdict", async () => {
    upload.mockResolvedValue(ok({ findings: [{ type: "hidden_text", severity: "MEDIUM", detail: "vanish" }], detections: [{ entity: "EMAIL", confidence: 0.9, severity: "MEDIUM", location: { start: 0, end: 1 }, detector: "pii" }] }));
    const onScanned = vi.fn();
    render(<FileScanner onScanned={onScanned} />);
    expect(scanButton().disabled).toBe(true);
    const f = file();
    pick(f);
    expect(scanButton().disabled).toBe(false);
    fireEvent.click(scanButton());
    await waitFor(() => expect(screen.getByText("Contact [REDACTED] please")).toBeTruthy());
    expect(upload).toHaveBeenCalledTimes(1);
    expect(upload.mock.calls[0]![0]).toBe(f);
    expect(screen.getByText(/What the model would receive/)).toBeTruthy();
    expect(screen.getByText(/Hidden text/)).toBeTruthy();
    expect(screen.getByText(/EMAIL 90%/)).toBeTruthy();
    expect(screen.getByText("docx")).toBeTruthy();
    expect(screen.getByText("a".repeat(64))).toBeTruthy();
    expect(onScanned).toHaveBeenCalled();
  });

  it("a BLOCK shows a plain-language reason and NO text, and says nothing would reach a model", async () => {
    upload.mockResolvedValue(ok({ decision: "BLOCK", blocked: true, reason: "macros_present", sanitized_text: null, findings: [{ type: "macros_present", severity: "CRITICAL", detail: "vba" }] }));
    render(<FileScanner />);
    pick(file());
    fireEvent.click(scanButton());
    await waitFor(() => expect(screen.getByText(/contains macros/)).toBeTruthy());
    expect(screen.getByText(/Nothing from this file would be sent to a model/)).toBeTruthy();
    expect(screen.queryByText(/What the model would receive/)).toBeNull();
  });

  it("a fail-closed result is announced as such", async () => {
    upload.mockResolvedValue(ok({ decision: "BLOCK", blocked: true, failed_closed: true, reason: "scanner_unreachable", sanitized_text: null }));
    render(<FileScanner />);
    pick(file());
    fireEvent.click(scanButton());
    await waitFor(() => expect(screen.getByText(/Failed closed/)).toBeTruthy());
    expect(screen.getByText(/scanner is unavailable/)).toBeTruthy();
  });

  it("very long extracted text is truncated in the preview only (with the true length stated)", async () => {
    upload.mockResolvedValue(ok({ sanitized_text: "x".repeat(6_000) }));
    const { container } = render(<FileScanner />);
    pick(file());
    fireEvent.click(scanButton());
    await waitFor(() => expect(screen.getByText(/first 5,000 of 6,000 characters/)).toBeTruthy());
    expect(container.querySelector("pre")!.textContent).toHaveLength(5_000);
  });

  it("rejects empty and oversize files in the browser without uploading, and clears an earlier result", async () => {
    upload.mockResolvedValue(ok());
    render(<FileScanner />);
    pick(file("a.txt", 10));
    fireEvent.click(scanButton());
    await waitFor(() => expect(screen.getByText("Contact [REDACTED] please")).toBeTruthy());

    pick(new File([], "empty.txt"));
    expect(screen.getByText(/empty/)).toBeTruthy();
    expect(screen.queryByText("Contact [REDACTED] please")).toBeNull();
    expect(scanButton().disabled).toBe(true);

    pick({ name: "big.pdf", size: MAX_UPLOAD_BYTES + 1 } as unknown as File);
    expect(screen.getByText(/larger than/)).toBeTruthy();
    expect(scanButton().disabled).toBe(true);
    expect(upload).toHaveBeenCalledTimes(1);
  });

  it("shows a friendly error for permission (403), rate-limit (429) and network failures, and never a result", async () => {
    for (const [err, msg] of [[new ApiError(403, "forbidden"), /do not have permission/], [new ApiError(429, "rate_limited"), /Too many requests/], [new ApiError(0, "network_error"), /unreachable/]] as const) {
      upload.mockRejectedValueOnce(err);
      render(<FileScanner />);
      pick(file());
      fireEvent.click(scanButton());
      await waitFor(() => expect(screen.getByText(msg)).toBeTruthy());
      expect(screen.queryByText(/What the model would receive/)).toBeNull();
      cleanup();
    }
  });

  it("prevents double submission while a scan is running", async () => {
    let resolve!: (v: FileScanResponse) => void;
    upload.mockReturnValue(new Promise<FileScanResponse>((r) => { resolve = r; }));
    render(<FileScanner />);
    pick(file());
    fireEvent.click(scanButton());
    await waitFor(() => expect(scanButton().textContent).toMatch(/Scanning/));
    expect(scanButton().disabled).toBe(true);
    fireEvent.click(scanButton());
    expect(upload).toHaveBeenCalledTimes(1);
    resolve(ok());
    await waitFor(() => expect(scanButton().textContent).toBe("Scan file"));
  });

  it("escapes hostile document text and file facts instead of interpreting them as HTML", async () => {
    upload.mockResolvedValue(ok({ sanitized_text: "<img src=x onerror=alert(1)><script>alert(1)</script>", findings: [{ type: "<b>weird</b>", severity: "LOW", detail: "d" }] }));
    const { container } = render(<FileScanner />);
    pick(file());
    fireEvent.click(scanButton());
    await waitFor(() => expect(container.querySelector("pre")).not.toBeNull());
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(container.textContent).toContain("<script>alert(1)</script>");
  });

  it("the file input offers only supported types, and every scanner reason code has a message (unknown ones are shown, not hidden)", () => {
    expect(ACCEPT.split(",")).toEqual([".pdf", ".docx", ".xlsx", ".csv", ".txt", ".json", ".png", ".jpg", ".jpeg", ".gif", ".webp"]);
    expect(describeReason("pdf_active_content")).toMatch(/JavaScript/);
    expect(describeReason("some_new_reason")).toBe("Blocked (some_new_reason).");
    expect(describeReason(null)).toBe("Blocked.");
  });
});
