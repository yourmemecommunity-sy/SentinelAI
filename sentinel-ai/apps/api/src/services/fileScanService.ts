import type { Action, Direction, Policy, RequestContext, RiskLevel, ScanRequest, ScanResult } from "@sentinelai/shared-types";
import { eventFromScan, type EventSink } from "../events/eventSink.js";
import type { FileRepository, FileVerdict } from "../repositories/fileRepository.js";
import type { PolicyRepository } from "../repositories/policyRepository.js";
import type { DocumentScanner, ExtractResult, FileFinding } from "../security/documentScanner.js";
import type { Principal } from "../security/rbac.js";
import { failClosedResult, withholdsContent, type SecurityScanner } from "../security/securityClient.js";

export interface FileScanOutcome {
  decision: Action;
  blocked: boolean;
  failedClosed: boolean;
  reason: string | null;
  /** The extracted text with the org policy applied; null when blocked. Forward THIS (or the original file only if decision is ALLOW). */
  sanitizedText: string | null;
  file: { sha256: string; size: number; detectedType: string | null; mime: string | null; pages: number | null; ocrUsed: boolean };
  findings: FileFinding[];
  risk: ScanResult["risk"];
  detections: ScanResult["detections"];
  policyId: string;
  eventId: string | null;
  auditFailed: boolean;
}

const SEV_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 } as const;
const worst = (fs: FileFinding[]) => fs.reduce<FileFinding["severity"]>((a, f) => (SEV_RANK[f.severity] > SEV_RANK[a] ? f.severity : a), "INFO");

/** Findings that mean "this file tried to hide or reach outside itself": they raise risk even when nothing sensitive is detected. */
const SUSPICIOUS = new Set(["hidden_text", "hidden_sheet", "external_resource", "external_links", "tracked_deletions"]);

export interface FileScanDeps { documents: DocumentScanner; scanner: SecurityScanner; policies: PolicyRepository; events: EventSink; files: FileRepository }

export class FileScanService {
  constructor(private readonly d: FileScanDeps) {}

  private ctx(p: Principal, meta: { application?: string | undefined; team?: string | undefined; environment?: string | undefined; ip?: string | undefined }): RequestContext {
    return {
      ...(p.userId ?? p.apiKeyId ? { user_id: p.userId ?? `api_key:${p.apiKeyId}` } : {}),
      ...(meta.application ? { application: meta.application } : {}), ...(meta.team ? { team: meta.team } : {}),
      ...(meta.environment ? { environment: meta.environment } : {}), ...(meta.ip ? { ip: meta.ip } : {}),
    } as RequestContext;
  }

  /** A decision made from the FILE itself (macros, malware, unparseable...) without involving the text engine. */
  private contentBlock(x: ExtractResult): ScanResult {
    const sev = worst(x.findings);
    const level: RiskLevel = sev === "CRITICAL" ? "CRITICAL" : sev === "HIGH" ? "HIGH" : "MEDIUM";
    const score = level === "CRITICAL" ? 95 : level === "HIGH" ? 75 : 50;
    const base = failClosedResult(x.blockReason ?? "blocked", "file-scan");
    return {
      ...base, failed_closed: x.infrastructureFailure, fail_closed_reason: x.infrastructureFailure ? x.blockReason : null,
      risk: { risk_score: score, risk_level: level, decision: "BLOCK",
        factors: [{ name: "file_verdict", contribution: score, detail: x.blockReason ?? "blocked" }, ...x.findings.filter((f) => SEV_RANK[f.severity] >= 2).map((f) => ({ name: f.type, contribution: 0, detail: f.detail }))] },
      detector_version: "document-scanner",
    };
  }

  async scanFile(p: Principal, data: Buffer, extension: string | null,
    meta: { application?: string | undefined; team?: string | undefined; environment?: string | undefined; ip?: string | undefined } = {}): Promise<FileScanOutcome> {
    const extract = await this.d.documents.extract(data, extension);

    let scan: ScanResult;
    let policyId = "sentinelai-baseline";
    if (extract.verdict === "BLOCK") {
      scan = this.contentBlock(extract);
    } else {
      let policy: Policy | undefined;
      let policyFailed = false;
      try { policy = await this.d.policies.getEffectivePolicy(p.organizationId); } catch { policyFailed = true; }
      if (policyFailed) scan = failClosedResult("policy_unavailable", "file-scan");
      else {
        const req: ScanRequest = { text: extract.text, direction: "INPUT" as Direction, organization_id: p.organizationId, context: this.ctx(p, meta), ...(policy ? { policy } : {}) };
        scan = await this.d.scanner.scan(req);
      }
      policyId = scan.policy_id;
      // Hidden/external constructs raise the risk floor even when the text engine found nothing sensitive.
      const suspicious = extract.findings.filter((f) => SUSPICIOUS.has(f.type));
      if (suspicious.length && !withholdsContent(scan.decision) && scan.risk.risk_score < 40) {
        scan = { ...scan, risk: { ...scan.risk, risk_score: 40, risk_level: scan.risk.risk_level === "LOW" ? "MEDIUM" : scan.risk.risk_level,
          factors: [...scan.risk.factors, ...suspicious.map((f) => ({ name: f.type, contribution: 0, detail: f.detail }))] } };
      }
    }

    let eventId: string | null = null;
    try {
      eventId = await this.d.events.record(eventFromScan({
        organizationId: p.organizationId, userId: p.userId, apiKeyId: p.apiKeyId, application: meta.application ?? null, provider: null, model: null,
        direction: "INPUT", eventType: scan.failed_closed ? "fail_closed" : "file_scan",
      }, scan));
    } catch { /* handled below */ }

    // An unauditable scan is never reported as a success: fail closed and return no text.
    if (eventId === null) {
      const fc = failClosedResult("audit_unavailable", scan.policy_id);
      return this.outcome(extract, fc, null, true);
    }

    const verdict: FileVerdict = extract.infrastructureFailure ? "ERROR" : withholdsContent(scan.decision) ? "BLOCKED" : scan.decision === "ALLOW" ? "CLEAN" : "SANITIZED";
    void this.d.files.record(p.organizationId, {
      sha256: extract.file.sha256, mime: extract.file.mime, sizeBytes: extract.file.size, verdict,
      findings: extract.findings.map((f) => ({ type: f.type, severity: f.severity })),
    }).catch(() => undefined);   // metadata only; not security-critical, never blocks the response

    return this.outcome(extract, scan, eventId, false, policyId);
  }

  private outcome(x: ExtractResult, scan: ScanResult, eventId: string | null, auditFailed: boolean, policyId = scan.policy_id): FileScanOutcome {
    const blocked = withholdsContent(scan.decision) || scan.sanitized_text === null;
    return {
      decision: blocked && !withholdsContent(scan.decision) ? "BLOCK" : scan.decision, blocked, failedClosed: scan.failed_closed, reason: scan.fail_closed_reason ?? x.blockReason,
      sanitizedText: blocked ? null : scan.sanitized_text, findings: x.findings, risk: scan.risk, detections: scan.detections, policyId, eventId, auditFailed,
      file: { sha256: x.file.sha256, size: x.file.size, detectedType: x.file.detectedType, mime: x.file.mime, pages: x.pages, ocrUsed: x.ocrUsed },
    };
  }
}
