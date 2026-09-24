import type { FastifyInstance } from "fastify";
import { requirePermission, principalOf } from "../middleware/auth.js";
import { RateLimiter } from "../middleware/hardening.js";
import type { ApiKeyAuthenticator } from "../security/apiKeys.js";
import type { FileScanService } from "../services/fileScanService.js";
import { ContextSchema } from "../validators/schemas.js";

export interface FileRouteDeps {
  auth: ApiKeyAuthenticator;
  files: FileScanService;
  maxFileBytes: number;
  /** Uploads are expensive (parsing, malware scan, OCR), so they get a stricter per-client limit than the global one. */
  perMinute?: number;
}

/** Extension only (`.pdf`). The caller's real file name is never forwarded, stored or logged: it can itself contain personal data. */
export function extensionOf(rawHeader: unknown): string | null {
  if (typeof rawHeader !== "string" || rawHeader.length > 1024) return null;
  let name: string;
  try { name = decodeURIComponent(rawHeader); } catch { return null; }
  const m = /\.([A-Za-z0-9]{1,8})$/.exec(name.trim());
  return m ? `.${m[1]!.toLowerCase()}` : null;
}

/**
 * POST /v1/files/scan  - body: the raw file bytes (Content-Type: application/octet-stream), optional `X-Filename`.
 * Always answers 200 with a decision (BLOCK is a decision, not an error), except: 401/403 auth, 413 too large,
 * 422 empty/invalid, 429 rate limited, 503 when the scan could not be audited.
 */
export function registerFileRoutes(app: FastifyInstance, d: FileRouteDeps): void {
  const limiter = new RateLimiter(d.perMinute ?? 30);
  // Encapsulated: the raw-body parser and larger body limit apply to this route only.
  void app.register(async (scope) => {
    scope.addContentTypeParser("application/octet-stream", { parseAs: "buffer", bodyLimit: d.maxFileBytes }, (_req, body, done) => done(null, body));

    scope.post("/v1/files/scan", { bodyLimit: d.maxFileBytes, preHandler: requirePermission(d.auth, "scan:use") }, async (req, reply) => {
      const retry = limiter.check(`file:${principalOf(req).apiKeyId ?? principalOf(req).userId ?? req.ip}`);
      if (retry !== null) return reply.code(429).header("retry-after", String(retry)).send({ error: "rate_limited" });

      const body = req.body;
      if (!Buffer.isBuffer(body) || body.length === 0) return reply.code(422).send({ error: "invalid_request", issues: [{ path: "body", message: "a non-empty file body is required" }] });

      const q = ContextSchema.partial().safeParse({
        application: (req.headers["x-application"] as string | undefined), team: (req.headers["x-team"] as string | undefined),
        environment: (req.headers["x-environment"] as string | undefined),
      });
      if (!q.success) return reply.code(422).send({ error: "invalid_request", issues: q.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });

      const o = await d.files.scanFile(principalOf(req), body, extensionOf(req.headers["x-filename"]), { ...q.data, ip: req.ip });
      if (o.auditFailed) return reply.code(503).send({ error: "audit_unavailable" });

      return reply.header("cache-control", "no-store").send({
        event_id: o.eventId, decision: o.decision, blocked: o.blocked, failed_closed: o.failedClosed, reason: o.reason,
        file: { sha256: o.file.sha256, size: o.file.size, detected_type: o.file.detectedType, mime: o.file.mime, pages: o.file.pages, ocr_used: o.file.ocrUsed },
        findings: o.findings, risk: o.risk, detections: o.detections, sanitized_text: o.sanitizedText, policy_id: o.policyId,
      });
    });
  });
}
