import type { FastifyInstance, FastifyReply } from "fastify";
import { z } from "zod";
import type { AppConfig } from "../config/env.js";
import { registerApiKeyRoutes } from "./apiKeyRoutes.js";
import { registerFileRoutes } from "./fileRoutes.js";
import { registerStreamRoutes } from "./streamRoutes.js";
import type { SecureStreamService } from "../services/secureStreamService.js";
import { deriveVaultSession, type TokenVault } from "../security/tokenVault.js";
import type { FileScanService } from "../services/fileScanService.js";
import type { DocumentScanner } from "../security/documentScanner.js";
import type { ApiKeyRepository } from "../repositories/apiKeyRepository.js";
import { registerAuthRoutes } from "./authRoutes.js";
import { registerDirectoryRoutes } from "./directoryRoutes.js";
import { registerProviderRoutes } from "./providerRoutes.js";
import type { DirectoryRepository } from "../repositories/directoryRepository.js";
import type { ProviderRepository } from "../repositories/providerRepository.js";
import type { RouterSource } from "../providers/orgRouters.js";
import type { CredentialCipher } from "../security/credentialCipher.js";
import type { AuthService } from "../services/authService.js";
import type { AuditLogWriter } from "../events/auditLog.js";
import { eventToWire, type EventSink } from "../events/eventSink.js";
import { principalOf, requirePermission } from "../middleware/auth.js";
import type { PolicyRepository } from "../repositories/policyRepository.js";
import type { ApiKeyAuthenticator } from "../security/apiKeys.js";
import type { SecurityScanner } from "../security/securityClient.js";
import type { ChatOutcome, SecureAiService } from "../services/secureAiService.js";
import {
  ChatBodySchema, EventsQuerySchema, GenerateBodySchema, PolicyBodySchema, PolicyUpdateSchema, ScanBodySchema, UsageQuerySchema,
} from "../validators/schemas.js";

export interface RouteDeps {
  config: AppConfig;
  auth: ApiKeyAuthenticator;
  service: SecureAiService;
  events: EventSink;
  policies: PolicyRepository;
  auditLog: AuditLogWriter;
  scanner: SecurityScanner;
  ping: () => Promise<boolean>;
  /** When absent, /v1/files/scan is not registered (there is no unscanned path: files simply cannot be submitted). */
  fileScan?: FileScanService;
  documents?: DocumentScanner;
  /** When absent, /v1/ai/stream is not registered. */
  streaming?: SecureStreamService;
  /** Token vault (hydration of tokenized values). When absent, `session_id` is ignored and replies are never hydrated. */
  vault?: TokenVault;
  /** When absent, /v1/api-keys is not registered. */
  apiKeys?: ApiKeyRepository;
  /** When absent, /v1/auth/* is not registered (API-key access only). */
  authService?: AuthService;
  signupEnabled?: boolean;
  /** Attempts/min for /v1/auth/*: per client IP and per login email. Defaults are production-strict (20 / 10). */
  authLimits?: { ipPerMinute: number; emailPerMinute: number };
  /** When absent, /v1/users, /v1/invitations and /v1/teams are not registered. */
  directory?: DirectoryRepository;
  /** When absent, /v1/providers is not registered. */
  providerSettings?: { repo: ProviderRepository; routers: RouterSource; cipher: CredentialCipher | undefined; platformProviders: string[] };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (s: string): boolean => UUID_RE.test(s);

export function sendChatOutcome(reply: FastifyReply, o: ChatOutcome) {
  switch (o.kind) {
    case "ok":
      return reply.send({
        provider: o.provider, model: o.model, content: o.content, ...(o.hydration ? { hydration: o.hydration } : {}),
        security: {
          input: { decision: o.input.decision, risk_level: o.input.riskLevel, event_id: o.input.eventId },
          output: { decision: o.output.decision, risk_level: o.output.riskLevel, event_id: o.output.eventId },
        },
      });
    case "blocked":
      return reply.code(403).send({ error: "blocked", stage: o.stage, decision: o.decision, failed_closed: o.failedClosed, reason: o.reason, event_id: o.eventId });
    case "provider_error":
      return reply.code(502).send({ error: "provider_error", code: o.code, event_id: o.eventId });
    case "audit_unavailable":
      return reply.code(503).send({ error: "audit_unavailable", stage: o.stage });
  }
}

export function registerRoutes(app: FastifyInstance, d: RouteDeps): void {
  const tooLarge = (reply: FastifyReply) => reply.code(413).send({ error: "payload_too_large" });
  const textLen = (parts: string[]) => parts.reduce((n, s) => n + s.length, 0);

  // ---------------------------------------------------------------- health
  app.get("/health", async () => ({ status: "alive", service: "api" }));
  app.get("/ready", async (_req, reply) => {
    const [engine, db, docs] = await Promise.all([d.scanner.ready(), d.ping(), d.documents ? d.documents.ready() : Promise.resolve(true)]);
    const ok = engine && db && docs;
    return reply.code(ok ? 200 : 503).send({ status: ok ? "ready" : "not_ready", security_engine: engine, database: db, ...(d.documents ? { document_scanner: docs } : {}),
      // Informational: a vault outage fails only tokenizing requests closed (and degrades hydration), so it does not make the gateway unready.
      ...(d.vault ? { token_vault: await d.vault.ready() } : {}) });
  });

  if (d.fileScan) registerFileRoutes(app, { auth: d.auth, files: d.fileScan, maxFileBytes: d.config.maxFileBytes });
  if (d.streaming) registerStreamRoutes(app, { auth: d.auth, streaming: d.streaming, vault: d.vault, config: d.config, sendOutcome: sendChatOutcome as never });
  if (d.apiKeys) registerApiKeyRoutes(app, { auth: d.auth, keys: d.apiKeys, auditLog: d.auditLog });
  if (d.directory) registerDirectoryRoutes(app, { auth: d.auth, directory: d.directory, auditLog: d.auditLog, pepper: d.config.apiKeyPepper,
    ...(d.authLimits ? { acceptLimit: d.authLimits.ipPerMinute } : {}) });
  if (d.providerSettings) registerProviderRoutes(app, { auth: d.auth, auditLog: d.auditLog, ...d.providerSettings });
  if (d.authService) registerAuthRoutes(app, { authService: d.authService, auth: d.auth, signupEnabled: d.signupEnabled ?? false,
    ...(d.authLimits ? { ipLimit: d.authLimits.ipPerMinute, emailLimit: d.authLimits.emailPerMinute } : {}) });

  // ---------------------------------------------------------------- security scan
  app.post("/v1/security/scan", { preHandler: requirePermission(d.auth, "scan:use") }, async (req, reply) => {
    const body = ScanBodySchema.parse(req.body);
    if (body.text.length > d.config.maxInputChars) return tooLarge(reply);
    const out = await d.service.scanText(principalOf(req), body.text, body.direction, { ...body.context, ip: req.ip });
    if (out.auditFailed) return reply.code(503).send({ error: "audit_unavailable" });
    const s = out.scan;
    return reply.send({
      request_id: s.request_id, event_id: out.eventId, decision: s.decision, failed_closed: s.failed_closed,
      fail_closed_reason: s.fail_closed_reason ?? null, risk: s.risk, detections: s.detections, entity_actions: s.entity_actions,
      sanitized_text: s.sanitized_text, policy_id: s.policy_id,
    });
  });

  app.post("/v1/security/check", { preHandler: requirePermission(d.auth, "scan:use") }, async (req, reply) => {
    const body = ScanBodySchema.parse(req.body);
    if (body.text.length > d.config.maxInputChars) return tooLarge(reply);
    const out = await d.service.scanText(principalOf(req), body.text, body.direction, { ...body.context, ip: req.ip });
    if (out.auditFailed) return reply.code(503).send({ error: "audit_unavailable" });
    const s = out.scan;
    return reply.send({ allowed: s.decision === "ALLOW", decision: s.decision, risk_level: s.risk.risk_level, failed_closed: s.failed_closed, event_id: out.eventId });
  });

  // ---------------------------------------------------------------- AI proxy
  app.post("/v1/ai/chat", { preHandler: requirePermission(d.auth, "ai:use") }, async (req, reply) => {
    const b = ChatBodySchema.parse(req.body);
    if (textLen(b.messages.map((m) => m.content)) > d.config.maxInputChars) return tooLarge(reply);
    const session = d.vault && b.session_id ? deriveVaultSession(principalOf(req), b.session_id) : undefined;
    const outcome = await d.service.chat(principalOf(req), b.provider, b.messages,
      { application: b.application, team: b.team, environment: b.environment, model: b.model, ip: req.ip, ...(session ? { vaultSession: session.id } : {}) },
      { ...(b.max_output_tokens !== undefined ? { maxOutputTokens: b.max_output_tokens } : {}), ...(b.temperature !== undefined ? { temperature: b.temperature } : {}), ...(b.hydrate !== undefined ? { hydrate: b.hydrate } : {}) });
    return sendChatOutcome(reply, outcome);
  });

  app.post("/v1/ai/generate", { preHandler: requirePermission(d.auth, "ai:use") }, async (req, reply) => {
    const b = GenerateBodySchema.parse(req.body);
    if (b.prompt.length > d.config.maxInputChars) return tooLarge(reply);
    const outcome = await d.service.chat(principalOf(req), b.provider, [{ role: "user", content: b.prompt }],
      { application: b.application, team: b.team, environment: b.environment, model: b.model, ip: req.ip },
      { ...(b.max_output_tokens !== undefined ? { maxOutputTokens: b.max_output_tokens } : {}), ...(b.temperature !== undefined ? { temperature: b.temperature } : {}) });
    return sendChatOutcome(reply, outcome);
  });

  // ---------------------------------------------------------------- events + usage
  app.get("/v1/events", { preHandler: requirePermission(d.auth, "events:read") }, async (req) => {
    const q = EventsQuerySchema.parse(req.query);
    const events = await d.events.list(principalOf(req).organizationId, {
      limit: q.limit, ...(q.risk_level ? { riskLevel: q.risk_level } : {}), ...(q.action ? { action: q.action } : {}),
      ...(q.event_type ? { eventType: q.event_type } : {}), ...(q.before ? { before: q.before } : {}),
    });
    return { events: events.map(eventToWire), next_before: events.length === q.limit ? events[events.length - 1]?.timestamp ?? null : null };
  });

  app.get<{ Params: { id: string } }>("/v1/events/:id", { preHandler: requirePermission(d.auth, "events:read") }, async (req, reply) => {
    if (!isUuid(req.params.id)) return reply.code(404).send({ error: "not_found" });
    const ev = await d.events.get(principalOf(req).organizationId, req.params.id);
    return ev ? reply.send(eventToWire(ev)) : reply.code(404).send({ error: "not_found" });
  });

  app.get("/v1/usage", { preHandler: requirePermission(d.auth, "usage:read") }, async (req) => {
    const q = UsageQuerySchema.parse(req.query);
    return { days: q.days, usage: await d.events.usage(principalOf(req).organizationId, q.days) };
  });

  // ---------------------------------------------------------------- policies
  app.get("/v1/policies", { preHandler: requirePermission(d.auth, "policies:read") }, async (req) => ({
    policies: await d.policies.list(principalOf(req).organizationId),
  }));

  app.get<{ Params: { id: string } }>("/v1/policies/:id", { preHandler: requirePermission(d.auth, "policies:read") }, async (req, reply) => {
    const p = await d.policies.get(principalOf(req).organizationId, z.string().min(1).max(128).parse(req.params.id));
    return p ? reply.send(p) : reply.code(404).send({ error: "not_found" });
  });

  const audit = (req: Parameters<typeof principalOf>[0], action: string, target: string, metadata: Record<string, string | number | boolean | null>) => {
    const p = principalOf(req);
    return d.auditLog.record({ organizationId: p.organizationId, actorId: p.userId ?? p.apiKeyId, actorType: p.userId ? "user" : "api_key", action, target, metadata });
  };

  app.post("/v1/policies", { preHandler: requirePermission(d.auth, "policies:write") }, async (req, reply) => {
    const b = PolicyBodySchema.parse(req.body);
    const p = principalOf(req);
    if ((await d.policies.get(p.organizationId, b.policy_id)) !== null) return reply.code(409).send({ error: "policy_exists", hint: "use PUT to create a new version" });
    const version = await d.policies.createVersion(p.organizationId, b.policy_id, b.rules as never, p.userId);
    await audit(req, "policy.create", b.policy_id, { version, rules: b.rules.length });
    return reply.code(201).send({ policy_id: b.policy_id, version, active: true });
  });

  app.put<{ Params: { id: string } }>("/v1/policies/:id", { preHandler: requirePermission(d.auth, "policies:write") }, async (req, reply) => {
    const id = PolicyBodySchema.shape.policy_id.parse(req.params.id);
    const b = PolicyUpdateSchema.parse(req.body);
    const p = principalOf(req);
    if ((await d.policies.get(p.organizationId, id)) === null) return reply.code(404).send({ error: "not_found" });
    const version = await d.policies.createVersion(p.organizationId, id, b.rules as never, p.userId);
    await audit(req, "policy.update", id, { version, rules: b.rules.length });
    return reply.send({ policy_id: id, version, active: true });
  });

  app.delete<{ Params: { id: string } }>("/v1/policies/:id", { preHandler: requirePermission(d.auth, "policies:write") }, async (req, reply) => {
    const id = PolicyBodySchema.shape.policy_id.parse(req.params.id);
    const existed = await d.policies.deactivate(principalOf(req).organizationId, id);
    if (!existed) return reply.code(404).send({ error: "not_found" });
    await audit(req, "policy.deactivate", id, {});
    return reply.code(204).send();
  });
}
