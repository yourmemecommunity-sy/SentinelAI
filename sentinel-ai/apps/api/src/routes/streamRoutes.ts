import type { OutgoingHttpHeaders } from "node:http";
import type { FastifyInstance, FastifyReply } from "fastify";
import type { AppConfig } from "../config/env.js";
import { principalOf, requirePermission } from "../middleware/auth.js";
import { securityHeaders } from "../middleware/hardening.js";
import type { ApiKeyAuthenticator } from "../security/apiKeys.js";
import { deriveVaultSession, type TokenVault } from "../security/tokenVault.js";
import type { SecureStreamService, StreamEvent } from "../services/secureStreamService.js";
import { StreamBodySchema } from "../validators/schemas.js";

export interface StreamRouteDeps {
  auth: ApiKeyAuthenticator;
  streaming: SecureStreamService;
  vault?: TokenVault | undefined;
  config: AppConfig;
  /** Renders the non-streaming outcomes (blocked / audit unavailable) exactly like /v1/ai/chat. */
  sendOutcome: (reply: FastifyReply, outcome: never) => unknown;
}

/** Wire form of a terminal or data event (one JSON object per SSE `data:` line, so newlines in text can never break framing). */
export function eventFrame(e: StreamEvent): string {
  switch (e.type) {
    case "delta": return `event: delta\ndata: ${JSON.stringify({ text: e.text })}\n\n`;
    case "done":
      return `event: done\ndata: ${JSON.stringify({
        provider: e.provider, model: e.model, hydration: e.hydration,
        security: {
          input: { decision: e.security.input.decision, risk_level: e.security.input.riskLevel, event_id: e.security.input.eventId },
          output: { decision: e.security.output.decision, risk_level: e.security.output.riskLevel, event_id: e.security.output.eventId },
        },
      })}\n\n`;
    case "error":
      if (e.error === "blocked") return `event: error\ndata: ${JSON.stringify({ error: "blocked", stage: e.stage, decision: e.decision, failed_closed: e.failedClosed, reason: e.reason, event_id: e.eventId })}\n\n`;
      if (e.error === "provider_error") return `event: error\ndata: ${JSON.stringify({ error: "provider_error", code: e.code, event_id: e.eventId })}\n\n`;
      return `event: error\ndata: ${JSON.stringify({ error: e.error })}\n\n`;
  }
}

/**
 * POST /v1/ai/stream - Server-Sent Events.
 *
 * Errors BEFORE the first byte (bad request, auth, blocked input, audit outage) are ordinary JSON responses with the same status
 * codes as /v1/ai/chat. Once streaming has started the status is already 200, so failures arrive as a terminal `error` event and the
 * stream ends; a client must treat anything other than a final `done` event as a failure.
 */
export function registerStreamRoutes(app: FastifyInstance, d: StreamRouteDeps): void {
  const active = new Map<string, number>();
  const HEARTBEAT_MS = 15_000;

  app.post("/v1/ai/stream", { preHandler: requirePermission(d.auth, "ai:use") }, async (req, reply) => {
    const b = StreamBodySchema.parse(req.body);
    if (b.messages.reduce((n, m) => n + m.content.length, 0) > d.config.maxInputChars) return reply.code(413).send({ error: "payload_too_large" });

    const p = principalOf(req);
    const who = p.apiKeyId ?? p.userId ?? req.ip;
    if ((active.get(who) ?? 0) >= d.config.stream.maxConcurrent) return reply.code(429).header("retry-after", "1").send({ error: "too_many_streams" });
    active.set(who, (active.get(who) ?? 0) + 1);

    const ctl = new AbortController();
    const res = reply.raw;
    // 'close' fires when the connection goes away AND after a normal end; only the former (not yet finished) is a disconnect.
    res.on("close", () => { if (!res.writableFinished) ctl.abort(); });
    let dispose: (() => Promise<void>) | undefined;
    let heartbeat: NodeJS.Timeout | undefined;
    try {
      const session = d.vault ? deriveVaultSession(p, b.session_id) : undefined;
      const open = await d.streaming.open(
        p, b.provider, b.messages,
        { application: b.application, team: b.team, environment: b.environment, model: b.model, ip: req.ip, ...(session ? { vaultSession: session.id } : {}) },
        { maxOutputTokens: b.max_output_tokens, temperature: b.temperature, hydrate: b.hydrate, mode: b.mode, signal: ctl.signal, vaultSession: session },
      );
      if (open.kind !== "stream") return d.sendOutcome(reply, open as never);
      dispose = open.dispose;
      if (ctl.signal.aborted) return reply;                                   // client left while the input was being screened

      reply.hijack();
      res.writeHead(200, {
        ...securityHeaders(d.config.nodeEnv === "production"),                 // hijack skips the onSend hook that normally adds these
        ...(reply.getHeaders() as OutgoingHttpHeaders),                                                // keep CORS / security / request-id headers: hijack skips the hooks that add them
        "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-store, no-transform", "x-accel-buffering": "no", connection: "keep-alive",
      });
      res.socket?.setNoDelay?.(true);
      res.flushHeaders();
      heartbeat = setInterval(() => { if (!res.destroyed && !res.writableEnded) res.write(": ping\n\n"); }, HEARTBEAT_MS);
      heartbeat.unref();

      const write = (chunk: string): Promise<void> => new Promise((resolve) => {
        if (res.destroyed || res.writableEnded) return resolve();
        if (res.write(chunk)) return resolve();
        const done = (): void => { res.off("drain", done); res.off("close", done); resolve(); };   // backpressure: wait for the client to catch up
        res.once("drain", done); res.once("close", done);
      });

      for await (const ev of open.events) {
        if (ctl.signal.aborted) break;
        await write(eventFrame(ev));
      }
    } catch {
      // Unexpected failure. If streaming has not started this becomes a 500 via Fastify; if it has, end the stream with a terminal error event.
      if (res.headersSent) { if (!res.destroyed && !res.writableEnded) res.write(eventFrame({ type: "error", error: "provider_error", code: "internal", eventId: null })); }
      else return reply.code(500).send({ error: "internal_error" });
    } finally {
      if (heartbeat) clearInterval(heartbeat);
      await dispose?.();
      const left = (active.get(who) ?? 1) - 1;
      if (left <= 0) active.delete(who); else active.set(who, left);
      if (res.headersSent && !res.writableEnded) res.end();
    }
    return reply;
  });
}
