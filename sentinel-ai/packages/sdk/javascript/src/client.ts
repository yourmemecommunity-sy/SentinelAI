import {
  SentinelAuthenticationError, SentinelBlockedError, SentinelConfigError, SentinelError, SentinelPermissionError, SentinelProviderError,
  SentinelRateLimitError, SentinelUnavailableError, SentinelValidationError,
} from "./errors.js";
import type {
  Action, CallOptions, ChatParams, CheckResult, Detection, FileScanParams, FileScanResult, Message, RiskLevel, ScanParams, ScanResult, SecureParams, SecureResponse,
  SentinelOptions, StageSummary, StreamParams, StreamSummary,
} from "./types.js";

const KEY_FORMAT = /^snl_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{43}$/;
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
const SDK_VERSION = "0.1.0";

type Json = Record<string, unknown>;

const env = (name: string): string | undefined => (typeof process !== "undefined" ? process.env?.[name] : undefined);
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown, what: string): string => { if (typeof v !== "string") throw new SentinelError(`unexpected response: ${what}`); return v; };

/**
 * SentinelAI client. Fails closed everywhere: content is only ever returned when the gateway answered 200 with a
 * well-formed body; every other outcome (blocked, network failure, timeout, malformed reply) throws.
 */
export class SentinelAI {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: SentinelOptions = {}) {
    const key = opts.apiKey ?? env("SENTINEL_API_KEY");
    if (!key) throw new SentinelConfigError("apiKey is required (or set SENTINEL_API_KEY)");
    if (!KEY_FORMAT.test(key)) throw new SentinelConfigError("apiKey is not a valid SentinelAI API key"); // never echo the value
    const rawUrl = opts.baseUrl ?? env("SENTINEL_BASE_URL");
    if (!rawUrl) throw new SentinelConfigError("baseUrl is required (or set SENTINEL_BASE_URL)");

    let url: URL;
    try { url = new URL(rawUrl); } catch { throw new SentinelConfigError("baseUrl is not a valid URL"); }
    if (url.protocol !== "https:" && url.protocol !== "http:") throw new SentinelConfigError("baseUrl must be http(s)");
    if (url.username || url.password) throw new SentinelConfigError("baseUrl must not contain credentials");
    if (url.protocol === "http:" && !LOCAL_HOSTS.has(url.hostname) && !opts.allowInsecureHttp) {
      throw new SentinelConfigError("baseUrl must use https:// (the API key would be sent in clear text). Set allowInsecureHttp only for trusted networks.");
    }
    if (opts.timeoutMs !== undefined && !(opts.timeoutMs > 0)) throw new SentinelConfigError("timeoutMs must be positive");

    this.apiKey = key;
    this.baseUrl = `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
    this.timeoutMs = opts.timeoutMs ?? 60_000;
    this.fetchImpl = opts.fetch ?? fetch;
  }

  /** Keep the key out of console.log / util.inspect / JSON.stringify of the client. */
  toJSON(): Json { return { baseUrl: this.baseUrl, apiKey: "[redacted]" }; }
  [Symbol.for("nodejs.util.inspect.custom")](): string { return `SentinelAI { baseUrl: '${this.baseUrl}', apiKey: '[redacted]' }`; }

  // ------------------------------------------------------------------ public API

  /** Send a prompt to an AI provider through SentinelAI. Throws SentinelBlockedError if security blocks it. */
  secure(p: SecureParams): Promise<SecureResponse> {
    const messages: Message[] = [...(p.system ? [{ role: "system" as const, content: p.system }] : []), { role: "user", content: p.prompt }];
    return this.chat({ ...p, messages });
  }

  async chat(p: ChatParams): Promise<SecureResponse> {
    const body = await this.post("/v1/ai/chat", chatBody(p), p.signal);
    const sec = body.security;
    if (!isObj(sec) || !isObj(sec.input) || !isObj(sec.output)) throw new SentinelError("unexpected response: security summary missing");
    const hydration = body.hydration === "applied" || body.hydration === "degraded" ? body.hydration : undefined;
    return {
      content: str(body.content, "content"), provider: str(body.provider, "provider"), model: str(body.model, "model"),
      security: { input: stage(sec.input), output: stage(sec.output) }, ...(hydration ? { hydration } : {}),
    };
  }

  /**
   * Streams a reply through SentinelAI. Iterate it for text as it is released; `summary` resolves once the stream has ENDED
   * WITH THE GATEWAY'S `done` EVENT.
   *
   *   const s = client.stream({ provider: "gemini", messages });
   *   for await (const text of s) process.stdout.write(text);
   *   const { security } = await s.summary;
   *
   * Fail-closed contract: a stream is complete only when it ends with `done`. A block, provider failure, timeout or a
   * connection that drops mid-reply throws from the iterator (and rejects `summary`), even though text already delivered was
   * scanned before release. Treat any exception as "the reply is incomplete".
   */
  stream(p: StreamParams): SecureStream {
    return new SecureStream((signal) => this.openStream(p, signal), p.signal, this.timeoutMs);
  }

  private async openStream(p: StreamParams, signal: AbortSignal): Promise<Response> {
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/v1/ai/stream`, {
        method: "POST", redirect: "error", signal,
        headers: { "content-type": "application/json", accept: "text/event-stream", authorization: `Bearer ${this.apiKey}`, "user-agent": `sentinelai-js/${SDK_VERSION}` },
        body: JSON.stringify({ ...chatBody(p), ...(p.mode ? { mode: p.mode } : {}) }),
      });
    } catch (err) {
      if (p.signal?.aborted) throw new SentinelUnavailableError("request aborted by caller");
      const timedOut = err instanceof DOMException && (err.name === "TimeoutError" || err.name === "AbortError");
      throw new SentinelUnavailableError(timedOut ? "request timed out" : "cannot reach the SentinelAI gateway");
    }
    if (!res.ok) {
      let obj: Json = {};
      try { const j = await res.json(); if (isObj(j)) obj = j; } catch { /* mapped by status */ }
      throwForStatus(res, obj);
    }
    if (!(res.headers.get("content-type") ?? "").startsWith("text/event-stream") || !res.body) {
      throw new SentinelUnavailableError("gateway returned an unusable response", res.status);
    }
    return res;
  }

  /** Scan text without calling a model. Returns the decision; a blocked result is returned, not thrown. */
  async scan(p: ScanParams): Promise<ScanResult> {
    const b = await this.post("/v1/security/scan", { text: p.text, direction: p.direction ?? "INPUT", ...(hasCtx(p) ? { context: ctx(p) } : {}) }, p.signal);
    const risk = b.risk;
    if (!isObj(risk)) throw new SentinelError("unexpected response: risk missing");
    if (!Array.isArray(b.detections) || !Array.isArray(risk.factors)) throw new SentinelError("unexpected response: evidence missing");
    const decision = str(b.decision, "decision") as Action;
    const blocked = decision === "BLOCK" || decision === "QUARANTINE";
    const sanitized = b.sanitized_text;
    // Invariant: a blocked decision never carries text, and a non-blocked one always does. Anything else is untrustworthy.
    if (blocked ? sanitized !== null : typeof sanitized !== "string") throw new SentinelError("unexpected response: inconsistent decision");
    return {
      requestId: str(b.request_id, "request_id"), eventId: typeof b.event_id === "string" ? b.event_id : null, decision, blocked,
      failedClosed: b.failed_closed === true, failClosedReason: typeof b.fail_closed_reason === "string" ? b.fail_closed_reason : null,
      riskScore: Number(risk.risk_score), riskLevel: str(risk.risk_level, "risk_level") as RiskLevel,
      riskFactors: (risk.factors as Json[]).map((f) => ({ name: str(f.name, "factor"), contribution: Number(f.contribution), detail: str(f.detail, "factor detail") })),
      detections: (b.detections as Json[]).map((d): Detection => ({
        entity: str(d.entity, "entity"), confidence: Number(d.confidence), severity: str(d.severity, "severity"),
        location: { start: Number((d.location as Json)?.start), end: Number((d.location as Json)?.end) }, detector: str(d.detector, "detector"),
      })),
      sanitizedText: sanitized as string | null, policyId: str(b.policy_id, "policy_id"),
    };
  }

  /** Cheap allow/deny check. `allowed` is true only for an unmodified ALLOW decision. */
  async check(p: ScanParams): Promise<CheckResult> {
    const b = await this.post("/v1/security/check", { text: p.text, direction: p.direction ?? "INPUT", ...(hasCtx(p) ? { context: ctx(p) } : {}) }, p.signal);
    return {
      allowed: b.allowed === true && b.decision === "ALLOW", decision: str(b.decision, "decision") as Action,
      riskLevel: str(b.risk_level, "risk_level") as RiskLevel, failedClosed: b.failed_closed === true, eventId: typeof b.event_id === "string" ? b.event_id : null,
    };
  }

  /**
   * Scan a file (PDF, DOCX, XLSX, CSV, TXT, JSON, PNG/JPEG/GIF/WEBP) before it goes anywhere near a model. A blocked file is
   * RETURNED (`blocked: true`), never thrown, so callers must check it. Network failure, timeout or an unusable reply throws.
   */
  async scanFile(p: FileScanParams): Promise<FileScanResult> {
    const bytes = p.data instanceof Uint8Array ? p.data : new Uint8Array(p.data);
    const ext = /\.[A-Za-z0-9]{1,8}$/.exec(p.filename ?? "")?.[0] ?? "";
    const b = await this.request("/v1/files/scan", bytes, "application/octet-stream", {
      ...(ext ? { "x-filename": encodeURIComponent(`upload${ext}`) } : {}),
      ...(p.application ? { "x-application": p.application } : {}), ...(p.team ? { "x-team": p.team } : {}), ...(p.environment ? { "x-environment": p.environment } : {}),
    }, p.signal);
    const risk = b.risk, file = b.file;
    if (!isObj(risk) || !isObj(file) || !Array.isArray(b.findings) || !Array.isArray(b.detections)) throw new SentinelError("unexpected response: file scan evidence missing");
    const decision = str(b.decision, "decision") as Action;
    const blocked = decision === "BLOCK" || decision === "QUARANTINE";
    const sanitized = b.sanitized_text;
    // Invariant: a blocked decision never carries text and a non-blocked one always does; anything else is untrustworthy.
    if (blocked ? sanitized !== null : typeof sanitized !== "string") throw new SentinelError("unexpected response: inconsistent decision");
    return {
      eventId: typeof b.event_id === "string" ? b.event_id : null, decision, blocked, failedClosed: b.failed_closed === true,
      reason: typeof b.reason === "string" ? b.reason : null,
      file: { sha256: str(file.sha256, "sha256"), size: Number(file.size), detectedType: typeof file.detected_type === "string" ? file.detected_type : null,
        mime: typeof file.mime === "string" ? file.mime : null, pages: typeof file.pages === "number" ? file.pages : null, ocrUsed: file.ocr_used === true },
      findings: (b.findings as Json[]).map((f) => ({ type: str(f.type, "finding"), severity: str(f.severity, "severity") as FileScanResult["findings"][number]["severity"], detail: str(f.detail, "detail") })),
      riskScore: Number(risk.risk_score), riskLevel: str(risk.risk_level, "risk_level") as RiskLevel,
      detections: (b.detections as Json[]).map((d): Detection => ({
        entity: str(d.entity, "entity"), confidence: Number(d.confidence), severity: str(d.severity, "severity"),
        location: { start: Number((d.location as Json)?.start), end: Number((d.location as Json)?.end) }, detector: str(d.detector, "detector") })),
      sanitizedText: sanitized as string | null, policyId: str(b.policy_id, "policy_id"),
    };
  }

  // ------------------------------------------------------------------ transport

  private post(path: string, payload: Json, external?: AbortSignal): Promise<Json> {
    return this.request(path, JSON.stringify(payload), "application/json", {}, external);
  }

  private async request(path: string, body: string | Uint8Array, contentType: string, extraHeaders: Record<string, string>, external?: AbortSignal): Promise<Json> {
    const timeout = AbortSignal.timeout(this.timeoutMs);
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method: "POST",
        headers: { "content-type": contentType, accept: "application/json", authorization: `Bearer ${this.apiKey}`, "user-agent": `sentinelai-js/${SDK_VERSION}`, ...extraHeaders },
        body,
        // Never follow redirects: a hostile/misconfigured redirect must not be handed our credentials.
        redirect: "error",
        signal: external ? AbortSignal.any([timeout, external]) : timeout,
      });
    } catch (err) {
      if (external?.aborted) throw new SentinelUnavailableError("request aborted by caller");
      const timedOut = err instanceof DOMException && (err.name === "TimeoutError" || err.name === "AbortError");
      throw new SentinelUnavailableError(timedOut ? "request timed out" : "cannot reach the SentinelAI gateway");
    }

    let reply: unknown = null;
    try { reply = await res.json(); } catch { /* handled per status below */ }
    const obj: Json = isObj(reply) ? reply : {};

    if (res.ok) {
      if (!isObj(reply)) throw new SentinelUnavailableError("gateway returned an unusable response", res.status);
      return reply;
    }
    return throwForStatus(res, obj);
  }

}

/** Maps a non-2xx gateway response to a typed error. Shared by every call so streaming fails closed exactly like chat. */
function throwForStatus(res: Response, obj: Json): never {
    switch (res.status) {
      case 401: throw new SentinelAuthenticationError("authentication failed: check your API key", 401, "unauthorized");
      case 403:
        if (obj.error === "blocked") {
          throw new SentinelBlockedError(obj.stage === "output" ? "output" : "input", typeof obj.decision === "string" ? obj.decision : "BLOCK",
            obj.failed_closed === true, typeof obj.reason === "string" ? obj.reason : null, typeof obj.event_id === "string" ? obj.event_id : null);
        }
        throw new SentinelPermissionError("this API key is not permitted to use this endpoint", 403, "forbidden");
      case 413: throw new SentinelValidationError("request too large", 413);
      case 422: throw new SentinelValidationError("request rejected as invalid", 422, Array.isArray(obj.issues) ? (obj.issues as Json[]).map((i) => ({ path: String(i.path ?? ""), message: String(i.message ?? "") })) : []);
      case 429: {
        const ra = Number(res.headers.get("retry-after"));
        throw new SentinelRateLimitError(Number.isFinite(ra) && ra > 0 ? ra : undefined);
      }
      case 502: throw new SentinelProviderError(typeof obj.code === "string" ? obj.code : "unknown", typeof obj.event_id === "string" ? obj.event_id : null);
      default:
        if (res.status >= 500) throw new SentinelUnavailableError(`gateway unavailable (HTTP ${res.status})`, res.status, typeof obj.error === "string" ? obj.error : undefined);
        throw new SentinelError(`unexpected HTTP ${res.status}`, res.status);
    }
}

const stage = (s: Json): StageSummary => ({ decision: str(s.decision, "decision") as Action, riskLevel: str(s.risk_level, "risk_level") as RiskLevel, eventId: str(s.event_id, "event_id") });

function chatBody(p: ChatParams): Json {
  return {
    provider: p.provider, messages: p.messages,
    ...(p.model ? { model: p.model } : {}),
    ...(p.maxOutputTokens !== undefined ? { max_output_tokens: p.maxOutputTokens } : {}),
    ...(p.temperature !== undefined ? { temperature: p.temperature } : {}),
    ...(p.sessionId !== undefined ? { session_id: p.sessionId } : {}),
    ...(p.hydrate !== undefined ? { hydrate: p.hydrate } : {}),
    ...ctx(p),
  };
}

/** Largest single SSE event accepted. A gateway never sends one near this; a larger one means something is wrong. */
const MAX_EVENT_BYTES = 1_000_000;

/**
 * One streamed reply. Async-iterable over text deltas; `summary` settles when the stream ends. Idle timeout: the client's
 * `timeoutMs` applies to the gap BETWEEN events, not to the whole stream (the gateway sends a heartbeat every 15 s).
 */
export class SecureStream implements AsyncIterable<string> {
  readonly summary: Promise<StreamSummary>;
  private resolveSummary!: (s: StreamSummary) => void;
  private rejectSummary!: (e: unknown) => void;
  private started = false;

  constructor(private readonly open: (signal: AbortSignal) => Promise<Response>, private readonly external?: AbortSignal, private readonly idleMs = 60_000) {
    this.summary = new Promise((res, rej) => { this.resolveSummary = res; this.rejectSummary = rej; });
    this.summary.catch(() => undefined);            // an unobserved summary must not become an unhandled rejection
  }

  /** Convenience: the whole reply as one string (still fails closed: throws unless the stream completed). */
  async text(): Promise<string> {
    let out = "";
    for await (const t of this) out += t;
    return out;
  }

  async *[Symbol.asyncIterator](): AsyncGenerator<string, void, void> {
    if (this.started) throw new SentinelError("a stream can only be iterated once");
    this.started = true;
    const ctl = new AbortController();
    const onAbort = () => ctl.abort();
    this.external?.addEventListener("abort", onAbort, { once: true });
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let finished = false;
    try {
      const res = await this.open(ctl.signal);
      reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      for (;;) {
        let timer: ReturnType<typeof setTimeout> | undefined;
        const idle = new Promise<never>((_, rej) => { timer = setTimeout(() => rej(new SentinelUnavailableError("stream stalled: no data from the gateway")), this.idleMs); });
        let chunk: Awaited<ReturnType<typeof reader.read>>;
        try { chunk = await Promise.race([reader.read(), idle]); } finally { clearTimeout(timer); }
        if (chunk.done) break;
        buf += decoder.decode(chunk.value, { stream: true });
        if (buf.length > MAX_EVENT_BYTES) throw new SentinelUnavailableError("gateway sent an oversized stream event");
        let sep: number;
        while ((sep = buf.search(/\r?\n\r?\n/)) !== -1) {
          const frame = buf.slice(0, sep);
          buf = buf.slice(sep).replace(/^\r?\n\r?\n/, "");
          const ev = parseEvent(frame);
          if (!ev) continue;                               // comment / heartbeat
          if (ev.event === "delta") {
            if (typeof ev.data?.text !== "string") throw new SentinelError("unexpected response: malformed delta");
            if (ev.data.text) yield ev.data.text;
          } else if (ev.event === "done") {
            const d = ev.data;
            if (!isObj(d) || !isObj(d.security) || !isObj(d.security.input) || !isObj(d.security.output)) throw new SentinelError("unexpected response: malformed summary");
            const hydration = d.hydration === "applied" || d.hydration === "degraded" ? d.hydration : "off";
            finished = true;
            this.resolveSummary({ provider: str(d.provider, "provider"), model: str(d.model, "model"), hydration, security: { input: stage(d.security.input), output: stage(d.security.output) } });
            return;
          } else if (ev.event === "error") {
            throw streamError(ev.data);
          }
        }
      }
      // The connection ended without `done`: whatever was delivered is NOT a complete reply.
      throw new SentinelUnavailableError("stream ended before the gateway completed it");
    } catch (err) {
      const e = err instanceof SentinelError ? err
        : this.external?.aborted ? new SentinelUnavailableError("request aborted by caller")
        : new SentinelUnavailableError("stream failed");
      this.rejectSummary(e);
      throw e;
    } finally {
      this.external?.removeEventListener("abort", onAbort);
      if (!finished) {
        ctl.abort();                                       // stop the upstream request if the caller broke out early
        this.rejectSummary(new SentinelUnavailableError("stream was not completed"));
      }
      await reader?.cancel().catch(() => undefined);
    }
  }
}

function parseEvent(frame: string): { event: string; data: Json } | null {
  let event = "message";
  const data: string[] = [];
  for (const line of frame.split(/\r?\n/)) {
    if (!line || line.startsWith(":")) continue;
    const i = line.indexOf(":");
    const field = i === -1 ? line : line.slice(0, i);
    const value = i === -1 ? "" : line.slice(i + 1).replace(/^ /, "");
    if (field === "event") event = value;
    else if (field === "data") data.push(value);
  }
  if (data.length === 0) return null;
  let parsed: unknown;
  try { parsed = JSON.parse(data.join("\n")); } catch { throw new SentinelError("unexpected response: stream event is not JSON"); }
  if (!isObj(parsed)) throw new SentinelError("unexpected response: stream event is not an object");
  return { event, data: parsed };
}

function streamError(d: Json): SentinelError {
  const eventId = typeof d.event_id === "string" ? d.event_id : null;
  if (d.error === "blocked") {
    return new SentinelBlockedError(d.stage === "input" ? "input" : "output", typeof d.decision === "string" ? d.decision : "BLOCK",
      d.failed_closed === true, typeof d.reason === "string" ? d.reason : null, eventId);
  }
  if (d.error === "provider_error") return new SentinelProviderError(typeof d.code === "string" ? d.code : "unknown", eventId);
  return new SentinelUnavailableError(`stream ended by the gateway: ${typeof d.error === "string" ? d.error : "error"}`, 200, typeof d.error === "string" ? d.error : undefined);
}

function hasCtx(p: CallOptions): boolean { return !!(p.application || p.team || p.environment); }
function ctx(p: CallOptions): Json {
  return { ...(p.application ? { application: p.application } : {}), ...(p.team ? { team: p.team } : {}), ...(p.environment ? { environment: p.environment } : {}) };
}
