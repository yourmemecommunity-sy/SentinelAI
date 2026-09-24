export type Provider = "gemini" | "anthropic" | "openai" | "ollama" | (string & {});
export type Action = "ALLOW" | "HASH" | "MASK" | "TOKENIZE" | "REDACT" | "QUARANTINE" | "BLOCK";
export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Direction = "INPUT" | "OUTPUT";

export interface SentinelOptions {
  /** `snl_...` key. Falls back to the SENTINEL_API_KEY environment variable. */
  apiKey?: string;
  /** Gateway URL. Falls back to SENTINEL_BASE_URL. Must be https:// unless it points at localhost. */
  baseUrl?: string;
  /** Per-request timeout. Default 60 000 ms. */
  timeoutMs?: number;
  /** Permit http:// to a non-local host. Off by default: the API key would travel in clear text. */
  allowInsecureHttp?: boolean;
  /** Custom fetch (tests, proxies). */
  fetch?: typeof fetch;
}

export interface RequestContext {
  application?: string;
  team?: string;
  environment?: string;
}

export interface CallOptions extends RequestContext {
  signal?: AbortSignal;
}

export interface Message { role: "system" | "user" | "assistant"; content: string }

export interface ChatParams extends CallOptions {
  provider: Provider;
  messages: Message[];
  model?: string;
  maxOutputTokens?: number;
  temperature?: number;
  /**
   * Names a token-vault session: values your organization's policy TOKENIZEs keep the same token across calls with the same
   * id, and the reply comes back with them restored. The gateway scopes the id to your API key, so it can never reach another
   * caller's session. Omit it for a one-off session that is deleted when the request ends.
   */
  sessionId?: string;
  /** Set false to receive tokens exactly as the model wrote them. */
  hydrate?: boolean;
}

export interface StreamParams extends ChatParams {
  /** "holdback" (default) streams with a look-ahead scan; "buffered" releases nothing until the whole reply has been scanned. */
  mode?: "holdback" | "buffered";
}

/** Returned once a stream has finished successfully (it ended with the gateway's `done` event). */
export interface StreamSummary {
  provider: string;
  model: string;
  hydration: "off" | "applied" | "degraded";
  security: { input: StageSummary; output: StageSummary };
}

export interface SecureParams extends CallOptions {
  provider: Provider;
  prompt: string;
  /** Optional system prompt (also scanned). */
  system?: string;
  model?: string;
  maxOutputTokens?: number;
  temperature?: number;
}

export interface StageSummary { decision: Action; riskLevel: RiskLevel; eventId: string }

/** A response that passed input AND output security. `content` is the (possibly sanitized) model output. */
export interface SecureResponse {
  content: string;
  provider: string;
  model: string;
  security: { input: StageSummary; output: StageSummary };
  /** Present when a session was used: whether tokens in the reply were restored. */
  hydration?: "applied" | "degraded";
}

export interface Detection {
  entity: string;
  confidence: number;
  severity: string;
  location: { start: number; end: number };
  detector: string;
}

export interface ScanParams extends RequestContext {
  text: string;
  direction?: Direction;
  signal?: AbortSignal;
}

export interface ScanResult {
  requestId: string;
  eventId: string | null;
  decision: Action;
  /** true for BLOCK and QUARANTINE: `sanitizedText` is null and the text must not be forwarded anywhere. */
  blocked: boolean;
  failedClosed: boolean;
  failClosedReason: string | null;
  riskScore: number;
  riskLevel: RiskLevel;
  riskFactors: { name: string; contribution: number; detail: string }[];
  detections: Detection[];
  /** Text safe to send to a model, or null when blocked. */
  sanitizedText: string | null;
  policyId: string;
}

export interface FileScanParams extends RequestContext {
  /** The raw file bytes. */
  data: Uint8Array | ArrayBuffer;
  /** Optional. Only the extension is sent (the gateway never receives or stores the name). */
  filename?: string;
  signal?: AbortSignal;
}

export interface FileFinding { type: string; severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; detail: string }

export interface FileScanResult {
  eventId: string | null;
  decision: Action;
  /** true for BLOCK/QUARANTINE (including fail-closed): do NOT forward the file or any of its content anywhere. */
  blocked: boolean;
  failedClosed: boolean;
  /** Why it was blocked (e.g. "macros_present", "malware_detected", "scanner_unreachable"), when applicable. */
  reason: string | null;
  file: { sha256: string; size: number; detectedType: string | null; mime: string | null; pages: number | null; ocrUsed: boolean };
  /** Things the file did that deserve attention: hidden_text, external_resource, ... */
  findings: FileFinding[];
  riskScore: number;
  riskLevel: RiskLevel;
  detections: Detection[];
  /** The file's extracted text with your policy applied - safe to give to a model. Null when blocked. */
  sanitizedText: string | null;
  policyId: string;
}

export interface CheckResult {
  allowed: boolean;
  decision: Action;
  riskLevel: RiskLevel;
  failedClosed: boolean;
  eventId: string | null;
}
