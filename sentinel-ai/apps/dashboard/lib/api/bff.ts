/**
 * Backend-for-frontend: the browser never sees an access or refresh token. Tokens live in httpOnly cookies set here;
 * client code calls /api/proxy/*, which attaches the bearer token server-side and transparently refreshes it.
 * Pure functions over Request/Response so they are unit-testable without a running Next server.
 */

export const COOKIE = { access: "sn_at", refresh: "sn_rt", session: "sn_sess" } as const;
export const CSRF_HEADER = "x-sentinel-csrf";

export interface BffDeps {
  gatewayUrl: string; fetch: typeof fetch; secure: boolean;
  /** Largest upload the BFF will buffer (default 20 MiB). The gateway enforces its own limit as well. */
  maxUploadBytes?: number;
}
export const DEFAULT_MAX_UPLOAD_BYTES = 20 * 1024 * 1024;

interface GatewaySession {
  access_token: string; refresh_token: string; expires_in: number;
  user: { id: string; organization_id: string; role: string };
}

// ------------------------------------------------------------------ cookies
export function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (header ?? "").split(";")) {
    const i = part.indexOf("=");
    const name = i > 0 ? part.slice(0, i).trim() : "";
    if (!name) continue;
    const raw = part.slice(i + 1).trim();
    try { out[name] = decodeURIComponent(raw); } catch { /* malformed escape: ignore the cookie instead of throwing */ }
  }
  return out;
}

function cookie(name: string, value: string, o: { maxAge: number; path: string; secure: boolean }): string {
  return `${name}=${encodeURIComponent(value)}; Max-Age=${o.maxAge}; Path=${o.path}; HttpOnly; SameSite=Strict${o.secure ? "; Secure" : ""}`;
}

const REFRESH_MAX_AGE = 30 * 86_400;

/** Access token: whole site (short-lived). Refresh token: only /api, so it is never sent to page routes. */
export function sessionCookies(s: GatewaySession, secure: boolean): string[] {
  return [
    cookie(COOKIE.access, s.access_token, { maxAge: s.expires_in, path: "/", secure }),
    cookie(COOKIE.refresh, s.refresh_token, { maxAge: REFRESH_MAX_AGE, path: "/api", secure }),
    // Non-secret presence marker so page middleware (which cannot see the /api-scoped refresh cookie) can gate navigation.
    cookie(COOKIE.session, "1", { maxAge: REFRESH_MAX_AGE, path: "/", secure }),
  ];
}

export function clearCookies(secure: boolean): string[] {
  return [
    cookie(COOKIE.access, "", { maxAge: 0, path: "/", secure }),
    cookie(COOKIE.refresh, "", { maxAge: 0, path: "/api", secure }),
    cookie(COOKIE.session, "", { maxAge: 0, path: "/", secure }),
  ];
}

function json(status: number, body: unknown, cookies: string[] = []): Response {
  const h = new Headers({ "content-type": "application/json", "cache-control": "no-store" });
  for (const c of cookies) h.append("set-cookie", c);
  return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: h });
}

// ------------------------------------------------------------------ CSRF
/**
 * Cookies are SameSite=Strict (primary defence). Additionally every state-changing request must carry a custom header
 * (which cross-site forms cannot send) and, when an Origin header is present, it must match the Host.
 */
export function passesCsrf(req: Request): boolean {
  if (req.method === "GET" || req.method === "HEAD") return true;
  if (req.headers.get(CSRF_HEADER) !== "1") return false;
  const origin = req.headers.get("origin");
  if (origin) {
    try { if (new URL(origin).host !== req.headers.get("host")) return false; } catch { return false; }
  }
  return true;
}

// ------------------------------------------------------------------ proxy allow-list
const ID = "[A-Za-z0-9._-]{1,128}";
const ALLOWED: { method: string; re: RegExp }[] = [
  { method: "GET", re: /^auth\/me$/ },
  { method: "GET", re: /^events$/ },
  { method: "GET", re: /^events\/[0-9a-fA-F-]{36}$/ },
  { method: "GET", re: /^usage$/ },
  { method: "GET", re: /^policies$/ },
  { method: "GET", re: new RegExp(`^policies/${ID}$`) },
  { method: "POST", re: /^policies$/ },
  { method: "PUT", re: new RegExp(`^policies/${ID}$`) },
  { method: "DELETE", re: new RegExp(`^policies/${ID}$`) },
  { method: "POST", re: /^security\/scan$/ },
  // explanations, replay (the gateway checks the text against the recorded content hash), red team, judge switch
  { method: "POST", re: /^events\/[0-9a-fA-F-]{36}\/replay$/ },
  { method: "GET", re: /^red-team\/rounds$/ },
  { method: "GET", re: /^organization\/ai-judge$/ },
  { method: "PUT", re: /^organization\/ai-judge$/ },
  { method: "GET", re: /^api-keys$/ },
  { method: "POST", re: /^api-keys$/ },
  { method: "DELETE", re: /^api-keys\/[0-9a-fA-F-]{36}$/ },
  // user / invitation / team management (the gateway enforces users:manage + session-only + escalation rules)
  { method: "GET", re: /^users$/ },
  { method: "PATCH", re: /^users\/[0-9a-fA-F-]{36}$/ },
  { method: "DELETE", re: /^users\/[0-9a-fA-F-]{36}$/ },
  { method: "GET", re: /^invitations$/ },
  { method: "POST", re: /^invitations$/ },
  { method: "DELETE", re: /^invitations\/[0-9a-fA-F-]{36}$/ },
  { method: "GET", re: /^teams$/ },
  { method: "POST", re: /^teams$/ },
  { method: "DELETE", re: /^teams\/[0-9a-fA-F-]{36}$/ },
  { method: "PUT", re: /^teams\/[0-9a-fA-F-]{36}\/members\/[0-9a-fA-F-]{36}$/ },
  { method: "DELETE", re: /^teams\/[0-9a-fA-F-]{36}\/members\/[0-9a-fA-F-]{36}$/ },
  // per-organization provider settings (providers:manage)
  { method: "GET", re: /^providers$/ },
  { method: "PUT", re: /^providers\/(gemini|openai|anthropic)\/credential$/ },
  { method: "DELETE", re: /^providers\/(gemini|openai|anthropic)\/credential$/ },
  { method: "PATCH", re: /^providers\/[a-z][a-z0-9_-]{1,31}$/ },
];
/** Only these gateway routes are reachable through the dashboard proxy (no path traversal, no ai/chat, no auth admin). */
export function isAllowedProxy(method: string, path: string): boolean {
  return !path.includes("..") && ALLOWED.some((a) => a.method === method && a.re.test(path));
}

// ------------------------------------------------------------------ auth endpoints
async function readJson(req: Request): Promise<Record<string, unknown> | null> {
  try { const b = await req.json(); return b && typeof b === "object" && !Array.isArray(b) ? (b as Record<string, unknown>) : null; } catch { return null; }
}

export async function handleAuth(kind: "login" | "register" | "logout", req: Request, d: BffDeps): Promise<Response> {
  if (!passesCsrf(req)) return json(403, { error: "csrf" });

  if (kind === "logout") {
    const rt = parseCookies(req.headers.get("cookie"))[COOKIE.refresh];
    if (rt) forgetRefresh(rt);
    if (rt) await d.fetch(`${d.gatewayUrl}/v1/auth/logout`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ refresh_token: rt }) }).catch(() => undefined);
    return json(200, { ok: true }, clearCookies(d.secure));
  }

  const body = await readJson(req);
  if (!body) return json(422, { error: "invalid_request" });
  const url = kind === "login" ? "/v1/auth/login" : "/v1/auth/signup";
  let res: Response;
  try {
    res = await d.fetch(`${d.gatewayUrl}${url}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  } catch { return json(502, { error: "gateway_unreachable" }); }

  const data = (await res.json().catch(() => ({}))) as Partial<GatewaySession> & Record<string, unknown>;
  if (!res.ok || !data.access_token || !data.refresh_token || !data.user) {
    // Pass through only the gateway's error code/message, never anything else.
    return json(res.status >= 400 && res.status < 600 ? res.status : 502, { error: data.error ?? "request_failed", ...(typeof data.message === "string" ? { message: data.message } : {}) });
  }
  return json(res.status === 201 ? 201 : 200, { user: data.user }, sessionCookies(data as GatewaySession, d.secure));
}

// ------------------------------------------------------------------ invitation acceptance (public)
/**
 * The invitee has no session yet. The token travels in the request body only (the page reads it from the URL fragment,
 * which browsers never send to servers or put in Referer). No session is created here: the new user signs in afterwards.
 */
export async function handleAcceptInvite(req: Request, d: BffDeps): Promise<Response> {
  if (!passesCsrf(req)) return json(403, { error: "csrf" });
  const body = await readJson(req);
  if (!body || typeof body.token !== "string" || typeof body.password !== "string") return json(422, { error: "invalid_request" });
  let res: Response;
  try {
    res = await d.fetch(`${d.gatewayUrl}/v1/invitations/accept`, { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: body.token, password: body.password }) });
  } catch { return json(502, { error: "gateway_unreachable" }); }
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) return json(res.status >= 400 && res.status < 600 ? res.status : 502, { error: data.error ?? "request_failed", ...(typeof data.message === "string" ? { message: data.message } : {}) });
  return json(201, { ok: true, role: typeof data.role === "string" ? data.role : null });
}

// ------------------------------------------------------------------ refresh (single-flight)
interface Flight { p: Promise<GatewaySession | null>; at: number; session?: GatewaySession }
const inflight = new Map<string, Flight>();

/**
 * How long a completed refresh may still be shared with requests that presented the SAME (now rotated) refresh token.
 * It only needs to cover requests already in flight when the first refresh finished (a page firing several API calls at
 * once). It is deliberately short: within this window anyone holding the old token gets the fresh session, which is
 * exactly the reuse the gateway would otherwise detect and punish. Residual risk: <= this many ms, per BFF instance.
 */
export const REFRESH_SHARE_MS = 5_000;

/**
 * Rotating refresh tokens + parallel requests would otherwise race: two requests present the same refresh token, the
 * second looks like token reuse, and the gateway revokes the whole session. Requests carrying the same refresh token
 * therefore share one refresh call.
 */
export function refreshOnce(rt: string, d: BffDeps): Promise<GatewaySession | null> {
  const now = Date.now();
  for (const [k, v] of inflight) if (now - v.at > REFRESH_SHARE_MS) inflight.delete(k);
  const existing = inflight.get(rt);
  if (existing) return existing.p;
  const flight: Flight = { at: now, p: Promise.resolve(null) };
  flight.p = d.fetch(`${d.gatewayUrl}/v1/auth/refresh`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ refresh_token: rt }) })
    .then(async (r) => {
      const s = r.ok ? ((await r.json()) as GatewaySession) : null;
      if (s) flight.session = s;
      else inflight.delete(rt); // failures are never shared
      return s;
    })
    .catch(() => { inflight.delete(rt); return null; });
  inflight.set(rt, flight);
  return flight.p;
}

/** Drop every cached refresh that produced (or was keyed by) this refresh token, e.g. on logout. */
export function forgetRefresh(rt: string): void {
  for (const [k, v] of inflight) if (k === rt || v.session?.refresh_token === rt) inflight.delete(k);
}

// ------------------------------------------------------------------ authenticated relay (shared by the JSON proxy and uploads)
const hasCredentials = (req: Request): boolean => {
  const c = parseCookies(req.headers.get("cookie"));
  return Boolean(c[COOKIE.access] || c[COOKIE.refresh]);
};

/**
 * Calls the gateway with the session's bearer token, refreshing it (single-flight) once on 401, and relays status + body.
 * The caller must already have checked `hasCredentials`. The browser's cookies are never forwarded.
 */
async function relay(req: Request, d: BffDeps, call: (token: string) => Promise<Response>): Promise<Response> {
  const cookies = parseCookies(req.headers.get("cookie"));
  let at = cookies[COOKIE.access];
  const rt = cookies[COOKIE.refresh];
  let setCookies: string[] = [];

  const refreshAndStore = async (): Promise<boolean> => {
    if (!rt) return false;
    const s = await refreshOnce(rt, d);
    if (!s) return false;
    at = s.access_token;
    setCookies = sessionCookies(s, d.secure);
    return true;
  };

  if (!at && !(await refreshAndStore())) return json(401, { error: "unauthorized" }, clearCookies(d.secure));

  let res: Response;
  try {
    res = await call(at!);
    if (res.status === 401 && (await refreshAndStore())) res = await call(at!);
  } catch { return json(502, { error: "gateway_unreachable" }, setCookies); }

  if (res.status === 401) return json(401, { error: "unauthorized" }, clearCookies(d.secure));
  const text = res.status === 204 ? null : await res.text();
  const h = new Headers({ "content-type": "application/json", "cache-control": "no-store" });
  for (const c of setCookies) h.append("set-cookie", c);
  return new Response(text, { status: res.status, headers: h });
}

// ------------------------------------------------------------------ proxy
export async function handleProxy(req: Request, path: string[], d: BffDeps): Promise<Response> {
  const joined = path.join("/");
  if (!isAllowedProxy(req.method, joined)) return json(404, { error: "not_found" });
  if (!passesCsrf(req)) return json(403, { error: "csrf" });
  if (!hasCredentials(req)) return json(401, { error: "unauthorized" });

  const search = new URL(req.url).search;
  const bodyText = req.method === "GET" || req.method === "DELETE" ? undefined : await req.text();
  return relay(req, d, (token) => d.fetch(`${d.gatewayUrl}/v1/${joined}${search}`, {
    method: req.method,
    headers: { authorization: `Bearer ${token}`, ...(bodyText !== undefined ? { "content-type": "application/json" } : {}) },
    ...(bodyText !== undefined ? { body: bodyText } : {}),
  }));
}

// ------------------------------------------------------------------ file upload
/** Reads at most `max` bytes. Returns null as soon as the stream exceeds it, without buffering the rest. */
async function readCapped(req: Request, max: number): Promise<Uint8Array<ArrayBuffer> | null> {
  if (!req.body) return new Uint8Array(0);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) { await reader.cancel().catch(() => undefined); return null; }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.byteLength; }
  return out;
}

/** The browser's real file name is never forwarded: only a synthetic `upload.<ext>` (the name itself can contain personal data). */
export function syntheticFilename(header: string | null): string | null {
  if (!header || header.length > 1024) return null;
  let name: string;
  try { name = decodeURIComponent(header); } catch { return null; }
  const m = /\.([A-Za-z0-9]{1,8})$/.exec(name.trim());
  return m ? encodeURIComponent(`upload.${m[1]!.toLowerCase()}`) : null;
}

/**
 * POST /api/files/scan: the browser sends the raw file bytes (application/octet-stream); the bytes are relayed to the gateway's
 * `/v1/files/scan` with the session's bearer token. Uploads are held in memory only. A body that does not match its declared
 * Content-Length (e.g. truncated by an intermediary) is rejected rather than scanned, because a truncated file could hide content.
 */
export async function handleFileScan(req: Request, d: BffDeps): Promise<Response> {
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });
  if (!passesCsrf(req)) return json(403, { error: "csrf" });
  if (!hasCredentials(req)) return json(401, { error: "unauthorized" });

  const max = d.maxUploadBytes ?? DEFAULT_MAX_UPLOAD_BYTES;
  if ((req.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase() !== "application/octet-stream") return json(415, { error: "unsupported_media_type" });

  const declaredHeader = req.headers.get("content-length");
  const declared = declaredHeader === null ? null : Number(declaredHeader);
  if (declared !== null && (!Number.isInteger(declared) || declared < 0)) return json(400, { error: "invalid_request" });
  if (declared !== null && declared > max) return json(413, { error: "payload_too_large" });

  const bytes = await readCapped(req, max).catch(() => undefined);
  if (bytes === undefined) return json(400, { error: "invalid_request" });
  if (bytes === null) return json(413, { error: "payload_too_large" });
  if (declared !== null && bytes.byteLength !== declared) return json(400, { error: "incomplete_upload" });
  if (bytes.byteLength === 0) return json(422, { error: "invalid_request", issues: [{ path: "body", message: "a non-empty file is required" }] });

  const filename = syntheticFilename(req.headers.get("x-filename"));
  return relay(req, d, (token) => d.fetch(`${d.gatewayUrl}/v1/files/scan`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/octet-stream", ...(filename ? { "x-filename": filename } : {}) },
    body: bytes,
  }));
}
