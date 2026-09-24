/** Browser-side API client. It only ever talks to same-origin /api/*; no tokens are visible to this code. */

export class ApiError extends Error {
  constructor(public readonly status: number, public readonly code: string, message?: string, public readonly reason?: string) {
    super(message ?? code);
    this.name = "ApiError";
  }
}

const HEADERS = { "content-type": "application/json", "x-sentinel-csrf": "1" } as const;

async function request<T>(url: string, init: RequestInit, redirectOn401: boolean): Promise<T> {
  let res: Response;
  try { res = await fetch(url, { ...init, headers: { ...HEADERS, ...(init.headers as Record<string, string> | undefined) }, credentials: "same-origin", cache: "no-store" }); }
  catch { throw new ApiError(0, "network_error", "Cannot reach the server."); }

  if (res.status === 401 && redirectOn401 && typeof window !== "undefined") {
    window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname)}`);
  }
  if (res.status === 204) return undefined as T;
  const body = (await res.json().catch(() => ({}))) as { error?: string; message?: string; reason?: string; issues?: { path: string; message: string }[] };
  if (!res.ok) {
    const detail = body.issues?.map((i) => `${i.path}: ${i.message}`).join("; ") ?? body.message;
    throw new ApiError(res.status, body.error ?? "request_failed", detail, typeof body.reason === "string" ? body.reason : undefined);
  }
  return body as T;
}

export const api = {
  get: <T>(path: string) => request<T>(`/api/proxy/${path}`, { method: "GET" }, true),
  post: <T>(path: string, body: unknown) => request<T>(`/api/proxy/${path}`, { method: "POST", body: JSON.stringify(body) }, true),
  put: <T>(path: string, body: unknown) => request<T>(`/api/proxy/${path}`, { method: "PUT", body: JSON.stringify(body) }, true),
  patch: <T>(path: string, body: unknown) => request<T>(`/api/proxy/${path}`, { method: "PATCH", body: JSON.stringify(body) }, true),
  del: <T>(path: string) => request<T>(`/api/proxy/${path}`, { method: "DELETE" }, true),
};

/** Uploads the raw file. Only a synthetic `upload.<ext>` name is sent: the real file name can itself contain personal data. */
export function uploadFile<T>(file: File): Promise<T> {
  const ext = /\.([A-Za-z0-9]{1,8})$/.exec(file.name)?.[1]?.toLowerCase();
  return request<T>("/api/files/scan", {
    method: "POST", body: file,
    headers: { "content-type": "application/octet-stream", ...(ext ? { "x-filename": encodeURIComponent(`upload.${ext}`) } : {}) },
  }, true);
}

export const auth = {
  login: (email: string, password: string) => request<{ user: unknown }>("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }, false),
  register: (organization_name: string, email: string, password: string) =>
    request<{ user: unknown }>("/api/auth/register", { method: "POST", body: JSON.stringify({ organization_name, email, password }) }, false),
  logout: () => request<{ ok: true }>("/api/auth/logout", { method: "POST", body: "{}" }, false),
  acceptInvite: (token: string, password: string) =>
    request<{ ok: true; role: string | null }>("/api/auth/accept", { method: "POST", body: JSON.stringify({ token, password }) }, false),
};

const EXPLAIN: Record<string, string> = {
  cannot_modify_self: "You cannot change your own role or disable yourself. Ask another administrator.",
  user_has_higher_privilege: "That user holds permissions you do not have.",
  invitation_has_higher_privilege: "That invitation grants permissions you do not have.",
  cannot_grant_role: "You can only grant roles whose permissions you already hold.",
  user_session_required: "Sign in as a user to do this (API keys cannot).",
  last_owner: "The organization must keep at least one active OWNER.",
  already_member: "That person is already a member of this organization.",
  invitation_pending: "There is already a pending invitation for that address. Revoke it first.",
  team_exists: "A team with that name already exists.",
  credential_storage_not_configured: "The operator has not configured credential storage (PROVIDER_CREDENTIAL_KEYS).",
  invalid_invitation: "This invitation is invalid, expired, revoked or already used. Ask your administrator for a new one.",
  account_exists: "An account with this email address already exists. Sign in instead.",
};

/** Message for a known gateway reason/error code, falling back to describeError. */
export function explainError(err: unknown): string {
  if (err instanceof ApiError) {
    const known = (err.reason && EXPLAIN[err.reason]) || EXPLAIN[err.code];
    if (known) return known;
  }
  return describeError(err);
}

/** Human-readable message for an error, never exposing internals. */
export function describeError(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 403) return "You do not have permission to do this.";
    if (err.status === 429) return "Too many requests. Please wait a moment and try again.";
    if (err.status === 502 || err.status === 0) return "The server is unreachable. Try again shortly.";
    return err.message === err.code ? `Request failed (${err.code}).` : err.message;
  }
  return "Something went wrong.";
}
