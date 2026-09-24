import { describe, expect, it, vi } from "vitest";
import {
  COOKIE, CSRF_HEADER, clearCookies, handleAcceptInvite, handleAuth, handleProxy, isAllowedProxy, parseCookies, passesCsrf, refreshOnce, sessionCookies,
} from "@/lib/api/bff";

const SESSION = { access_token: "AT1", refresh_token: "snr_RT1", expires_in: 900, user: { id: "u1", organization_id: "o1", role: "OWNER" } };
const jsonRes = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const deps = (f: (url: string, init?: RequestInit) => Promise<Response>, secure = false) => ({ gatewayUrl: "http://gw.test", fetch: f as unknown as typeof fetch, secure });
const req = (method: string, url: string, init: { headers?: Record<string, string>; body?: unknown } = {}) =>
  new Request(`http://dash.test${url}`, { method, headers: { host: "dash.test", ...init.headers }, ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}) });
const post = (url: string, body: unknown, headers: Record<string, string> = {}) => req("POST", url, { body, headers: { [CSRF_HEADER]: "1", origin: "http://dash.test", ...headers } });
const setCookies = (r: Response) => r.headers.getSetCookie();

describe("cookies", () => {
  it("session cookies are HttpOnly + SameSite=Strict, the refresh token is scoped to /api, and Secure follows the flag", () => {
    const [at, rt, sess] = sessionCookies(SESSION, true);
    for (const c of [at, rt, sess]) { expect(c).toContain("HttpOnly"); expect(c).toContain("SameSite=Strict"); expect(c).toContain("Secure"); }
    expect(at).toContain("Path=/;"); expect(at).toContain("Max-Age=900");
    expect(rt).toContain("Path=/api;");
    expect(sessionCookies(SESSION, false).join()).not.toContain("Secure");
  });

  it("clearing expires all three cookies at the same paths", () => {
    const c = clearCookies(false);
    expect(c.every((x) => x.includes("Max-Age=0"))).toBe(true);
    expect(c.map((x) => x.split("=")[0])).toEqual([COOKIE.access, COOKIE.refresh, COOKIE.session]);
  });

  it("parseCookies handles encoding, spacing and garbage", () => {
    expect(parseCookies("a=1; b=x%20y;  c=3")).toEqual({ a: "1", b: "x y", c: "3" });
    expect(parseCookies(null)).toEqual({});
    expect(parseCookies("noequals; =bad")).toEqual({});
    expect(parseCookies("good=1; bad=%E0%A4%A; also=2")).toEqual({ good: "1", also: "2" });
  });
});

describe("CSRF", () => {
  it("GET needs nothing; mutations need the custom header and a matching Origin", () => {
    expect(passesCsrf(req("GET", "/x"))).toBe(true);
    expect(passesCsrf(req("POST", "/x"))).toBe(false);
    expect(passesCsrf(post("/x", {}))).toBe(true);
    expect(passesCsrf(post("/x", {}, { origin: "http://evil.test" }))).toBe(false);
    expect(passesCsrf(post("/x", {}, { origin: "not a url" }))).toBe(false);
    expect(passesCsrf(req("POST", "/x", { headers: { origin: "http://dash.test" } }))).toBe(false);
    expect(passesCsrf(req("DELETE", "/x", { headers: { [CSRF_HEADER]: "0" } }))).toBe(false);
  });
});

describe("proxy allow-list", () => {
  it("allows only the dashboard's routes and methods", () => {
    for (const [m, p] of [["GET", "events"], ["GET", "events/11111111-1111-4111-8111-111111111111"], ["GET", "usage"], ["GET", "policies"], ["POST", "policies"],
      ["PUT", "policies/eng"], ["DELETE", "policies/eng"], ["POST", "security/scan"], ["GET", "auth/me"],
      ["GET", "api-keys"], ["POST", "api-keys"], ["DELETE", "api-keys/11111111-1111-4111-8111-111111111111"]] as const) expect(isAllowedProxy(m, p), `${m} ${p}`).toBe(true);
    for (const [m, p] of [["POST", "ai/chat"], ["POST", "auth/login"], ["POST", "auth/refresh"], ["GET", "policies/../auth/me"], ["GET", "events/not-a-uuid"],
      ["DELETE", "events"], ["PUT", "policies"], ["GET", ""], ["GET", "internal/scan"], ["POST", "auth/signup"],
      ["DELETE", "api-keys"], ["PUT", "api-keys/11111111-1111-4111-8111-111111111111"], ["GET", "api-keys/11111111-1111-4111-8111-111111111111"], ["DELETE", "api-keys/x"]] as const) expect(isAllowedProxy(m, p), `${m} ${p}`).toBe(false);
  });
});

describe("login / register / logout", () => {
  it("login sets cookies, returns ONLY the user (never tokens), and forwards credentials to the gateway", async () => {
    const f = vi.fn(async () => jsonRes(SESSION));
    const res = await handleAuth("login", post("/api/auth/login", { email: "a@b.co", password: "pw" }), deps(f));
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(JSON.parse(body)).toEqual({ user: SESSION.user });
    expect(body).not.toContain("AT1"); expect(body).not.toContain("snr_RT1");
    expect(setCookies(res)).toHaveLength(3);
    expect(f).toHaveBeenCalledWith("http://gw.test/v1/auth/login", expect.objectContaining({ method: "POST" }));
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("register maps to signup and returns 201", async () => {
    const f = vi.fn(async (_u: string, _i?: RequestInit) => jsonRes(SESSION, 201));
    const res = await handleAuth("register", post("/api/auth/register", { organization_name: "X", email: "a@b.co", password: "pw" }), deps(f));
    expect(res.status).toBe(201);
    expect(f.mock.calls[0]![0]).toBe("http://gw.test/v1/auth/signup");
  });

  it("failures pass through status + error code only and set no cookies", async () => {
    const res = await handleAuth("login", post("/x", { email: "a@b.co", password: "bad" }), deps(async () => jsonRes({ error: "invalid_credentials", stack: "secret internals", access_token: "leak" }, 401)));
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_credentials" });
    expect(setCookies(res)).toHaveLength(0);
    const weak = await handleAuth("register", post("/x", { a: 1 }), deps(async () => jsonRes({ error: "weak_password", message: "password must be at least 12 characters" }, 422)));
    expect(await weak.json()).toEqual({ error: "weak_password", message: "password must be at least 12 characters" });
  });

  it("gateway down -> 502, malformed body -> 422, missing CSRF -> 403 (gateway not called)", async () => {
    const f = vi.fn(async () => { throw new Error("ECONNREFUSED"); });
    expect((await handleAuth("login", post("/x", {}), deps(f))).status).toBe(502);
    const g = vi.fn();
    expect((await handleAuth("login", new Request("http://dash.test/x", { method: "POST", body: "not json", headers: { [CSRF_HEADER]: "1", host: "dash.test" } }), deps(g as never))).status).toBe(422);
    expect((await handleAuth("login", req("POST", "/x", { body: {} }), deps(g as never))).status).toBe(403);
    expect(g).not.toHaveBeenCalled();
  });

  it("a gateway 'success' without tokens is treated as a failure (no half-sessions)", async () => {
    const res = await handleAuth("login", post("/x", {}), deps(async () => jsonRes({ user: SESSION.user })));
    expect(setCookies(res)).toHaveLength(0);
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it("logout revokes the refresh token at the gateway and clears cookies even if the gateway is down", async () => {
    const f = vi.fn(async (_u: string, _i?: RequestInit) => new Response(null, { status: 204 }));
    const res = await handleAuth("logout", post("/x", {}, { cookie: `${COOKIE.refresh}=snr_RT1` }), deps(f));
    expect(JSON.parse(f.mock.calls[0]![1]!.body as string)).toEqual({ refresh_token: "snr_RT1" });
    expect(setCookies(res).every((c) => c.includes("Max-Age=0"))).toBe(true);
    const down = await handleAuth("logout", post("/x", {}, { cookie: `${COOKIE.refresh}=snr_RT1` }), deps(async () => { throw new Error("x"); }));
    expect(down.status).toBe(200);
  });
});

describe("proxy", () => {
  it("attaches the bearer token server-side and relays status + body; never forwards the browser's cookies", async () => {
    const f = vi.fn(async () => jsonRes({ events: [] }));
    const res = await handleProxy(req("GET", "/api/proxy/events?limit=5", { headers: { cookie: `${COOKIE.access}=AT1; ${COOKIE.refresh}=snr_RT1` } }), ["events"], deps(f));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ events: [] });
    const [url, init] = f.mock.calls[0]! as unknown as [string, RequestInit];
    expect(url).toBe("http://gw.test/v1/events?limit=5");
    expect(init.headers).toEqual({ authorization: "Bearer AT1" });
  });

  it("rejects disallowed paths (404), missing CSRF on mutations (403) and missing credentials (401) without calling the gateway", async () => {
    const f = vi.fn();
    const d = deps(f as never);
    expect((await handleProxy(req("POST", "/x", { headers: { cookie: `${COOKIE.access}=AT1`, [CSRF_HEADER]: "1" }, body: {} }), ["ai", "chat"], d)).status).toBe(404);
    expect((await handleProxy(req("POST", "/x", { headers: { cookie: `${COOKIE.access}=AT1` }, body: {} }), ["policies"], d)).status).toBe(403);
    expect((await handleProxy(req("GET", "/x"), ["events"], d)).status).toBe(401);
    expect(f).not.toHaveBeenCalled();
  });

  it("forwards JSON bodies for mutations", async () => {
    const f = vi.fn(async () => jsonRes({ policy_id: "p", version: 1 }, 201));
    const res = await handleProxy(post("/x", { policy_id: "p", rules: [] }, { cookie: `${COOKIE.access}=AT1` }), ["policies"], deps(f));
    expect(res.status).toBe(201);
    const init = (f.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect(JSON.parse(init.body as string)).toEqual({ policy_id: "p", rules: [] });
    expect((init.headers as Record<string, string>)["content-type"]).toBe("application/json");
  });

  it("204 responses stay empty", async () => {
    const res = await handleProxy(req("DELETE", "/x", { headers: { cookie: `${COOKIE.access}=AT1`, [CSRF_HEADER]: "1" } }), ["policies", "eng"], deps(async () => new Response(null, { status: 204 })));
    expect(res.status).toBe(204);
  });

  it("transparently refreshes an expired access token, retries once, and sets new cookies", async () => {
    const calls: string[] = [];
    const f = async (url: string, init?: RequestInit) => {
      calls.push(`${url} ${(init?.headers as Record<string, string> | undefined)?.authorization ?? ""}`);
      if (url.endsWith("/v1/auth/refresh")) return jsonRes({ ...SESSION, access_token: "AT2", refresh_token: "snr_RT2" });
      return (init!.headers as Record<string, string>).authorization === "Bearer AT2" ? jsonRes({ ok: true }) : jsonRes({ error: "unauthorized" }, 401);
    };
    const res = await handleProxy(req("GET", "/x", { headers: { cookie: `${COOKIE.access}=OLD; ${COOKIE.refresh}=snr_RT_A` } }), ["usage"], deps(f));
    expect(res.status).toBe(200);
    expect(setCookies(res).join("|")).toContain("sn_at=AT2");
    expect(calls.map((c) => c.split(" ")[0]!.replace("http://gw.test", ""))).toEqual(["/v1/usage", "/v1/auth/refresh", "/v1/usage"]);
  });

  it("with no access cookie but a refresh cookie, refreshes first", async () => {
    const f = async (url: string, init?: RequestInit) => url.endsWith("/refresh") ? jsonRes({ ...SESSION, access_token: "AT3", refresh_token: "snr_RT3" }) : jsonRes({ who: (init!.headers as Record<string, string>).authorization });
    const res = await handleProxy(req("GET", "/x", { headers: { cookie: `${COOKIE.refresh}=snr_RT_B` } }), ["auth", "me"], deps(f));
    expect(await res.json()).toEqual({ who: "Bearer AT3" });
  });

  it("if refresh fails, the session is cleared and the caller gets 401", async () => {
    const f = async (url: string) => url.endsWith("/refresh") ? jsonRes({ error: "invalid_token" }, 401) : jsonRes({ error: "unauthorized" }, 401);
    const res = await handleProxy(req("GET", "/x", { headers: { cookie: `${COOKIE.access}=OLD; ${COOKIE.refresh}=snr_RT_C` } }), ["usage"], deps(f));
    expect(res.status).toBe(401);
    expect(setCookies(res).every((c) => c.includes("Max-Age=0"))).toBe(true);
  });

  it("a 403 from the gateway is relayed as 403 (no refresh, session kept)", async () => {
    const res = await handleProxy(req("GET", "/x", { headers: { cookie: `${COOKIE.access}=AT1; ${COOKIE.refresh}=snr_RT1` } }), ["events"], deps(async () => jsonRes({ error: "forbidden" }, 403)));
    expect(res.status).toBe(403);
    expect(setCookies(res)).toHaveLength(0);
  });

  it("gateway unreachable -> 502", async () => {
    const res = await handleProxy(req("GET", "/x", { headers: { cookie: `${COOKIE.access}=AT1` } }), ["events"], deps(async () => { throw new Error("down"); }));
    expect(res.status).toBe(502);
  });
});

describe("refresh single-flight (rotation must not be raced by parallel page requests)", () => {
  it("N concurrent requests with the same expired session cause exactly ONE refresh call", async () => {
    let refreshCalls = 0;
    const f = async (url: string, init?: RequestInit) => {
      if (url.endsWith("/v1/auth/refresh")) { refreshCalls++; await new Promise((r) => setTimeout(r, 30)); return jsonRes({ ...SESSION, access_token: "ATN", refresh_token: "snr_RTN" }); }
      return (init!.headers as Record<string, string>).authorization === "Bearer ATN" ? jsonRes({ ok: 1 }) : jsonRes({ error: "unauthorized" }, 401);
    };
    const d = deps(f);
    const one = () => handleProxy(req("GET", "/x", { headers: { cookie: `${COOKIE.access}=EXPIRED; ${COOKIE.refresh}=snr_SHARED` } }), ["usage"], d);
    const results = await Promise.all([one(), one(), one(), one(), one()]);
    expect(results.map((r) => r.status)).toEqual([200, 200, 200, 200, 200]);
    expect(refreshCalls).toBe(1);
  });

  it("different sessions do not share a refresh", async () => {
    let n = 0;
    const d = deps(async () => { n++; return jsonRes(SESSION); });
    await Promise.all([refreshOnce("snr_X1", d), refreshOnce("snr_X2", d)]);
    expect(n).toBe(2);
  });
});

describe("refresh sharing is bounded (a stolen, already-rotated token must not mint a live session)", () => {
  const rotated = () => jsonRes({ ...SESSION, access_token: "ATX", refresh_token: "snr_LIVE" });

  it("after the share window, presenting the OLD refresh token hits the gateway again (which will flag reuse)", async () => {
    const { REFRESH_SHARE_MS } = await import("@/lib/api/bff");
    let calls = 0;
    const d = deps(async () => { calls++; return calls === 1 ? rotated() : jsonRes({ error: "invalid_token" }, 401); });
    const t0 = Date.now();
    const spy = vi.spyOn(Date, "now");
    spy.mockReturnValue(t0);
    expect((await refreshOnce("snr_OLD1", d))?.refresh_token).toBe("snr_LIVE");
    spy.mockReturnValue(t0 + REFRESH_SHARE_MS - 1);
    expect((await refreshOnce("snr_OLD1", d))?.refresh_token).toBe("snr_LIVE"); // in-flight burst: shared
    expect(calls).toBe(1);
    spy.mockReturnValue(t0 + REFRESH_SHARE_MS + 1);
    expect(await refreshOnce("snr_OLD1", d)).toBeNull();                          // replay: NOT served from cache
    expect(calls).toBe(2);
    spy.mockRestore();
  });

  it("logout purges cached sessions so a replay right after logout cannot obtain tokens", async () => {
    const { forgetRefresh } = await import("@/lib/api/bff");
    let calls = 0;
    const d = deps(async () => { calls++; return calls === 1 ? rotated() : jsonRes({ error: "invalid_token" }, 401); });
    await refreshOnce("snr_OLD2", d);                 // legit rotation: OLD2 -> snr_LIVE
    await handleAuth("logout", post("/x", {}, { cookie: `${COOKIE.refresh}=snr_LIVE` }), d); // user logs out with the new token
    expect(await refreshOnce("snr_OLD2", d)).toBeNull();   // attacker replays OLD2 immediately: cache was purged
    forgetRefresh("snr_LIVE");
  });

  it("failed refreshes are never cached", async () => {
    let calls = 0;
    const d = deps(async () => { calls++; return jsonRes({ error: "invalid_token" }, 401); });
    await refreshOnce("snr_BAD", d); await refreshOnce("snr_BAD", d);
    expect(calls).toBe(2);
  });
});

describe("user, team and provider management routes", () => {
  const U = "11111111-1111-4111-8111-111111111111";
  it("allows exactly the management routes the pages use", () => {
    for (const [m, p] of [["GET", "users"], ["PATCH", `users/${U}`], ["DELETE", `users/${U}`], ["GET", "invitations"], ["POST", "invitations"],
      ["DELETE", `invitations/${U}`], ["GET", "teams"], ["POST", "teams"], ["DELETE", `teams/${U}`], ["PUT", `teams/${U}/members/${U}`],
      ["DELETE", `teams/${U}/members/${U}`], ["GET", "providers"], ["PUT", "providers/openai/credential"], ["DELETE", "providers/gemini/credential"],
      ["PATCH", "providers/anthropic"]] as const) expect(isAllowedProxy(m, p), `${m} ${p}`).toBe(true);
  });
  it("refuses everything else: public accept via the proxy, other providers' credentials, traversal, wrong methods", () => {
    for (const [m, p] of [["POST", "invitations/accept"], ["PUT", "providers/ollama/credential"], ["PUT", "providers/../credential"],
      ["PATCH", "users"], ["POST", `users/${U}`], ["PUT", `users/${U}`], ["GET", "providers/openai/credential"], ["PATCH", "providers/openai/credential"],
      ["DELETE", "users/x"], ["PUT", `teams/${U}/members/x`], ["PATCH", "providers/Open AI"]] as const) expect(isAllowedProxy(m, p), `${m} ${p}`).toBe(false);
  });
});

describe("invitation acceptance", () => {
  const TOKEN = "sni_" + "A".repeat(43);
  it("forwards only token and password, sets NO cookies, and never echoes the token", async () => {
    const f = vi.fn(async (_u: string, _i?: RequestInit) => jsonRes({ user_id: "u9", organization_id: "o1", role: "DEVELOPER" }, 201));
    const res = await handleAcceptInvite(post("/api/auth/accept", { token: TOKEN, password: "pw-long-enough", extra: "dropped" }), deps(f));
    expect(res.status).toBe(201);
    const body = await res.text();
    expect(JSON.parse(body)).toEqual({ ok: true, role: "DEVELOPER" });
    expect(body).not.toContain(TOKEN);
    expect(setCookies(res)).toHaveLength(0);
    expect(f.mock.calls[0]![0]).toBe("http://gw.test/v1/invitations/accept");
    expect(JSON.parse(String(f.mock.calls[0]![1]!.body))).toEqual({ token: TOKEN, password: "pw-long-enough" });
  });
  it("requires the CSRF header, rejects malformed bodies, and passes gateway errors through by code only", async () => {
    const f = vi.fn(async () => jsonRes({ error: "invalid_invitation", internal: "secret-detail" }, 400));
    expect((await handleAcceptInvite(req("POST", "/api/auth/accept", { body: { token: TOKEN, password: "x" } }), deps(f))).status).toBe(403);
    expect((await handleAcceptInvite(post("/api/auth/accept", { token: 5 }), deps(f))).status).toBe(422);
    expect(f).not.toHaveBeenCalled();
    const res = await handleAcceptInvite(post("/api/auth/accept", { token: TOKEN, password: "x" }), deps(f));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_invitation" });
    const down = await handleAcceptInvite(post("/api/auth/accept", { token: TOKEN, password: "x" }), deps(async () => { throw new Error("ECONNREFUSED"); }));
    expect(down.status).toBe(502);
  });
});
