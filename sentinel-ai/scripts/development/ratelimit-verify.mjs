#!/usr/bin/env node
/**
 * Rate limiting of the RUNNING gateway, measured from one client. Run against a freshly started gateway (the limiters are
 * in memory) with the default limits: 600 requests/min per client IP (every route), and 20 attempts/min per IP on
 * /v1/auth/* (signup, login, refresh, logout). Both limiters count every request they see, including rejected ones, so
 * the expected numbers below are exact, not approximate.
 *
 *   docker run --rm --network sentinel-ai_frontend -v "$PWD/scripts/development:/s:ro" node:20-alpine node /s/ratelimit-verify.mjs
 */
const API = process.env.API_URL ?? "http://api:4000";
let failures = 0;
const check = (name, ok, detail = "") => { console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? `  (${detail})` : ""}`); if (!ok) failures++; };
const post = (path, body, headers = {}) => fetch(`${API}${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });

let used = 0;                                                    // requests this client has sent in the current window

// 1. Auth limiter first (after the global window is exhausted, the global limiter would answer instead).
const s = await (await post("/v1/auth/signup", { organization_name: `rl-${Date.now().toString(36)}`, email: `rl-${Date.now().toString(36)}@example.com`, password: "Str0ng-Rl-Passw0rd!" })).json();
used++;                                                          // auth attempt #1 (signup)
const loginCodes = [];
for (let i = 0; i < 25; i++) {                                   // distinct emails: the per-email limiter (10/min) is not involved
  const r = await post("/v1/auth/login", { email: `nobody-${i}@example.com`, password: "wrong-password-123" });
  loginCodes.push(r.status); await r.text(); used++;
}
// Auth attempts 2..20 are allowed (19 logins answer 401), attempts 21..26 are refused (6 logins answer 429).
check("auth limiter: 20 attempts/min per IP - 19 wrong-password logins answer 401, the next 6 answer 429",
  loginCodes.slice(0, 19).every((c) => c === 401) && loginCodes.slice(19).every((c) => c === 429), loginCodes.join(","));

// 2. Global per-IP limit.
const k = await (await post("/v1/api-keys", { name: "rl", role: "DEVELOPER" }, { authorization: `Bearer ${s.access_token}` })).json();
used++;
const codes = {}; let retryAfter = null;
await Promise.all(Array.from({ length: 700 }, async () => {
  const r = await post("/v1/security/check", { text: "hello" }, { "x-sentinel-api-key": k.key });
  codes[r.status] = (codes[r.status] ?? 0) + 1;
  if (r.status === 429) retryAfter ??= r.headers.get("retry-after");
  await r.text();
}));
const expectOk = 600 - used;                                     // 600 per window, minus what setup already used
check(`global limit: 600 requests/min per IP - of 700 sent, exactly ${expectOk} served (${used} used by setup) and ${700 - expectOk} refused`,
  (codes[200] ?? 0) === expectOk && (codes[429] ?? 0) === 700 - expectOk, JSON.stringify(codes));
check("429 responses carry a Retry-After within the window", retryAfter !== null && Number(retryAfter) > 0 && Number(retryAfter) <= 60, `retry-after=${retryAfter}`);

process.exit(failures === 0 ? 0 : 1);
