# ADR-0006: Dashboard is a backend-for-frontend; browsers never hold tokens

**Status:** accepted

**Context.** Storing a refresh token in `localStorage` (or any JavaScript-readable place) turns any XSS into full account takeover for 30 days.

**Decision.** The Next.js server is a BFF (`apps/dashboard/lib/api/bff.ts`).
- Login/registration go to `/api/auth/*`; the BFF calls the gateway and sets three cookies, all `HttpOnly; SameSite=Strict; Secure` (in production):
  `sn_at` (access token, path `/`), `sn_rt` (refresh token, path `/api` only - never sent to page routes), `sn_sess` (non-secret presence marker so page middleware can gate navigation).
  The JSON returned to the browser contains only the user, never a token.
- File uploads use a separate route, `/api/files/scan`, because the JSON proxy cannot carry binary bodies. It is excluded from the Next middleware matcher: Next clones request bodies that pass through middleware and caps them (10 MB by default in Next 15.5), which we observed truncating a 15 MB upload. The route therefore does its own CSRF/Origin, session and size checks, reads the body with a hard cap, and rejects any body that does not match its declared `Content-Length` rather than scanning a truncated file.
- The browser calls `/api/proxy/*`. The BFF attaches the bearer token, relays the response, and transparently refreshes an expired access token.
- **Allow-list:** only the gateway routes the dashboard needs are proxied (events, usage, policies, `security/scan`, `auth/me`); `ai/chat`, `auth/*` administration and everything else return 404.
- **CSRF:** SameSite=Strict plus a required custom header (`x-sentinel-csrf`) and Origin-must-match-Host on every non-GET request.
- **CSP:** per-request nonce with `strict-dynamic` (middleware), so every page is rendered dynamically; no `unsafe-inline` for scripts; `frame-ancestors 'none'`.
- **Refresh races:** rotating refresh tokens + several parallel API calls would look like token reuse and revoke the session, so concurrent refreshes with the same token share one gateway call.
  The sharing window is **5 seconds** and cached sessions are purged on logout. An earlier 30 s window was found (by replay testing against the live stack) to let a stolen, already-rotated token obtain a live session; see `tests/bff.test.ts`.

**Consequences / residual risk**
- Within 5 s of a legitimate rotation, on the same BFF instance, a replayed old token is served the shared session. Multi-instance deployments need sticky sessions or a shared (Redis) single-flight store.
- Access tokens (15 min) cannot be revoked; logout revokes the refresh family only.
- The navigation gate (`sn_sess`) is UX; the gateway authorizes every call.
