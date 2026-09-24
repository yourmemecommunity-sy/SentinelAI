# Authentication

Two credential types are accepted on every `/v1/*` route (`Authorization: Bearer <token>`, or `x-sentinel-api-key: <key>` for keys).
Each resolves to a *principal* (organization + role); RBAC permissions are then enforced per route.

## User sessions (implemented)

| Endpoint | Purpose |
|---|---|
| `POST /v1/auth/signup` | Create an organization and its OWNER. **Disabled by default in production** (`SIGNUP_ENABLED=true` to enable). 201 / 403 / 409 / 422 |
| `POST /v1/auth/login` | Email + password -> access token + refresh token. Failure is always `401 invalid_credentials` |
| `POST /v1/auth/refresh` | Rotate a refresh token -> new pair. Failure is always `401 invalid_token` |
| `POST /v1/auth/logout` | Revoke the refresh-token family. Always `204` |
| `GET /v1/auth/me` | Who am I (works for JWTs and API keys) |

- **Passwords:** scrypt (N=2^15, r=8, p=1, 16-byte salt), parameters stored in the hash so they can be raised; verification refuses
  attacker-supplied cost parameters. Policy: 12-128 chars, not containing the email name, not trivially repetitive. Input is NFKC-normalized.
- **Uniform failures + timing:** unknown email, wrong password and disabled account return the *same* response, and an unknown email still
  performs one scrypt verification against a dummy hash.
- **Access token:** JWT, HS256 pinned (`alg: none` / other algorithms rejected), 15 min default, `iss`/`aud`/`exp`/`sub`/`org`/`role` all
  required and validated, `jti` included. Secret `JWT_ACCESS_SECRET` (>= 32 chars, must differ from the API-key pepper in production).
- **Refresh token:** opaque 256-bit random value, only its SHA-256 stored, 30 days default. **Rotation with reuse detection:** each refresh
  atomically revokes the presented token and issues a successor in the same *family*; presenting an already-used token revokes the whole
  family (theft/replay) and is audited (`auth.refresh_reuse_detected`). Concurrent use of one token yields at most one success.
- **Role changes / disabling** take effect at the next refresh (<= access-token TTL); access tokens are not checked against the DB per request.
- **Throttling:** `/v1/auth/*` has its own limiter (20/min per IP, 10/min per login email) in addition to the global limiter. In-process only.
- Audit: `auth.signup`, `auth.login`, `auth.login_failed`, `auth.logout`, `auth.refresh_reuse_detected` go to `audit_logs` (metadata only).

## API-key management (implemented)
`GET /v1/api-keys`, `POST /v1/api-keys {name, role, expires_in_days?}`, `DELETE /v1/api-keys/:id` (dashboard: **API keys**). Rules, each enforced server-side and tested:
- needs `keys:manage` (OWNER, ADMIN, DEVELOPER) **and a user session**: an API key can never create, list or revoke keys (no self-perpetuating credentials);
- **no privilege escalation**: you may only grant a role whose permissions are a subset of your own (a DEVELOPER can mint only DEVELOPER keys; only OWNER can mint OWNER) and only revoke keys you could grant;
- the secret is returned **once** (`Cache-Control: no-store`); listings never include it, its hash, or its random part;
- keys expire (default 90 days, max 365), each organization is capped at 100 active keys, `last_used_at` is refreshed at most hourly;
- create and revoke are written to the audit log (metadata only).
Roles and permissions are defined once in `@sentinelai/shared-types` (used by gateway and dashboard); the DB seed is asserted equal to it. Migration 0006 gave ADMIN `evaluation:run` so ADMIN is a superset of SECURITY_ANALYST.

## API keys (implemented, machine access)
- `snl_<8 id chars>_<43 secret chars>`; shown once; only `HMAC-SHA256(API_KEY_HASH_PEPPER, key)` and a 12-char prefix are stored. Lookup by exact
  prefix through a `SECURITY DEFINER` function, constant-time compare, dummy compare for unknown prefixes.
- Malformed, unknown, revoked, expired and wrong-secret keys all return the same `401`.

## Not implemented
MFA/TOTP, SSO/SAML/OIDC/SCIM, email verification and password reset, user/team management endpoints, account lockout beyond throttling,
access-token revocation list, per-device session listing.
