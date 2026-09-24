# Organization management: users, invitations, teams, provider credentials

All routes here require **`users:manage`** (users, invitations, teams) or **`providers:manage`** (providers) *and a user
session*. An API key is never accepted, whatever role it holds: a leaked key cannot create users, change roles, or store
provider credentials. Every change is written to the audit log.

## Users

| Route | Behaviour |
|---|---|
| `GET /v1/users` | Members with role, status, teams |
| `PATCH /v1/users/{id}` | Change role and/or enable/disable |
| `DELETE /v1/users/{id}` | Disable (soft): audit history keeps pointing at a real user |

Rules, each enforced server-side and tested:

* **No privilege escalation.** A caller may only act on users whose role, and grant roles whose permissions, are a subset
  of their own. An ADMIN can neither modify an OWNER nor promote anyone to OWNER.
* **No self-modification.** You cannot change your own role or disable yourself — that is how organizations lock
  themselves out. Another administrator does it.
* **An organization always keeps an active OWNER.** Enforced by a database trigger, not only by the API: no code path, bug
  or direct SQL statement can leave an organization unadministrable. The API surfaces it as `409 last_owner`.
* **Changes take effect on the next request.** Session tokens are re-checked against the database on every request, so a
  disabled user is refused immediately and a demoted user immediately loses the permissions they lost — the access token
  is not authoritative until it expires. Disabling also revokes the user's refresh tokens (database trigger), so their
  session cannot be renewed.
* Another organization's user is `404`, never `403`: the API does not confirm that an id exists elsewhere.

## Invitations

`POST /v1/invitations` returns a token **exactly once**. Only an HMAC of it is stored, so a database dump cannot be used
to accept invitations. Acceptance (`POST /v1/invitations/accept`) is public — the invitee has no account yet — rate
limited per IP, and single use.

Invalid, expired, revoked and already-used tokens all answer the same `400 invalid_invitation`. One live invitation per
address per organization; an expired one can be re-issued. Inviting someone whose address already has an account
elsewhere fails at acceptance with `409 account_exists` (one organization per user, as the schema requires).

The dashboard puts the token in the **URL fragment** (`/accept-invite#sni_…`), which browsers never send to a server and
never put in a `Referer` header, and strips it from the address bar once read.

## Teams

Teams group people for reporting (the `team` field on security events). **They are not an authorization boundary** —
access is decided by role alone. `GET/POST /v1/teams`, `DELETE /v1/teams/{id}`, and
`PUT|DELETE /v1/teams/{id}/members/{userId}` (adding is idempotent).

## Per-organization provider credentials

`GET /v1/providers` shows, per provider, which key requests use (`organization`, `platform`, `disabled`, `none`) and, for
a stored credential, a 4-character hint and the sealing key id. The credential itself is **write-only**: no endpoint, log
line or audit record ever contains it.

`PUT /v1/providers/{provider}/credential` accepts a key for `gemini`, `openai` or `anthropic` and seals it with
**AES-256-GCM** before it reaches the database. The additional authenticated data binds the ciphertext to
`organization:provider`, so a row copied to another organization or provider fails authentication instead of lending one
tenant's key to another. `PROVIDER_CREDENTIAL_KEYS` (`p1:<base64 32 bytes>[,p2:…]`) holds the master keys; the first is
used for new credentials and the rest stay readable, which is what makes rotation possible. Without it configured the
endpoint answers `503`, so a deployment can never half-store credentials.

Routing per request, in order:

1. the organization disabled the provider → the request is **blocked** as `unknown_provider`;
2. the organization stored its own key → a provider instance built with **that** key;
3. otherwise → the operator's key, if one is configured.

If a stored credential cannot be decrypted (master key removed, ciphertext tampered with or moved between tenants), the
request is **blocked and audited** (`provider_config_unavailable`) rather than falling back to the operator's key.
Spending the operator's account on a request the organization meant to bill to its own key — or silently switching data
processors — is not an acceptable degradation.

Per-organization base URLs are deliberately **not** supported: letting a tenant point the gateway at an arbitrary host is
an SSRF surface. Base URLs remain operator configuration (a database CHECK enforces it).

Settings are cached per organization for 30 seconds and invalidated immediately on the replica that changes them; other
replicas pick a change up within the TTL.
