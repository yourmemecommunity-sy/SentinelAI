# DevicePulse threat model

Scope: the DevicePulse endpoints of the SentinelAI gateway (`/v1/devicepulse/*`), the data they store, and the path to the
configured AI model. The Android app is in scope only where it holds credentials or renders responses. The rest of
SentinelAI is covered by `docs/security/threat-model.md`.

## Assets

| Asset | Why it matters |
|---|---|
| Device telemetry in a request | Can reveal usage patterns; combined with an account it is personal data |
| User credential on the phone (access/refresh token or per-installation key) | Lets anyone act as that user against DevicePulse |
| Provider API keys, gateway secrets, database credentials | Server-side only; must never reach a phone |
| Model output shown to the user | Users may act on it (change settings, delete data) |
| Request records and feedback | Small, but tied to a user id |
| Model spend | Every explain call costs money |

## Trust boundaries

1. Phone → gateway (public internet, TLS). Everything the phone sends is untrusted.
2. Gateway → security engine (internal network, shared internal token).
3. Gateway → AI provider (internet, TLS, operator credential).
4. Gateway → PostgreSQL (internal, RLS-restricted application role).

## Data flow of one explanation

```
phone ──TLS──► gateway: auth (JWT or key) → per-IP limit → role check (devicepulse:use) → per-credential limit
             → consent check → strict schema → semantic checks (units, bounds, timestamps, evidence references)
             → minimization (client ids → aliases E1/L1, timestamps → age in minutes, consent and app version dropped)
             → org provider settings → org policy → security-engine scan of the prompt → audit event
             → model call (one configured provider, deadline) → security-engine scan of the reply → audit event
             → reply validation (JSON, evidence/action/limitation ids, no links or markup) → alias → client ids
             → request record → response
```

Any failure after the consent check ends the request with a typed error. Nothing falls through to an unscreened path.

## Threats and controls

| # | Threat | Control | Verified by |
|---|---|---|---|
| DP-T1 | A credential is extracted from the APK | No credential is shipped in the APK. Users obtain short-lived access tokens via `/v1/auth/login`; refresh tokens rotate. The `DEVICE_CLIENT` role can only call DevicePulse: no `ai:use`, no `scan:use`, no `keys:manage` | `routes.test.ts` "DEVICE_CLIENT is least privilege"; e2e with a real API key |
| DP-T2 | A stolen or revoked token keeps working | Every request re-authenticates; JWTs are re-checked against the user's current state; revoked keys fail at once | `routes.test.ts` "revoked credential"; existing auth suites |
| DP-T3 | Forged or nonsensical telemetry | Metric/unit/type compatibility, physical bounds, integer checks, timestamp window, unique evidence ids, size limits; unknown fields rejected | `v1.test.ts`, `routes.test.ts` "untrusted telemetry" |
| DP-T4 | Prompt injection through request fields | No free-text field exists. Identifiers are limited to `[A-Za-z0-9_-]{1,40}` **and replaced by server aliases** before the model sees anything. The prompt is still scanned by the engine | `routes.test.ts` "injection text has no field"; `unit.test.ts` |
| DP-T5 | Uploading logs, contacts, SMS, notifications, app inventories | Not representable in the schema; rejected as `invalid_request` without echoing the value | `v1.test.ts` "no field that accepts free text" |
| DP-T6 | Model fabricates evidence or cites data it was not given | Each finding must cite ≥ 1 alias that was sent; any unknown alias rejects the whole reply | `routes.test.ts` "rejects malformed, fabricated or unapproved model output" |
| DP-T7 | Model recommends something harmful (factory reset, phishing link, "install this booster") | Actions are ids from an approved, non-destructive list per diagnostic type; text with links, web addresses, markdown or HTML is rejected; disclaimers are server-chosen. The provider's JSON mode is requested, but the reply is validated regardless | same; `unit.test.ts` disclaimers |
| DP-T8 | Model output leaks secrets or personal data | Output is scanned by the engine: BLOCK/QUARANTINE withholds it, MASK sanitizes it. A masked email keeps its domain and is then rejected by the no-web-address rule | `routes.test.ts`; e2e with the real engine (credential blocked, email never returned) |
| DP-T9 | Security engine or policy store down → unscreened data reaches a model | Fail closed: `security_unavailable`, the model is not called | `routes.test.ts`; e2e "FAILS CLOSED when the engine dies" |
| DP-T10 | Data silently routed to a different provider | One operator-configured provider. Unknown or org-disabled provider = `remote_analysis_unavailable`; the router has no fallback | `routes.test.ts` "no fallback" |
| DP-T11 | Provider hangs | Deadline on the model call (`DEVICEPULSE_TIMEOUT_MS`), `504 model_timeout` | `routes.test.ts` timeout test |
| DP-T12 | Audit trail cannot be written | Input audit failure stops the request before the model call; a request-record failure withholds the result | `routes.test.ts` "audit store down", "request record cannot be written" |
| DP-T13 | Cross-tenant access to records or feedback | PostgreSQL RLS on both tables; composite foreign key ties feedback to the same organization; repository also scopes by actor | `tests/db/devicePulse.test.ts` (PGlite locally, real PostgreSQL 18 in CI) |
| DP-T14 | Request-id enumeration via feedback | Ids are random UUIDs; an id owned by someone else gives exactly the same 404 as a random one | `routes.test.ts` "cannot rate or even detect" |
| DP-T15 | Cost abuse / denial of wallet | Per-IP limit (gateway-wide) and per-credential limit on explain; body limit 16 KB; ≤ 40 observations | `routes.test.ts` "rate limits" |
| DP-T16 | Consent bypass | Consent is checked before anything else, required as literal `true` by the schema, and re-checked in the service before any remote call; version and age enforced | `v1.test.ts`, `routes.test.ts` "defence in depth" |
| DP-T17 | Telemetry in logs | Bodies are never logged; failures log reason codes only; provider messages are not returned | `routes.test.ts` "never leaking provider messages" |
| DP-T18 | Interception in transit | TLS required in production (see `android-api-integration.md`); HSTS on production responses | Configuration; not testable in this repository |

## Residual risks (not solved, stated plainly)

1. **Detection is imperfect.** The engine misses many prompt-injection and some PII patterns (see
   `docs/verification/08-independent-evaluation.md`, `12-ai-vs-ai.md`). DevicePulse's main injection defence is
   structural (no free text, aliases), not detection.
2. **The model can still be wrong.** A validated reply is well-formed and cites real evidence; it is not necessarily a
   correct diagnosis. `confidence` is self-reported and uncalibrated. This is why every response carries
   `model_generated_explanation` and `ai_generated_content`.
3. **Language is not verified.** Nothing checks that the reply is in the requested locale.
4. **Rate limits are per gateway process.** With N replicas the effective limit is N times higher (no shared store yet).
5. **Telemetry can be forged by a modified app.** Bounds checks catch impossible values, not plausible lies. The impact is
   limited to the attacker's own explanation and spend, which the per-credential limit caps.
6. **Masked personal data causes a discarded reply** rather than a cleaned one when the masked form contains a domain.
   Safe, but the user sees a failure.
7. **Per-installation API keys** (if used instead of user login) cannot be bound to a device; treat them as revocable,
   low-privilege secrets and rotate on reinstall.
