# DevicePulse privacy data map

What DevicePulse collects, where each item goes, how long it is kept and how it is deleted. "Model" means the one AI
provider the operator configured with `DEVICEPULSE_AI_PROVIDER`.

## Principles

- **Local first.** The Android app runs its own diagnostics; the backend only adds an explanation, and only with consent.
  Everything works locally when the backend is unreachable or consent is not given.
- **No free text.** The request schema accepts enums, bounded numbers and short opaque ids, nothing else.
- **Minimize before sending.** Client ids, absolute timestamps, consent details and the app version never reach the model.
- **Store metadata, not telemetry.** No observation value, no model text is written to the database.

## Never collected

Rejected by the schema (there is no field for them): device logs (logcat), contacts, SMS/MMS, call logs, notification
contents, installed-app lists or app names, location, IMEI/serial/advertising id, account names, file names, free-text
notes. The app should not collect them for DevicePulse either.

## Per data element

| Data | Sent by app | Sent to model | Stored by backend | Where | Retention | Deletion |
|---|---|---|---|---|---|---|
| Credential (JWT / API key) | Header | No | API key: HMAC only; JWT: not stored (refresh token hashed) | `api_keys`, `refresh_tokens` | Until revoked/expired | Revocation; account removal by an admin |
| `diagnostic_type`, `locale` | Yes | Type: yes; locale: as a language name | Type: yes | `devicepulse_requests` | `DEVICEPULSE_RETENTION_DAYS` (default 30) | Purge, or `DELETE /v1/devicepulse/data` |
| Consent block | Yes | **No** | No (checked, not stored) | — | — | — |
| `client.app_version` | Yes | **No** | No | — | — | — |
| `client.android_api_level` | Yes | Yes | No | — | — | — |
| Observation metric, value, unit | Yes | Yes (value rounded to 3 decimals) | **No** | — | Not stored | — |
| `observed_at` | Yes | Only as age in minutes | No | — | — | — |
| Client `evidence_id`, `finding_id` | Yes | **No** (replaced by E1/L1 aliases) | No | — | — | — |
| Local finding code, severity | Yes | Yes | No | — | — | — |
| Model reply text | — | (produced by model) | **No** | Returned to the app only | — | — |
| Request record: request id, organization, actor (user id or key id), type, status, finding count, input event id, timestamps | — | — | Yes | `devicepulse_requests` | 30 days default | Purge hourly; erasure endpoint |
| Feedback: rating, reason code | Yes, with `consent_to_store` | No | Yes | `devicepulse_feedback` | Same as its request | Cascades with the request |
| Security events: request id, user/key id, application `devicepulse`, provider, model, decision, risk, entity **types**, detector names/scores/versions, keyed HMAC of the scanned text | — | — | Yes | `security_events` | Organization audit policy (see gap below) | Not user-deletable (security audit) |
| Per-detection offsets and digests | — | — | Only when the organization has `zero_retention = false` (default is true: not stored) | `scan_results` | As above | As above |
| Daily counters per provider | — | — | Yes (counts only) | `usage` | As above | As above |
| Erasure record (counts only) | — | — | Yes | `audit_logs` (`devicepulse.data_deleted`) | As above | Not user-deletable |
| Client IP | Connection | No | Used for rate limiting in memory; passed to the engine as scan context | Process memory | Rate-limit window (1 min) | Automatic |
| Application logs | — | — | Reason codes, request ids; never bodies, never provider messages | stdout | Operator's log retention | Operator |

## Third parties

The configured model provider receives the minimized prompt described above for every explain request. Its retention and
training policy is the provider's (Gemini, OpenAI, Anthropic) or the operator's own (Ollama, self-hosted). The privacy
notice shown in the app must name the provider the operator configured. If the operator configures none, nothing is sent
anywhere.

The security engine is part of the same deployment. It may call an external LLM judge (Anthropic) on already-sanitized
text when the organization has `external_judge` enabled; organizations can switch this off
(`PUT /v1/organization/ai-judge`).

## Consent

- `consent.cloud_analysis: true` is required for every explain call; the app must only send it after an explicit opt-in.
- `consent_version` identifies the consent text. The operator lists accepted versions in `DEVICEPULSE_CONSENT_VERSIONS`;
  removing a version forces users to re-consent (403 `consent_outdated`).
- Consent older than 395 days is refused (403 `consent_expired`).
- Withdrawal: the app stops sending explain requests and calls `DELETE /v1/devicepulse/data`.
- Feedback needs its own `consent_to_store: true`.

## Retention and deletion

- `devicepulse_requests` and `devicepulse_feedback`: deleted when `expires_at` passes (hourly purge in the gateway,
  `app_purge_devicepulse()`), or immediately via `DELETE /v1/devicepulse/data` for the calling user/key. Expired records
  are also invisible to the feedback endpoint before the purge runs.
- **Known gap:** `organizations.audit_retention_days` exists in the schema, but no job in this repository deletes old
  `security_events`, `audit_logs` or `usage` rows. Operators must schedule that themselves until it is implemented.

## Tenant isolation

Both DevicePulse tables use the same PostgreSQL row-level security as the rest of SentinelAI (`organization_id =
app_org_id()`), are written through the RLS-restricted application role, and feedback is tied to its request's
organization by a composite foreign key. Tested in `apps/api/tests/db/devicePulse.test.ts`.
