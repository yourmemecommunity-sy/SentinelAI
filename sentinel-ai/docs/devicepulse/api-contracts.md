# DevicePulse API contracts (schema version 1.0)

The machine-readable source of truth is `packages/devicepulse-contracts` (Zod schemas, catalog, validator). The JSON files
in `packages/devicepulse-contracts/examples/v1/` are tested against those schemas on every CI run, so they are safe to
copy into Android unit tests. `GET /v1/devicepulse/capabilities` returns the full catalog at runtime.

All bodies are JSON (`content-type: application/json`), field names are `snake_case`, timestamps are RFC 3339 **with an
offset** (`2026-10-14T09:00:00Z` or `…+05:30`).

## Endpoints

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /v1/devicepulse/health` | none | Is the service up, and is remote analysis available at all |
| `GET /v1/devicepulse/capabilities` | `devicepulse:use` | Catalog, limits, accepted consent versions, availability for the caller's organization |
| `POST /v1/devicepulse/diagnostics/explain` | `devicepulse:use` | AI explanation of locally collected diagnostics |
| `POST /v1/devicepulse/diagnostics/feedback` | `devicepulse:use` | Optional rating of one explanation (enum only) |
| `DELETE /v1/devicepulse/data` | `devicepulse:use` | Erase everything DevicePulse stored for the calling user or key |

The existing `POST /v1/security/scan` is unchanged and is **not** part of DevicePulse.

### Authentication and authorization

Send `Authorization: Bearer <credential>`. The credential is either a user access token from the existing
`/v1/auth/login` / `/v1/auth/refresh` flow (preferred for an app; 15-minute tokens, rotating refresh tokens) or a SentinelAI
API key provisioned for one installation. Either must carry the `DEVICE_CLIENT` role (only `devicepulse:use`) or `ADMIN`
/ `OWNER`. `DEVELOPER`, `SECURITY_ANALYST` and `VIEWER` are refused with 403. A revoked key, disabled user or expired token
is refused on its next request.

Why feedback and deletion exist: feedback is the only way to measure explanation quality, and it is reduced to a rating
and a reason code. Deletion is required because the server keeps a small record per explanation (needed to tie feedback
to it); a user who withdraws consent must be able to erase it.

## `GET /v1/devicepulse/health`

```json
{ "status": "ok", "service": "devicepulse", "supported_schema_versions": ["1.0"], "remote_analysis": "available" }
```

`status` is `degraded` and `remote_analysis` is `unavailable` when no DevicePulse model is configured or the security
engine is not ready. Always HTTP 200 while the gateway is up. It contains no organization data.

## `GET /v1/devicepulse/capabilities`

Returns `schema_version`, `supported_schema_versions`, `remote_analysis {available, reason}`, `consent {accepted_versions,
max_age_days}`, `limits`, `locales`, `diagnostic_types[] {id, metrics[] {id, unit, min, max, integer}, local_finding_codes,
action_ids}`, `limitation_codes`, `disclaimer_codes`, `error_codes`.

`remote_analysis.reason` is one of `not_configured`, `provider_disabled_for_organization`, `provider_config_unavailable`,
`security_engine_unavailable`, or `null` when available.

## `POST /v1/devicepulse/diagnostics/explain`

### Request

| Field | Type | Rules |
|---|---|---|
| `schema_version` | `"1.0"` | other values: `unsupported_schema_version` |
| `diagnostic_type` | enum | `battery_drain`, `thermal`, `storage`, `memory`, `network`, `performance`; other strings: `unsupported_diagnostic_type` |
| `locale` | enum | `en-US`, `en-GB`, `en-IN`, `hi-IN`, `es-ES`, `es-MX`, `fr-FR`, `de-DE`, `pt-BR` |
| `consent.cloud_analysis` | `true` | anything else: 403 `consent_required` (checked before the rest of the body) |
| `consent.consent_version` | `YYYY-MM-DD` | must be in the accepted list: else 403 `consent_outdated` |
| `consent.granted_at` | timestamp | not in the future (5 min skew); not older than 395 days: else 403 `consent_expired` |
| `client.app_version` | `MAJOR.MINOR.PATCH` | not sent to the model |
| `client.android_api_level` | integer 26–40 | |
| `observations[]` | 1–40 items | none: `insufficient_evidence` |
| `observations[].evidence_id` | `[A-Za-z0-9_-]{1,40}` | unique in the request; never shown to the model |
| `observations[].metric` | enum | must belong to the diagnostic type |
| `observations[].value` | finite number | within the metric's `min`/`max`; whole number where `integer` |
| `observations[].unit` | enum | must equal the metric's unit (no conversion is done) |
| `observations[].observed_at` | timestamp | not in the future (5 min skew), not older than 168 hours |
| `local_findings[]` | 0–20 items | |
| `local_findings[].finding_id` | `[A-Za-z0-9_-]{1,40}` | unique |
| `local_findings[].code` | enum | must belong to the diagnostic type |
| `local_findings[].severity` | `low`, `medium`, `high` | |
| `local_findings[].evidence_ids` | 1–10 ids | each must name an observation in the same request: else `invalid_evidence_reference` |

Unknown fields are rejected at every level. Maximum body size: 16,384 bytes (413 `payload_too_large`). There is no free-text
field anywhere: logs, contacts, SMS, notification contents and app inventories have nowhere to go.

Metrics, units and bounds (from the catalog):

| Metric | Unit | Range | Types |
|---|---|---|---|
| `battery_level` | percent | 0–100 | battery_drain, thermal |
| `battery_drain_rate` | percent_per_hour | 0–100 | battery_drain |
| `battery_temperature` | celsius | −20–80 | battery_drain, thermal |
| `battery_capacity_health` | percent | 0–150 | battery_drain |
| `charge_cycles` | count (integer) | 0–10,000 | battery_drain |
| `screen_on_time_24h`, `wakelock_time_24h` | minutes | 0–1440 | battery_drain |
| `cpu_temperature` | celsius | −20–130 | thermal |
| `skin_temperature` | celsius | −20–80 | thermal |
| `thermal_status` | level (integer) | 0–6 (Android `PowerManager.THERMAL_STATUS_*`) | thermal |
| `cpu_usage` | percent | 0–100 | battery_drain, thermal, performance |
| `storage_free`, `storage_total`, `cache_size_total` | megabytes | 0 (total: 1)–16,000,000 | storage |
| `storage_free_ratio` | percent | 0–100 | storage, performance |
| `ram_available`, `ram_total` | megabytes | 0 (total: 1)–262,144 | memory (ram_available also performance) |
| `low_memory_events_24h` | count (integer) | 0–10,000 | memory |
| `background_process_count` | count (integer) | 0–1000 | memory |
| `network_latency`, `dns_resolution_time` | milliseconds | 0–60,000 | network |
| `packet_loss` | percent | 0–100 | network |
| `wifi_signal` | dbm | −127–0 | network |
| `cellular_signal` | dbm | −140–−40 | network |
| `download_throughput`, `upload_throughput` | mbps | 0–10,000 | network |
| `app_cold_start_time` | milliseconds | 0–60,000 | performance |
| `frame_drop_ratio` | percent | 0–100 | performance |
| `anr_count_24h`, `crash_count_24h` | count (integer) | 0–10,000 | performance |
| `uptime` | hours | 0–8760 | memory, performance |

Sizes are megabytes on purpose: raw byte counts are long digit strings that can look like card or account numbers to the
security scanner and would get legitimate requests blocked.

Example: `packages/devicepulse-contracts/examples/v1/explain-request.battery_drain.json`.

### Response (200)

| Field | Meaning |
|---|---|
| `schema_version` | `"1.0"` |
| `request_id` | UUID; use it for feedback and support |
| `status` | `completed` or `insufficient_data` |
| `diagnostic_type`, `locale` | echoed from the request |
| `summary` | plain text, ≤ 600 characters, in the requested language |
| `findings[]` | ≤ 8: `finding_id` (`f1`…), `title` (≤ 120), `explanation` (≤ 600), `severity` (`info`/`low`/`medium`/`high`), `confidence` 0–1, `evidence_ids` (non-empty subset of YOUR observation ids), `related_local_finding_ids` (subset of YOUR finding ids) |
| `confidence` | `{overall: 0–1, level: low/medium/high}`; model-estimated and **uncalibrated**; `low` whenever status is `insufficient_data` |
| `limitations[]` | always starts with `model_generated_explanation`, `model_confidence_uncalibrated`; may add `limited_observation_window`, `no_historical_baseline`, `insufficient_observations`, `metrics_not_hardware_verified`, `manufacturer_customization_possible` |
| `recommended_action_ids[]` | ≤ 6, only from the diagnostic type's approved list (if the model lists more approved ids, its first 6 are kept; any unapproved id discards the whole reply) |
| `disclaimer_codes[]` | chosen by the server: always `ai_generated_content`, `not_professional_repair_advice`; plus `battery_safety_warning` (battery or skin ≥ 45 °C, CPU ≥ 90 °C, thermal status ≥ 3, or an overheating local finding) and `backup_before_deleting_data` (when `review_large_files` or `remove_unused_apps` is recommended) |
| `processing_mode` | `"remote_ai"` |
| `generated_at` | timestamp |

Example: `packages/devicepulse-contracts/examples/v1/explain-response.battery_drain.json`.

Text fields never contain links, web addresses, markdown or HTML: a model reply that does is discarded (502
`model_response_invalid`). Render them as plain text anyway (no `autoLink`, no HTML).

Approved actions per diagnostic type:

| Type | Action ids |
|---|---|
| battery_drain | open_battery_settings, enable_battery_saver, reduce_screen_brightness, shorten_screen_timeout, review_background_usage, check_for_system_update, contact_manufacturer_support |
| thermal | let_device_cool_down, remove_case_while_charging, avoid_heavy_use_while_charging, review_running_apps, check_for_system_update, contact_manufacturer_support |
| storage | open_storage_settings, clear_app_cache, review_large_files, remove_unused_apps |
| memory | restart_device, review_running_apps, remove_unused_apps, check_for_system_update |
| network | toggle_airplane_mode, forget_and_rejoin_wifi, move_closer_to_router, restart_router, open_network_settings, contact_carrier |
| performance | restart_device, check_for_system_update, clear_app_cache, open_storage_settings, review_running_apps, remove_unused_apps |

Nothing destructive is in the catalog (no factory reset, network reset or uninstalling a named app).

## `POST /v1/devicepulse/diagnostics/feedback`

```json
{ "schema_version": "1.0", "request_id": "<uuid from explain>", "rating": "helpful",
  "reason_code": "too_generic", "consent_to_store": true }
```

`rating`: `helpful` | `not_helpful`. `reason_code` (optional): `inaccurate`, `unclear`, `not_actionable`, `too_generic`,
`wrong_language`, `other`. `consent_to_store` must be `true` (403 `consent_required` otherwise). No free text.

201 → `{"schema_version":"1.0","request_id":"…","status":"recorded"}`. 404 `unknown_request` when the id does not exist
**for this credential** (another user's or organization's id gives the identical answer), or it expired. 409
`feedback_exists` on a second rating. Body limit 2,048 bytes.

## `DELETE /v1/devicepulse/data`

Deletes every DevicePulse request record of the calling user (or API key) in its organization, and their feedback.
Idempotent. 200 → `{"schema_version":"1.0","deleted":{"requests":3,"feedback":1}}`. Security audit events (which contain
no telemetry) are kept under the organization's audit policy; see `privacy-data-map.md`.

## Errors

Every error body has `error` (a code below). DevicePulse handlers add `message` (English, for logs, not for display),
`retryable`, `request_id` once one was assigned, and `issues[] {path, message}` for validation errors. Messages never echo
values the client sent. Gateway-wide errors may carry only `error`. Ignore unknown fields.

| HTTP | `error` | Retry? | Meaning |
|---|---|---|---|
| 400 | `bad_request` | no | Malformed JSON or wrong content type |
| 401 | `unauthorized` | no (re-authenticate) | Missing, invalid, revoked or expired credential |
| 403 | `forbidden` | no | Role lacks `devicepulse:use` |
| 403 | `consent_required` | no | `consent.cloud_analysis` is not `true` (or feedback without `consent_to_store`) |
| 403 | `consent_outdated` | no | Show the current consent text again |
| 403 | `consent_expired` | no | Ask the user to renew consent |
| 404 | `unknown_request` | no | Feedback for an id this credential does not own |
| 409 | `feedback_exists` | no | Already rated |
| 413 | `payload_too_large` | no | Body over the limit |
| 422 | `invalid_request` | no | Schema violation (unknown field, wrong type, bad timestamp format…) |
| 422 | `unsupported_schema_version`, `unsupported_diagnostic_type` | no | Upgrade or downgrade the client |
| 422 | `invalid_observation` | no | Metric/type mismatch, wrong unit, out of bounds, stale or future timestamp |
| 422 | `invalid_evidence_reference` | no | Duplicate evidence id, or a local finding cites an unknown one |
| 422 | `invalid_local_finding` | no | Finding code not valid for the type, duplicate finding id |
| 422 | `insufficient_evidence` | no | No observations |
| 422 | `blocked_by_security_policy` | no | The organization's security policy blocked the prompt or the model's reply |
| 429 | `rate_limited` | yes, after `Retry-After` | Per-IP or per-credential limit |
| 502 | `model_unavailable` | per `retryable` | Provider error (rate limit/outage: retryable; auth/config: not) |
| 502 | `model_response_invalid` | no | The model's reply failed validation and was discarded |
| 503 | `remote_analysis_unavailable` | no | No model configured, or the organization disabled it |
| 503 | `security_unavailable` | yes | Security engine or policy store unavailable: nothing was sent to any model |
| 503 | `audit_unavailable` | yes | The audit/data store is unavailable: the request was not completed |
| 503 | `auth_unavailable` | yes | The credential could not be verified right now |
| 504 | `model_timeout` | yes | The model did not answer within `request_timeout_ms` |
| 500 | `internal_error` | yes | Unexpected; carries `request_id` |

## Versioning

`schema_version` is `MAJOR.MINOR`. Additive changes (new optional response field, new enum value in a response) bump the
minor version and keep `v1`; clients must ignore unknown response fields. Anything that can make a valid v1 request invalid,
or change the meaning of a field, is a new `v2` directory in the contracts package, served side by side with v1 until
clients migrate. New diagnostic types, metrics or action ids are announced through `/capabilities` first.
