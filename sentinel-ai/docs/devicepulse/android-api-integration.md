# DevicePulse — Android integration guide

For the Android (Kotlin) client. Contract details are in `api-contracts.md`; example payloads that are validated in CI are in
`packages/devicepulse-contracts/examples/v1/`.

## 1. What the app must do without the backend

Local diagnostics are the product; the backend only adds an explanation. The app must:

- collect metrics and run its own rules (producing local findings) with no network access;
- show local results when the backend is unreachable, returns any error, or consent is not given;
- call the backend only after the user has opted in to cloud analysis.

`GET /v1/devicepulse/health` tells the app whether to offer "Explain with AI" at all.

## 2. Base URL configuration

Never hardcode a host or IP in source. Inject the base URL per build type or flavor, for example from a Gradle property:

```kotlin
// app/build.gradle.kts (build configuration, not UI)
android {
    buildFeatures { buildConfig = true }
    buildTypes {
        debug   { buildConfigField("String", "DEVICEPULSE_BASE_URL", "\"${project.findProperty("devicepulse.debugBaseUrl") ?: "http://10.0.2.2:4000"}\"") }
        release { buildConfigField("String", "DEVICEPULSE_BASE_URL", "\"${project.findProperty("devicepulse.releaseBaseUrl")}\"") }
    }
}
```

Put the per-developer value in `~/.gradle/gradle.properties` or `local.properties` (not committed). Release builds must
fail the build if the release URL is missing or not `https://`.

| Environment | Base URL | Notes |
|---|---|---|
| Android emulator → gateway on the same computer | `http://10.0.2.2:4000` | `10.0.2.2` is the emulator's alias for the host's loopback. The compose stack publishes the gateway on `127.0.0.1:4000`, which this reaches. |
| Physical device over USB | `http://127.0.0.1:4000` after `adb reverse tcp:4000 tcp:4000` | Recommended: no firewall or LAN exposure. Re-run `adb reverse` after reconnecting. |
| Physical device over Wi-Fi | `http://<computer's LAN IP>:4000` | Only works if the gateway listens on the LAN interface. The compose file binds to `127.0.0.1` on purpose; prefer `adb reverse`. |
| Staging / production | `https://<your API host>` | HTTPS only. The gateway speaks plain HTTP on port 4000 and must sit behind a TLS-terminating proxy or ingress. |

This repository's stack usually runs inside WSL2. Windows forwards `localhost` ports to WSL, so the emulator path above
works, but Windows → WSL forwarding has been measured as unreliable on this machine (`docs/release/current-status.md`).
If requests time out intermittently, retry or run the stack natively.

## 3. TLS requirements

- Production and staging: `https://` only, TLS 1.2 or newer, a publicly trusted certificate. Do not add user-installed CAs
  to the release trust store.
- Android 9+ blocks cleartext HTTP by default. Allow cleartext **only in debug builds and only for `10.0.2.2` and
  `127.0.0.1`**, through a debug-only network security configuration. Release builds must not permit cleartext.
- Certificate pinning is optional. If you pin, pin the public key of the issuing CA or your own intermediate, ship a backup
  pin, and plan rotation; a wrong pin bricks the feature for every installed app.
- The gateway sends `Strict-Transport-Security` in production and `Cache-Control: no-store` on every response.

## 4. Authentication

No secret ships in the APK: no provider key, no gateway key, no database credential, no internal token.

**Recommended: per-user login.**

1. An administrator of the DevicePulse organization invites the user with the least-privilege role:
   `POST /v1/invitations {"email": "...", "role": "DEVICE_CLIENT"}` (ADMIN or OWNER credential, server side).
2. The user accepts once: `POST /v1/invitations/accept {"token": "sni_…", "password": "…"}`.
3. The app logs in: `POST /v1/auth/login {"email": "...", "password": "..."}` returns
   `{"access_token", "refresh_token", "token_type": "Bearer", "expires_in": 900, "user": {...}}`.
4. Send `Authorization: Bearer <access_token>` on every DevicePulse call.
5. On 401, call `POST /v1/auth/refresh {"refresh_token": "snr_…"}` **once**; it returns a new pair and invalidates the old
   refresh token (rotation). If refresh also fails, ask the user to sign in again.
6. On sign-out, `POST /v1/auth/logout {"refresh_token": "…"}`, then delete local tokens.

Production deployments run with `SIGNUP_ENABLED=false` (the production default). Self-service signup creates a new
organization whose first user is OWNER, which is not a suitable path for app users.

**Alternative: per-installation API key** with role `DEVICE_CLIENT`, issued by your own backend after the user signs in to
your service, sent as `Authorization: Bearer snl_…`. Never embed one key in the APK for all users.

Token storage: keep tokens only in app-private storage encrypted with a key from the Android Keystore, exclude that
storage from cloud backup and device-to-device transfer, never log them, and keep the access token in memory where
possible.

## 5. Calls

### Health (no auth)

```
GET /v1/devicepulse/health
200 {"status":"ok","service":"devicepulse","supported_schema_versions":["1.0"],"remote_analysis":"available"}
```

### Capabilities (once per session, cache it)

```
GET /v1/devicepulse/capabilities
Authorization: Bearer <access_token>
```

Use it to build requests: the accepted metrics and units per diagnostic type, the local finding codes, approved action ids,
the accepted consent versions and the limits. If `remote_analysis.available` is false, hide the AI option.

### Explain

```
POST /v1/devicepulse/diagnostics/explain
Authorization: Bearer <access_token>
Content-Type: application/json
```

Body (abridged; full example in `examples/v1/explain-request.battery_drain.json`):

```json
{
  "schema_version": "1.0",
  "diagnostic_type": "battery_drain",
  "locale": "en-US",
  "consent": { "cloud_analysis": true, "consent_version": "2026-10-01", "granted_at": "2026-10-02T08:15:00Z" },
  "client": { "app_version": "1.4.0", "android_api_level": 34 },
  "observations": [
    { "evidence_id": "ev_drain", "metric": "battery_drain_rate", "value": 14.5, "unit": "percent_per_hour", "observed_at": "2026-10-14T09:00:00Z" }
  ],
  "local_findings": [
    { "finding_id": "lf_drain", "code": "high_drain_rate", "severity": "high", "evidence_ids": ["ev_drain"] }
  ]
}
```

Rules that most often cause 422s:

- Send each metric in its catalog unit (sizes in **megabytes**, temperatures in °C, signal in dBm). The server does not convert.
- `observed_at` must carry an offset (`Z` or `+05:30`) and be within the last 168 hours; the device clock may be at most 5
  minutes ahead.
- Every `evidence_ids` entry of a local finding must be the `evidence_id` of an observation in the same request.
- Ids: 1–40 characters of `A-Z a-z 0-9 _ -`. Use short opaque ids; they never leave the server anyway.
- `locale` must be one of the supported tags; map the device locale to the closest one, defaulting to `en-US`.

Response (abridged; full example in `examples/v1/explain-response.battery_drain.json`):

```json
{
  "schema_version": "1.0", "request_id": "6f1c2a7e-…", "status": "completed",
  "summary": "Your battery is draining about three times faster than typical…",
  "findings": [{ "finding_id": "f1", "title": "…", "explanation": "…", "severity": "high", "confidence": 0.72,
                 "evidence_ids": ["ev_wake", "ev_drain"], "related_local_finding_ids": ["lf_wake", "lf_drain"] }],
  "confidence": { "overall": 0.66, "level": "medium" },
  "limitations": ["model_generated_explanation", "model_confidence_uncalibrated", "no_historical_baseline"],
  "recommended_action_ids": ["review_background_usage", "enable_battery_saver"],
  "disclaimer_codes": ["ai_generated_content", "not_professional_repair_advice"],
  "processing_mode": "remote_ai", "generated_at": "2026-10-14T09:31:02.114Z"
}
```

Rendering rules:

- Show `summary`, `title` and `explanation` as **plain text** (no HTML, no Markdown, no auto-linking).
- Link each finding to your own evidence through `evidence_ids`; they are your ids.
- Map `recommended_action_ids` to your own localized strings and, where relevant, to system settings screens. Ignore ids
  you do not know (a newer server may add some).
- Map every `disclaimer_codes` entry to visible text. `battery_safety_warning` should be prominent.
- Treat `confidence` as a hint. Do not present it as a probability.

### Feedback (optional, separate consent)

```
POST /v1/devicepulse/diagnostics/feedback
{"schema_version":"1.0","request_id":"<from explain>","rating":"not_helpful","reason_code":"too_generic","consent_to_store":true}
201 {"schema_version":"1.0","request_id":"…","status":"recorded"}
```

### Delete my data (on consent withdrawal or sign-out with "remove my data")

```
DELETE /v1/devicepulse/data
200 {"schema_version":"1.0","deleted":{"requests":3,"feedback":1}}
```

## 6. Timeouts and retries

The server bounds its own work: each security scan has a budget of a few seconds, the model call has
`limits.request_timeout_ms` from `/capabilities` (default 20 s), and an explain request makes up to four scans plus one
model call. Recommended client settings for explain:

| Setting | Value |
|---|---|
| Connect timeout | 10 s |
| Read / call timeout for explain | 60 s |
| Read timeout for health, capabilities, feedback, delete | 15 s |

Measured on this repository's development machine with local models through Ollama: 2–5 s per explanation with
qwen2.5:1.5b, 9–31 s with nemotron-mini (4.2B). With a local model, the operator should raise `DEVICEPULSE_TIMEOUT_MS`
(the 20 s default cut-off is meant for hosted APIs) and the app should show progress.

Retry only when the error body says `"retryable": true` (or on a network error before any response), at most twice, with
exponential backoff starting at the `Retry-After` header value (or 2 s). Never retry 4xx errors other than 429. Always fall
back to the local result.

## 7. Error handling in the app

| `error` | What the app should do |
|---|---|
| `unauthorized` | Refresh the token once; otherwise sign in again |
| `forbidden` | The account lacks the DevicePulse role: show local results, report a configuration problem |
| `consent_required`, `consent_outdated`, `consent_expired` | Show the consent screen (current text version), then retry |
| `invalid_*`, `insufficient_evidence`, `unsupported_*`, `invalid_request` | Client bug: log `issues[].path` (never values), show local results |
| `payload_too_large` | Send fewer observations (≤ 40) |
| `rate_limited` | Wait `Retry-After`; show local results meanwhile |
| `remote_analysis_unavailable` | Hide the AI option for this session |
| `security_unavailable`, `audit_unavailable`, `auth_unavailable`, `model_timeout` | Retryable: back off, keep local results visible |
| `model_unavailable` | Retry only if `retryable` |
| `model_response_invalid`, `blocked_by_security_policy` | Show "AI explanation unavailable" with local results; do not retry automatically |
| `unknown_request`, `feedback_exists` | Feedback only: ignore |

## 8. Trying it against a local stack

The base URL below is the compose default seen from the host; from the emulator use `10.0.2.2` instead of `127.0.0.1`.

```bash
# 1. Enable remote analysis with the local model (in sentinel-ai/.env), then restart the api container:
#    OLLAMA_BASE_URL=http://host.docker.internal:11434  OLLAMA_MODEL=<installed model>  DEVICEPULSE_AI_PROVIDER=ollama
# 2. As an ADMIN, create a DEVICE_CLIENT key for testing (shown once):
curl -s -X POST http://127.0.0.1:4000/v1/api-keys -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "content-type: application/json" -d '{"name":"android-dev","role":"DEVICE_CLIENT"}'
# 3. Call the API with it:
curl -s http://127.0.0.1:4000/v1/devicepulse/capabilities -H "Authorization: Bearer $DEVICE_KEY"
curl -s -X POST http://127.0.0.1:4000/v1/devicepulse/diagnostics/explain -H "Authorization: Bearer $DEVICE_KEY" \
     -H "content-type: application/json" --data @packages/devicepulse-contracts/examples/v1/explain-request.battery_drain.json
```

The example request's timestamps are fixed, so the last call answers `invalid_observation` (older than 168 hours) unless
you update `observed_at` and `granted_at` to recent times first.
