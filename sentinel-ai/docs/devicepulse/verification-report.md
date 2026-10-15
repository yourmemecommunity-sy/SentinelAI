# DevicePulse backend — verification report

Date: 2026-10-14. Machine: Windows 11 host (Node 24), WSL2 with Docker Engine 29.1.3. Every number below comes from a run
made on that date; nothing was carried over from documentation. Baseline numbers are in `implementation-audit.md` §3.

Status vocabulary as in `docs/release/current-status.md`: **VERIFIED** (against the real dependency), **MOCK-VERIFIED**
(against a double), **NOT VERIFIED**, **BLOCKED**.

## Test suites

| Suite | Ran against | Before | After |
|---|---|---|---|
| Gateway, all files (`apps/api: vitest run`) | PGlite, fakes, and the **real** Python engine for e2e files | 31 files, 492 passed | 35 files, 561 passed, 0 failed |
| of which DevicePulse routes + unit (`tests/devicepulse`) | fakes | — | 47 passed |
| of which DevicePulse DB (`tests/db/devicePulse.test.ts`) | PGlite | — | 10 passed |
| of which DevicePulse e2e (`tests/e2e/devicePulseEngine.e2e.test.ts`) | **real** security engine, PGlite, real API-key auth, model double | — | 12 passed |
| All DB suites on **real PostgreSQL 18.6** (`SENTINEL_TEST_DATABASE_URL`, throwaway container) | real server | not run in baseline | 10 files, 148 passed (a deliberately wrong password made the same file fail, proving the server was used) |
| Contracts package (`packages/devicepulse-contracts`) | — | — | 29 passed; typecheck and build clean |
| AI router (`services/ai-router`) | mocks + one **real** local Ollama test | 61 passed | 63 passed (2 new JSON-mode wire-format tests) |
| Dashboard (`apps/dashboard`) | jsdom | not run in baseline | 72 passed; typecheck clean (one assertion updated: ADMIN can now grant `DEVICE_CLIENT`) |
| Python security + regression tests (`tests/security tests/regression`) | engine venv | not run in baseline | 25 passed (the OpenAPI contract test first failed on the five undocumented routes; fixed by documenting them) |
| Security engine (`services/security-engine`) | — | 208 passed | unchanged code, not re-run |
| Gateway typecheck | — | clean | clean |
| Structure validator | — | 2 violations (local `.env`) | the same 2, nothing new |

Two existing assertions were changed on purpose and are listed here so they can be reviewed: the role count in
`tests/db/repositories.test.ts` (5 → 6) and the ADMIN grantable list in `apps/dashboard/tests/ui.test.tsx`.

Mutation checks: disabling the fabricated-evidence check and, separately, the consent pre-check each made the suite fail.
The consent mutation showed that the post-parse schema still accepted `cloud_analysis: false`; consent is now enforced in
three places (pre-check, schema literal `true`, service guard).

## Container image

**VERIFIED.** `apps/api/Dockerfile` built from a clean copy (no `node_modules`, `dist`, `.env`) under a separate tag
(`sentinel-ai/api:devicepulse-check`, so the image the running stack uses was not replaced). In the image: the contracts
package resolves as a production dependency, the DevicePulse routes module loads, and `0010_devicepulse.sql` is present.
The full compose stack was **not** restarted with the new image, and `docker-verify.sh` was **not** run.

## Helm

**Rendered** with `helm template` (Helm in WSL): with `api.devicepulse.provider=ollama` the API Deployment gets
`DEVICEPULSE_AI_PROVIDER` plus the four tuning variables; with defaults the provider variable is absent (remote analysis
off). Not installed on a cluster in this run.

## Real model (local Ollama) through the real security engine

`apps/api/dev/devicepulseLiveCheck.ts`: one realistic request per diagnostic type, real engine, real model, in-memory stores.

| Model | Change | Valid explanations | Rejections (reason) | Latency |
|---|---|---|---|---|
| qwen2.5:1.5b | prompt only | 2/12 | 10 (prose instead of JSON, schema) | 1–21 s |
| qwen2.5:1.5b | + native JSON mode | 8/12 | 4 (schema ×3, not JSON ×1) | 2–19 s |
| qwen2.5:1.5b | + approved-action list trimmed to 6 | 14/18 | 4 (schema ×3, **fabricated evidence ×1**) | 1–5 s |
| nemotron-mini 4.2B | final code | 9/12 | 3 (schema ×2, **fabricated evidence ×1**) | 9–31 s |

Every accepted reply matched the response contract. Two real fabricated-evidence replies were caught and discarded.
Observed quality issue: the 1.5B model often recommends every approved action. Validity is not correctness: these runs
check structure and evidence binding, not whether the explanation is right.

## Not verified / blocked

| Item | Status | Why |
|---|---|---|
| Gemini, OpenAI, Anthropic as the DevicePulse provider | **BLOCKED** | No API keys on this machine. JSON-mode request fields are MOCK-VERIFIED (wire-format tests) only |
| CI on GitHub-hosted runners | **NOT VERIFIED** | Nothing was pushed. The new tests run in the existing `gateway` job (`pnpm test`, the real-PostgreSQL DB step, e2e with the engine) without CI changes |
| Full compose stack with DevicePulse enabled, `docker-verify.sh` | **NOT VERIFIED** | Would replace the image of the owner's running deployment |
| Android client | Out of scope | Built separately in Android Studio |
| Multi-replica rate limiting | Known limitation | Limits are per process |
