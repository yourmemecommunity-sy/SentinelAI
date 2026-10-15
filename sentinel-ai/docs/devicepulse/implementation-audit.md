# DevicePulse backend — implementation audit (Phase 1)

Date: 2026-10-14. Scope: the SentinelAI repository as it exists on disk, inspected **before** any DevicePulse change.
Statements below come from reading the code and running the tests, not from the README.

## 1. Repository and Git state

| Item | Observed |
|---|---|
| Git root | `googleAi/` (one level above `sentinel-ai/`) |
| Branch | `main`, last commit `e0b10fd` (stream revocation tests/docs) |
| Uncommitted changes | One untracked, empty file `googleAi/veylora`. Not created by this work; left untouched. |
| Local-only files | `sentinel-ai/.env` (git-ignored; the owner's live deployment configuration). Left untouched. |
| Package manager | pnpm 9.12.0 (pinned by `packageManager`), reachable on this machine only via `corepack pnpm` |
| Workspace packages | `apps/api`, `apps/dashboard`, `services/ai-router`, `packages/shared-types`, `packages/security-rules`, `packages/sdk/javascript` |

## 2. What exists, component by component

| Component | Where | What the code actually does | Reuse for DevicePulse |
|---|---|---|---|
| HTTP gateway | `apps/api` (Fastify 5, Zod) | `buildApp(deps)` with injected dependencies; security headers, allow-list CORS, per-IP fixed-window rate limit (in-process), error handler that never echoes input | **Reuse**: new routes register on the same app |
| Authentication | `apps/api/src/security/{apiKeys,tokens,authenticators}.ts` | API keys (`snl_…`, peppered hash, DB lookup) and JWT access tokens; JWTs are re-checked against the user's current state on every request (disabled user → refused immediately); 503 `auth_unavailable` when the credential store is down | **Reuse** unchanged |
| Authorization | `packages/shared-types/src/rbac.ts` | Static role → permission table; roles seeded in SQL and asserted equal by a test | **Extend**: one new permission and one least-privilege role |
| Tenant isolation | `apps/api/src/db/tenantDb.ts`, migrations | PostgreSQL row-level security on every tenant table (`app.org_id` set per transaction); the gateway refuses to start in production on a role that bypasses RLS | **Reuse** for the new tables |
| Security engine | `services/security-engine` (Python/FastAPI) | Rules + NER + local classifier (+ optional LLM judge) detection, policy evaluation, sanitization, explanation; 208 tests | **Reuse** via the gateway's `HttpSecurityClient` (fails closed on timeout, HTTP error, malformed response, invariant violation) |
| Policy enforcement | `services/security-engine/app/policies` + `apps/api/src/repositories/policyRepository.ts` | Per-organization versioned policies, evaluated **inside the engine** on every scan | **Reuse** (automatically applied by the scan) |
| `services/policy-engine` | Python skeleton | **Not implemented.** `/ready` deliberately returns 503. Its own README says evaluation lives in the security engine (ADR-0003). | **Not used.** DevicePulse must not depend on it. |
| Secure AI pipeline | `apps/api/src/services/secureAiService.ts` | Per-org provider resolution → unknown provider = fail-closed block → org policy fetch (failure = fail closed) → input scan of every message (+ joined) → audit event (failure = 503) → provider call → output scan → audit | **Reuse** `chat()` as the only path to a model |
| AI router | `services/ai-router` | Gemini, OpenAI, Anthropic, Ollama adapters; typed `ProviderError` (`timeout`, `invalid_response`…); **no automatic cross-provider fallback** by design | **Reuse**; DevicePulse names one provider in operator config |
| Per-org provider control | `apps/api/src/providers/orgRouters.ts` | Org may disable a provider or bring its own key; undecryptable key = fail closed, never falls back to the platform key | **Reuse** (a disabled provider makes remote analysis unavailable for that org) |
| Audit | `security_events` (metadata only, no content), `audit_logs` (structural metadata) | Both written through RLS; event write failure is treated as fail-closed | **Reuse** |
| Redis | `services/token-vault` only | The gateway itself does not use Redis. The rate limiter is per process. | Not needed; the per-process limitation is documented |
| Migrations | `scripts/database/migrations/0001…0009` | Checksummed, advisory-locked runner; tests apply them to PGlite and (CI) real PostgreSQL 18 | **Extend** with `0010_devicepulse.sql` |
| Docker | `docker-compose.yml`, `apps/api/Dockerfile` | API image copies each workspace package explicitly | **Extend**: copy the contracts package; pass DevicePulse env |
| CI | `googleAi/.github/workflows/ci.yml` | 9 jobs; `gateway` runs `pnpm build` + `pnpm test` (all workspace packages) + DB suites on real PostgreSQL 18 | **Extend** implicitly: a new workspace package's tests run under `pnpm test` |

### Existing `POST /v1/security/scan`

Takes `{text, direction, context}` and returns the engine's decision, detections and sanitized text. It is a generic
DLP scan. It does **not** produce device-diagnostic explanations, and its contract is left unchanged.

### Equivalent DevicePulse functionality

None. No route, schema, table or document mentions DevicePulse or device diagnostics.

## 3. Test baseline (before any change)

Run on the Windows host on 2026-10-14.

| Suite | Command | Result |
|---|---|---|
| Gateway (unit, security, streaming, DB on PGlite, e2e against the **real** Python engine via the local `.venv`) | `apps/api: vitest run` | **31 files, 492 passed, 0 failed** |
| Gateway typecheck | `apps/api: tsc -p tsconfig.test.json` | clean |
| AI router (incl. one test against a **real** local Ollama) | `services/ai-router: vitest run` | **2 files, 61 passed** |
| Security engine | `services/security-engine: .venv python -m pytest -q` | **208 passed** |
| Structure validator | `node scripts/development/validate-structure.mjs` | **Fails locally, 2 violations, both caused by the git-ignored `.env`** (a pre-existing local condition; CI checks out without it) |

Not run in the baseline: dashboard, SDKs, document scanner, token vault, the real-PostgreSQL DB suites (they need a
PostgreSQL server; CI runs them), Docker/`act`.

## 4. Gaps and risks found that shape the design

1. **No credential suitable for a mobile app.** Every existing role that may call a model (`ai:use`) can also do much
   more (`DEVELOPER` has `keys:manage`). A shipped APK is extractable, so no static key may be embedded. The Android
   app must use per-user short-lived JWTs (existing `/v1/auth/login` + refresh rotation) or a per-installation API key
   provisioned out of band, and the credential needs a role that can do nothing except DevicePulse.
2. **`services/policy-engine` is a skeleton.** Treating it as a dependency would make the feature permanently
   unavailable; policy enforcement happens in the security engine, which DevicePulse already goes through.
3. **Rate limiting is per IP and per process.** Model calls cost money, so DevicePulse needs a per-principal limit too.
   Both remain per process (multi-replica deployments multiply the limit; documented, not solved).
4. **Free text is the main injection channel.** The engine's prompt-injection detection is imperfect: the rules layer
   detected 1.7 % (deepset) and 39.6 % (jackhhao) of public attack sets (`docs/verification/08-independent-evaluation.md`);
   the v2 cascade improves on that but is not perfect either (`docs/verification/12-ai-vs-ai.md`).
   The DevicePulse request therefore carries **no free text at all**: only enums, bounded numbers and opaque IDs, and
   the IDs are replaced by server-generated aliases before anything reaches a model.
5. **Numbers can look like PII.** Long digit strings (e.g. raw byte counts) can match card or phone detectors and
   cause a BLOCK. Metrics are expressed in units that keep values short (MB, not bytes).
6. **Retention.** `organizations.audit_retention_days` exists but nothing in the repository enforces it. DevicePulse
   tables get their own expiry and purge.
