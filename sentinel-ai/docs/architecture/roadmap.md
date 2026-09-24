# Roadmap and Implementation Status

Updated after every phase. "Implemented" means code + tests exist and were **run**; nothing here is production-ready.

## Verification status — "written but never run" → "verified for real" (2026-09-26)

Evidence for each row is in [docs/verification/](../verification/); summary, blockers and maturity rating in [FINAL-REPORT.md](../verification/FINAL-REPORT.md). The phase tables below were written before this run; where
they say "never built / never run", this table is the current truth.

| Step | Status | Evidence |
|---|---|---|
| 1. Baseline: every existing suite | **Done** — 1,119 tests, 0 failed; 16 scanner tests need real ClamAV/Tesseract (run in step 5) | [01-baseline.md](../verification/01-baseline.md) |
| 2. Docker: all 7 Dockerfiles built, full stack healthy, `/ready`, scan, dashboard | **Done** — 81/81 container checks; `ollama` healthcheck added | [02-docker.md](../verification/02-docker.md) |
| 3. Real PostgreSQL 18.6: migrations 0001–0008 on a fresh DB, DB suites | **Done** — 130/130 incl. 40/40 tenant isolation | [03-postgresql.md](../verification/03-postgresql.md) |
| 4. Real Redis: vault suite, TTL eviction, circuit breaker on a frozen server | **Done** — 112/112 + live breaker/TTL 8/8 | [04-redis.md](../verification/04-redis.md) |
| 5. Real ClamAV 1.5.4 + Tesseract 5.5: EICAR blocked, screenshot email masked | **Done** — 133/133 scanner tests, live checks pass | [05-clamav-tesseract.md](../verification/05-clamav-tesseract.md) |
| 6. Real AI provider | **Cloud providers BLOCKED** (no Gemini/OpenAI/Anthropic key anywhere); adapters remain mock-verified. **Ollama VERIFIED**: 14 real-server tests + both SDKs through the Docker stack (10/10); a recording proxy proves masking before the model and zero requests for a blocked secret | [06-real-provider.md](../verification/06-real-provider.md) |
| 7. CI | **Done under `act`**: 8/8 jobs pass from the real repository root, `containers` steps run directly (Trivy 0 fixable HIGH/CRITICAL). Two defects fixed: the workflow sat where GitHub never reads it (moved to the repo root), and the OpenAPI contract tests were silently skipped in CI. **Not yet run on GitHub-hosted runners** (not pushed; the history must be squashed first — 79 gitleaks findings in commit `9ac9039`) | [07-ci.md](../verification/07-ci.md) |
| 8. Independent evaluation (public datasets, no tuning) | **Done** — test splits: deepset/prompt-injections **1.7 %** detection / 0 % FP; jackhhao/jailbreak-classification **39.6 %** detection / 0 % FP (threat). The self-authored suite overstates coverage | [08-independent-evaluation.md](../verification/08-independent-evaluation.md) |
| 9. Performance (k6, mocked instant provider) | **Done** — gateway adds p50 42 / p95 56 / p99 84 ms to a chat at 1 in flight; saturates at ≈44–68 chat req/s, ≈128 scan req/s on one laptop; 0 failed requests | [09-performance.md](../verification/09-performance.md) |
| 10. README for recruiters | **Done** — problem statement, Mermaid architecture, verified-for-real table, evaluation + benchmark numbers, one-command quick start, limitations | [README.md](../../README.md) |
| 11. Learning guide | **Done** — 8 design decisions (what / why / rejected alternative / what breaks / files / 3 interview Q&A each); states plainly that the multi-replica rate-limit fix is designed, not built | [LEARNING.md](../LEARNING.md) |

## Phase 0 - Architecture: **done**
Repo structure, structure validator (+ tests), architecture docs, Mermaid diagrams, ERD, OpenAPI, threat model, security model,
env template, Docker Compose foundation, test foundation.

## Phase 1 - Core MVP: **functionally complete; real-infrastructure verification remains**

| Item | Status |
|---|---|
| Security engine (detectors, policy, sanitization, risk, fail-closed pipeline, `/scan`, `/ready` canary) | Implemented + tested |
| Synthetic datasets (524 records) + evaluation gate | Implemented; 464/464 critical pass |
| PostgreSQL migrations (now `0001-0008`) + checksummed runner | Implemented; verified on PGlite **and on a real PostgreSQL 18.6 server** (see step 3 above) |
| Multi-tenancy: `organization_id` everywhere, RLS, composite FKs, append-only evidence tables | Implemented; 40 isolation tests + mutation-checked harness |
| Gateway: API-key auth (HMAC), RBAC, validation, rate limit, CORS, secure headers | Implemented + tested |
| Gateway: `/v1/security/scan`, `/check`, `/v1/ai/chat`, `/generate`, `/events`, `/usage`, `/policies` (CRUD) | Implemented + tested |
| Fail-closed orchestration (engine down, bad response, unknown provider, policy/audit outage, output block) | Implemented + tested, incl. **e2e against the real engine** |
| Audit: security events + audit log, zero-retention mode, no-content-persisted test | Implemented + tested |
| `AIProvider` interface, `AiRouter`, retry, SSE streaming, **Gemini adapter** | Implemented; tested against a **mocked** Gemini API (never called the real one) |
| Signup, email/password login, JWT access tokens, rotating refresh tokens with reuse detection, logout, `/auth/me` | Implemented + tested (see [authentication](../api/authentication.md)) |
| User/team management endpoints, MFA, SSO, email verification, password reset | **Not started** |
| Dashboard (Next.js): login/register, overview with metrics + chart + scan playground, security events (filters, search, pagination, CSV export, drill-down), threats, policy editor (never-allow rules enforced in the UI), usage, settings. BFF with httpOnly cookies, CSRF, nonce CSP | Implemented; 39 unit/component tests; production build verified; **driven end-to-end over HTTP against the real engine + gateway** (no browser/visual test was run) |
| API-key management: `GET/POST/DELETE /v1/api-keys` + dashboard page (create shows the secret once; escalation guard; keys cannot manage keys; default 90-day expiry; 100-key cap; `last_used_at`) | Implemented; 19 DB/HTTP tests + verified on the live stack |
| Dashboard **File scan** page + BFF upload route `POST /api/files/scan` (raw bytes, bounded streaming read with a 20 MiB default cap, Content-Length/truncation check, credentials checked before the body is read, synthetic `upload.<ext>` name only, single-flight refresh with the same bytes re-sent; `file_scan` events filterable in the events API and page) | Implemented; 23 new dashboard tests (63 total), mutation-checked, and **driven against the real Next production server + real gateway/engine/scanner** (binary DOCX byte-exact, macro DOCX blocked, 15 MB upload untruncated, 21 MB -> 413, CSRF/Origin/401/415 checks). Not tested in a real browser |
| Dashboard pages NOT built (no backing API yet): providers, models, users, teams, applications, audit-logs, security-evaluation | **Not started** |
| One-command local stack (engine + gateway on in-memory Postgres + dashboard) | Implemented (`node scripts/development/dev-stack.mjs`) |
| Docker Compose / Dockerfiles | **Built and run** (Docker Engine in WSL2); verified by 81 container checks (step 2 above) |
| CI workflow | **Executed under `act`** (8/8 jobs; see step 7 above); not yet on GitHub-hosted runners |

## Phase 2 - Multi-model: **in progress**

| Item | Status |
|---|---|
| OpenAI, Anthropic (Claude) and Ollama adapters behind the same `AIProvider` interface; shared HTTP/error layer; Gemini moved onto it | Implemented; a 4-provider contract suite (chat, generate, stream, models, validate, error mapping, key hygiene) + wire-format tests. **Mocked APIs only** for OpenAI/Anthropic/Gemini |
| Ollama against a **real local server** | **Verified for real** with `qwen2:0.5b`: adapter chat + streaming, and the full path SDK -> gateway -> real engine -> real Ollama, with a recording proxy proving the real server received the masked text (`j***@example.com`) and never the raw address, and was never contacted for a blocked secret |
| Gateway provider registry from operator config (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OLLAMA_BASE_URL`+`OLLAMA_MODEL`) | Implemented + tested |
| E2E: all four real adapters behind the gateway and the real engine (masking before provider, block, output leak, unknown provider, local-vs-external risk, no content persisted, per-provider usage) | Implemented; 20 tests |
| JavaScript/TypeScript SDK `@sentinelai/sdk` and Python SDK `sentinelai` (zero runtime deps; fail-closed; https-only; no redirects; key redaction) | Implemented; 31 + 57 tests (incl. `scanFile` / `scan_file`); **both verified end-to-end against the real gateway + engine**; not published to npm/PyPI |
| Gateway streaming: `POST /v1/ai/stream` (SSE) with output look-ahead scanning, token-split-safe hydration, AbortController wiring, idle/duration/concurrency limits, audit on every exit path | Implemented; 96 unit/HTTP tests (real sockets, real disconnects) + e2e; 10 mutations killed. Not exercised against real provider SSE or a browser; SDKs do not expose it |
| Reversible tokenization: `services/token-vault` (Redis Hashes, absolute 3600 s TTL, AES-256-GCM at rest, per-session HKDF keys, HMAC-deterministic tokens, default-deny type allow-list, circuit breaker) + engine `vault_session` (`TOKENIZE` writes to the vault; vault failure fails closed) + gateway hydration for chat and streams | Implemented; 109 vault tests + 22 engine tests + 12 e2e (real engine + real vault process + PGlite); 12 vault mutations killed. **Verified against a real Redis server** (step 4 above) |
| File scanning: `POST /v1/files/scan` (raw bytes) -> magic-byte type validation -> malware scan -> isolated extraction / OCR -> same engine + org policy -> allow/block/sanitize; PDF/DOCX/XLSX/CSV/TXT/JSON/images; hidden-text, macro, zip-bomb, PDF-active-content, XXE and parser-crash handling; memory-only, metadata-only records, fully audited, fails closed | Implemented: 117 scanner tests (benign + hostile synthetic files), 44 gateway tests, 19 e2e tests (real engine + scanner + PGlite), both SDKs (`scanFile` / `scan_file`) verified end-to-end. **Verified with real ClamAV and Tesseract**, natively and in the compose stack (step 5 above) |
| SDK streaming/async, per-org provider credentials in the DB, provider/model management APIs | **Not started** |
## Phase 3 - AI security: ML-assisted injection classifier, NER, independent red-team datasets, advanced policies.
## Phase 4 - Enterprise: SSO/SAML/OIDC/SCIM/MFA, Kubernetes/Helm/Terraform, tracing/metrics, Redis rate limiting.
## Phase 5 - Advanced: AI usage discovery, behavioural analytics, governance.

## Known limitations

- The dashboard was exercised through its HTTP surface and unit/component tests, **not in a real browser**: layout, accessibility with assistive tech and client-side navigation are unverified.
- The dashboard has no user/team management, so extra users can only be created directly in the database (tests do this).

See [threat model](../security/threat-model.md#known-gaps). Highlights: no NER or ML layer; evaluation set is self-authored;
the independent evaluation (step 8) shows low recall on third-party injection/jailbreak prompts; tokenized values are reversible only within a vault session (see streaming-and-tokenization.md); multi-message chats are scanned per message plus joined, so a secret
split mid-token across messages is only caught if the joined text still matches; rate limiting is per-instance; policy
writes and their audit-log entry are separate transactions.
