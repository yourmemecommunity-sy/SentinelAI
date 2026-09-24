# Final report — "written but never run" → "verified for real"

Run: **2026-09-26 → 2026-09-27**, autonomously. Scope: tasks 1–11; no new features; phases 3–5 out of scope.
Every "Done" below links to evidence that contains the commands and their real output. Nothing is marked done that was not
run and seen to pass.

## 1. Task status

| # | Task | Status | Evidence |
|---|---|---|---|
| 1 | Baseline: all existing suites | **Done** — 1,119 tests, 0 failed (16 scanner tests need real ClamAV/Tesseract → run in task 5) | [01-baseline.md](01-baseline.md) |
| 2 | Docker: build everything, run the stack, verify | **Done** — all 7 Dockerfiles build; 10 services healthy; `/ready` 200; scan masks/blocks correctly; dashboard over HTTP; 81/81 container checks. Added the missing `ollama` healthcheck | [02-docker.md](02-docker.md) |
| 3 | Real PostgreSQL | **Done** — PostgreSQL 18.6: migrations 0001–0008 on a fresh DB (idempotent re-run), 130/130 DB tests incl. **40/40 tenant isolation** | [03-postgresql.md](03-postgresql.md) |
| 4 | Real Redis | **Done** — Redis 8.0.5: 112/112 vault tests; plus a new live check against a **frozen** real Redis: TTL eviction, fail-closed, breaker opens (calls fail in ~0.01 ms) and recovers after cooldown | [04-redis.md](04-redis.md) |
| 5 | Real ClamAV + Tesseract | **Done** — ClamAV 1.5.4 + Tesseract 5.5: 133/133 scanner tests, 0 skipped; through the live stack EICAR is blocked (`Eicar-Test-Signature`) and an email in a PNG screenshot is OCR'd and masked | [05-clamav-tesseract.md](05-clamav-tesseract.md) |
| 6 | Real AI provider | **Partially done** — cloud providers **BLOCKED** (no key); **Ollama verified**: 14 real-server tests + both SDKs through the Docker stack (10/10). A recording proxy proves the model received `j***@example.com` (never the address) and **zero** requests for a blocked secret | [06-real-provider.md](06-real-provider.md) |
| 7 | CI | **Done under `act`** — 8/8 jobs pass from the real repository root; `containers` steps run directly (Trivy: 0 fixable HIGH/CRITICAL). Badge added. **GitHub-hosted run BLOCKED** on the owner's push (history must be squashed first) | [07-ci.md](07-ci.md) |
| 8 | Independent security evaluation | **Done** — public datasets, no tuning, one command, hash-pinned. Test splits: deepset/prompt-injections **1.7 %** detection / 0 % FP; jackhhao/jailbreak-classification **39.6 %** / 0 % FP. garak not run (D6) | [08-independent-evaluation.md](08-independent-evaluation.md) |
| 9 | Performance | **Done** — k6 + instant mock provider: the gateway adds **p50 42 / p95 56 / p99 84 ms** to a chat request at 1 in flight; saturates at ≈44–68 chat req/s, ≈128 scan req/s on one laptop; 0 failed requests | [09-performance.md](09-performance.md) |
| 10 | README for recruiters | **Done** — problem statement, Mermaid diagram, verified-for-real table, numbers, one-command quick start, limitations | [README.md](../../README.md) |
| 11 | Learning guide | **Done** — 8 decisions × (what / why / rejected alternative / what breaks / files / 3 interview Q&A) | [LEARNING.md](../LEARNING.md) |

## 2. Defects found and fixed during this run

1. **CI would never have run on GitHub.** The workflow sat in `sentinel-ai/.github/workflows/`, but the git root is one level
   up, and GitHub only reads the root. It is now moved to the root, with the paths adjusted, and verified under `act` from the real
   root. Earlier `act` runs had hidden this by treating `sentinel-ai/` as the root.
2. **The OpenAPI contract tests were silently skipped in CI** (`importorskip("yaml")` with PyYAML not installed). They are now installed
   and run with `-rs`: 15 passed, 0 skipped.
3. **The `ollama` service had no healthcheck.** It now uses `ollama list`, which passes only once its API answers.
4. Harness bugs in the new verification scripts, fixed and re-run rather than reported as passes: the OCR check ran where
   Pillow was missing; the EICAR check accepted any block (now requires `malware_detected`); a TTL bound ignored the documented
   round-up to whole seconds; k6 could not write its summaries.

No product code changed in this run. Every existing test and check is intact; none was weakened or skipped.

## 3. Blockers — exactly what you must do

| Blocker | What to do |
|---|---|
| **Git history contains synthetic secret-shaped values** (commit `9ac9039`: 79 gitleaks findings; GitHub push protection will reject the push, and the CI secret scan would fail) | From `C:\Users\Shivam dubey\OneDrive\Desktop\googleAi`:<br>`git reset --soft 9ac9039`<br>`git commit --amend -m "SentinelAI: security gateway for enterprise AI"`<br>`git log --oneline` (must show **1** commit)<br>`git push -u origin main`<br>Verified on a clone: the result is 1 commit, a tree identical to today's HEAD, **0 findings**. Do not use GitHub's "allow secret" links. |
| **CI never ran on GitHub-hosted runners** | After the push, open *Actions* and confirm all 9 jobs are green: structure, security-engine, document-scanner, python-typecheck, token-vault, gateway, dependency-scanning, secret-scanning, containers. The README badge turns green only then |
| **No cloud-provider API key** | Put a real key in `sentinel-ai/.env` (for example `GEMINI_API_KEY=…`; never commit it), restart the stack, run `cd apps/api && npx vitest run tests/e2e/multiProvider.e2e.test.ts` and the SDK e2e, then record the result in `docs/verification/06-real-provider.md` |
| Laptop suspends mid-run (Modern Standby ignores the keep-awake when the lid closes) | Keep the lid open and on power while running long verifications; the scripts detect a suspend (wall time ≠ VM uptime), and affected runs were discarded |

## 4. Decisions taken (full list: [decisions-log.md](../decisions-log.md))

* **D1** Commits are stacked on the unpushed `9ac9039`; squashing is left to you, because the environment refused a history rewrite.
* **D2 / D10** A keep-awake runs during verification; any run hit by a suspend is discarded and repeated (3 were).
* **D3** Cloud provider is blocked (no key); Ollama is re-verified instead.
* **D4** The `containers` CI job is not run under `act` (it would clobber the running stack's volumes); its commands were run directly.
* **D5** Independent evaluation uses deepset/prompt-injections + jackhhao/jailbreak-classification, test splits, no tuning,
  data cached outside the repo and pinned by hash.
* **D6** garak is not run: it measures a model's outputs over hours of CPU generation, not the gateway's input filter.
* **D7** The workflow moved to the repository root.
* **D8** CI installs PyYAML so the contract tests actually run.
* **D9** k6 with an instant mock provider; the rate limit is lifted for the benchmark only and restored afterwards.
* **D11** No root README added; `sentinel-ai/README.md` is the landing page (you can move it when publishing).

## 5. Final numbers

| Measure | Result |
|---|---|
| Automated tests | 1,119 (host), 0 failed; plus 130 DB tests on real PostgreSQL, 112 vault tests on real Redis, 133 scanner tests with real ClamAV/Tesseract, 81 container checks, 8 live checks, 8 breaker/TTL checks |
| Self-authored evaluation (524 records) | 100 % of critical cases, false-positive rate within the 2 % budget |
| **Independent evaluation, test splits** | deepset/prompt-injections: **1.7 %** detection, 0 % FP · jackhhao/jailbreak-classification: **39.6 %** detection, 0 % FP (threat) / 0.8 % (any block) |
| Independent evaluation, all rows | 3.8 % / 0 % · 32.0 % / 0.2 % |
| **Gateway latency overhead**, 1 in flight | chat: p50 **42.4 ms**, p95 **55.7 ms**, p99 **84.1 ms** · scan alone: p50 22.9 ms |
| Throughput, one instance on one laptop | ≈ 44–68 chat req/s · ≈ 128 scan req/s |
| Images | 0 fixable HIGH/CRITICAL CVEs in all 6 (Trivy) |

## 6. Honest maturity rating

**Overall: a well-engineered, security-first prototype verified on a single machine. It is not production-ready, and its
detection quality is the weakest part.**

| Dimension | Rating | Why |
|---|---|---|
| Security architecture (fail-closed, RLS, crypto, file defences, audit) | **Strong** | Designed defensively and now proven against real Postgres, Redis, ClamAV, Tesseract and Docker, including outages |
| Engineering hygiene (tests, typing, CI, evidence) | **Strong** | 1,100+ tests, mypy strict, 8 CI jobs green under `act`, reproducible evidence |
| **Detection quality (what it catches)** | **Weak** | Precise but low recall on third-party attacks (1.7 % / 39.6 %). Rules only, English-centric. The self-authored suite overstated it |
| Provider coverage | **Partial** | Only Ollama is real; the Gemini/OpenAI/Anthropic adapters have never made a real call |
| Operations / scale | **Early** | Single instance and one laptop; per-instance rate limiting; no soak, multi-node or managed-cloud run; ≈65 chat req/s |
| Readiness for real users | **Not ready** | Needs better detection recall (ML classifier), real provider verification, a GitHub CI run, a shared rate limiter, and a load/soak test on real hardware |

In an interview, this is a credible portfolio project: it shows systems and security depth, and it states its limits with
evidence. Its strongest story is how security failures are prevented and proven. Its weakest is the detection numbers, which are
worth presenting honestly as "measured, and why an ML layer is next".

## 7. Open items not closed by this run

* An intermittent failure of the JavaScript SDK suite on the Windows host (about 5 of 78 historical runs; never on Linux). It
  passed in this run's baseline; root cause not determined (see `docs/release/v1.0-release-report.md` §10).
* Multi-replica rate limiting: designed, not built ([LEARNING.md §7](../LEARNING.md#7-rate-limiting-per-instance-today-and-the-fix)).
* garak / model-output red-teaming, and cloud providers (above).
