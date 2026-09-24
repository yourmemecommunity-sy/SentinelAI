# Task 1 — Baseline: every existing test suite

Run: **2026-09-26 10:55–11:48 IST** on the Windows 11 host (Node 24, Python 3.13), commit `6137845` plus the
uncommitted evidence docs. Runner: the same commands CI uses, one suite at a time, results parsed from JSON/JUnit reports.

| Suite | Command | Tests | Passed | Failed | Skipped |
|---|---|---|---|---|---|
| apps/api (unit, security, streaming, e2e with real engine/scanner/vault processes, DB on PGlite) | `cd apps/api && npx vitest run` | 456 | 456 | 0 | 0 |
| services/ai-router (incl. 3 tests against a real Ollama server) | `cd services/ai-router && npx vitest run` | 61 | 61 | 0 | 0 |
| apps/dashboard | `cd apps/dashboard && npx vitest run` | 67 | 67 | 0 | 0 |
| packages/sdk/javascript (incl. real gateway e2e) | `cd packages/sdk/javascript && npx vitest run` | 61 | 61 | 0 | 0 |
| services/security-engine | `python -m pytest -q` | 132 | 132 | 0 | 0 |
| services/token-vault (fakeredis) | `python -m pytest -q` | 112 | 112 | 0 | 0 |
| services/document-scanner | `python -m pytest -q` | 133 | 117 | 0 | **16** |
| packages/sdk/python | `python -m pytest packages/sdk/python/tests` | 82 | 82 | 0 | 0 |
| repo security + regression | `python -m pytest tests/security tests/regression` | 15 | 15 | 0 | 0 |
| Security evaluation gate (self-authored, 524 records) | `python scripts/security/run_evaluation.py` | — | PASS | 0 critical | — |
| Dependency audit | `pnpm audit --prod --audit-level=high` | — | no known vulnerabilities | — | — |
| Structure validator + its tests | `node scripts/development/validate-structure.mjs` | 3 | 3 | 0 | 0 |
| TypeScript, src **and** tests | `tsc --noEmit` (api, ai-router, sdk-js, dashboard, shared-types) | — | 0 errors ×5 | — | — |

**The 16 skipped document-scanner tests need a real ClamAV daemon and a real Tesseract binary**, which the Windows host does
not have. They are not counted as passes here: they are run for real in Task 5 (inside WSL), where all 133 pass with 0 skipped.

## Failures found and fixed while establishing the baseline

* An earlier baseline attempt (10:24) lost `tests/e2e/streamVault.e2e.test.ts` (12 tests reported "skipped" because its
  `beforeAll` timed out). Cause: the laptop entered **Windows Modern Standby 10:28:03 → 10:46:51** (System event log,
  Kernel-Power 506/507) while the test was starting its engine and vault processes. The file passes on its own (12/12,
  14 s) and in the full run above. Not a code defect; see decision D2.
* Known open issue carried over: the JavaScript SDK suite has failed intermittently on this Windows host in earlier runs
  (about 5 of 78 full runs; "cannot reach" against its own local stand-in server; never on Linux, 0/30). It passed in this
  baseline. Root cause not determined — see `docs/release/v1.0-release-report.md` §10.

## Raw output (excerpt)
```
exit=0 (167s)
exit=0 (6s)
exit=0 (8s)
exit=0 (20s)
132 passed, 2 warnings in 12.76s
112 passed in 7.99s
117 passed, 16 skipped, 3 warnings in 18.84s
exit=0 (48s)
exit=0 (3s)
  BENIGN               50/50 passed
  DATA_EXFILTRATION    20/20 passed
  FINANCIAL            80/80 passed
  JAILBREAK            18/18 passed
  MALICIOUS_DOCUMENT   12/12 passed
  OUTPUT_LEAKAGE       26/26 passed
  PII                  140/140 passed
  PROMPT_INJECTION     70/70 passed
  SECRETS              108/108 passed
RESULT: PASS
No known vulnerabilities found
exit=0 (8s)
HOST_DONE
Structure validation passed for sentinel-ai.
ℹ tests 3
ℹ pass 3
ℹ fail 0
  apps/api: 0 type errors
  services/ai-router: 0 type errors
  packages/sdk/javascript: 0 type errors
  apps/dashboard: 0 type errors
  packages/shared-types: 0 type errors
HOST3_DONE

== apps_api.json: total=456 passed=456 failed=0 skipped=0
== services_ai-router.json: total=61 passed=61 failed=0 skipped=0
== apps_dashboard.json: total=67 passed=67 failed=0 skipped=0
== packages_sdk_javascript.json: total=61 passed=61 failed=0 skipped=0
   router REAL: passed REAL local Ollama server validate() and getModels() work against the real API
   router REAL: passed REAL local Ollama server a model that is not pulled yields a typed bad_request (real server error path), not a
   router REAL: passed REAL local Ollama server real chat and streaming with the first installed model
== py_document-scanner.xml: tests=133 passed=117 failed=0 errors=0 skipped=16
== py_repo.xml: tests=15 passed=15 failed=0 errors=0 skipped=0
== py_sdk.xml: tests=82 passed=82 failed=0 errors=0 skipped=0
== py_security-engine.xml: tests=132 passed=132 failed=0 errors=0 skipped=0
== py_token-vault.xml: tests=112 passed=112 failed=0 errors=0 skipped=0
== eval keys: ['records', 'categories', 'metrics', 'critical', 'failures', 'dataset_problems']
```
