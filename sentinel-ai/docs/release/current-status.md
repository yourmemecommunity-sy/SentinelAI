# SentinelAI — current verification status

Updated **2026-09-26**. Machine: Windows 11 host, WSL2 (Ubuntu 26.04) with Docker Engine 29.1.3 + Compose 2.40.3,
Node 24 (host) / 20 (containers), Python 3.13 (host) / 3.12–3.13 (containers). Full detail: `v1.0-release-report.md`.

Status vocabulary: **VERIFIED** (exercised against the real dependency) · **MOCK-VERIFIED** (only against a double)
· **PARTIALLY VERIFIED** · **NOT VERIFIED** · **BLOCKED** (needs something outside this repository) · **NOT IMPLEMENTED**.

A test passing is not by itself verification: what matters is *what the test ran against*.

## Environment actually available

| Dependency | Present | Used for |
|---|---|---|
| Docker Engine + Compose (inside WSL2) | **Yes** | Full stack, image scanning, `act`, kind |
| kind / Helm / kubectl / Terraform | **Yes** (kind v0.30.0, Helm 3.16, Terraform 1.9 in a container) | Kubernetes + Terraform verification |
| PostgreSQL 18 | **Yes** — container, WSL-native, and CI service container | Migrations, RLS, all DB suites |
| Redis | **Yes** — container, WSL-native, CI service container | Token vault |
| ClamAV + Tesseract | **Yes** — container and WSL-native | Document scanner |
| Ollama | **Yes** — `qwen2:0.5b` | Real chat and streaming |
| Chromium (Playwright container) | **Yes** | Browser E2E |
| Gemini / OpenAI / Anthropic keys | **No** | Real calls **BLOCKED** |

> **Networking caveat (measured):** Windows → WSL TCP is unreliable on this machine — on the same run one port connected
> and another timed out, then the reverse. Real-infrastructure suites are therefore run *inside* WSL/Docker (compose, `act`,
> kind), where they are reliable, rather than from the Windows host.

## Component status

| Area | Status | Evidence |
|---|---|---|
| Authentication, JWT, refresh rotation, per-request session re-check | **VERIFIED** | Real PostgreSQL; containers; browser |
| RBAC + multi-tenancy (RLS) | **VERIFIED** | Real PostgreSQL; containers; kind |
| Migrations (8) | **VERIFIED** | Real PostgreSQL; advisory-locked; race-tested; idempotent; checksum guard proven in practice |
| Detection engine | **VERIFIED** | 132 tests + evaluation gate |
| Policy + risk engine, sanitization | **VERIFIED** | Engine + gateway tests |
| Token vault | **VERIFIED on real Redis** | 112 tests on real Redis 8.0.5; vault outage under load fails closed; bursts above the pool size queue |
| Streaming (SSE) | **VERIFIED with a real provider** | Real Ollama through containers and both SDKs |
| Document scanner | **VERIFIED** | Real ClamAV + Tesseract; container fail-closed |
| User / team / invitation management | **VERIFIED** | Real PostgreSQL; containers; browser |
| Per-organization provider credentials | **VERIFIED** | Encryption, AAD binding, routing, fail-closed; containers |
| Ollama adapter | **VERIFIED** | Real server |
| Gemini / OpenAI / Anthropic adapters | **MOCK-VERIFIED** — real calls **BLOCKED** | No credentials |
| SDKs (JS + Python), incl. streaming | **VERIFIED** | Against the real gateway and a real model. JS SDK suite: intermittent failure on the Windows host only, root cause not determined (release report §10) |
| Dashboard | **VERIFIED** | Real Chromium E2E, 23 checks |
| Audit / zero-knowledge trail | **VERIFIED** | No plaintext in any table |
| Docker Compose | **VERIFIED** | 81 checks |
| Container image scanning | **VERIFIED** | 0 fixable HIGH/CRITICAL |
| Kubernetes / Helm | **VERIFIED on kind** (single node) | 31 checks incl. NetworkPolicy enforcement. Multi-node: **NOT VERIFIED**; managed cloud: **BLOCKED** |
| Terraform | **VERIFIED on kind** (`modules/kubernetes`); cloud modules **NOT IMPLEMENTED** | plan/apply/destroy |
| CI pipeline | **VERIFIED under `act`** | 8/8 jobs (incl. `python-typecheck`); GitHub-hosted runners **BLOCKED** until pushed |
| Python type checking | **VERIFIED** | mypy strict (application code) on all 5 packages, tests type-checked; 0 `type: ignore` |
| Secret scanning (push protection) | **VERIFIED** | gitleaks default rules, no allow-list: 0 findings on the commit file set |
| Performance | **VERIFIED (baseline)** | ~145–185 req/s, 0 errors, single VM. Sustained soak: **NOT VERIFIED** |
| Chaos / failure | **VERIFIED** | 5 faults under load, invariants held |

## Blockers requiring owner action

| # | Blocker | Exact action |
|---|---|---|
| 1 | No `GEMINI_API_KEY` | Add a real key to `.env` (or store one for a test organization via `PUT /v1/providers/gemini/credential`) |
| 2 | No `OPENAI_API_KEY` | Same, for OpenAI |
| 3 | No `ANTHROPIC_API_KEY` | Same, for Anthropic |
| 4 | CI never run on GitHub | Amend local commit 9ac9039 (it holds pre-defang dataset values), push, confirm all 9 jobs green |

Docker is no longer a blocker: Docker Engine runs inside WSL2.
