# Components

## apps/dashboard (Next.js) - **implemented (see [ADR-0006](adr/0006-dashboard-bff-token-handling.md))**
BFF + UI for overview, events, threats, **file scan** (upload a file, see the verdict, findings, hidden-text warnings and the text a model would receive), policies, usage, settings. Pages for providers, models, users, teams, applications, api-keys, audit-logs and security-evaluation are not built because their APIs do not exist yet.

## apps/api (TypeScript) - **implemented core**
Implemented: API-key authentication, RBAC, tenant-scoped data access (Postgres RLS), request validation, rate limiting, CORS/secure headers,
orchestration of the security pipeline with fail-closed handling, provider routing via `ai-router`, audit/usage writing, policy CRUD,
`/health`, `/ready`. Also: signup, email/password login, JWT + rotating refresh tokens. API-key management. File scanning (`POST /v1/files/scan`), SSE streaming (`POST /v1/ai/stream`) and vault-backed hydration. Not yet: user/team management, MFA/SSO, billing APIs, streaming.
Never contains provider-specific logic and never bypasses the pipeline.

## services/security-engine (Python) - **implemented core**
| Module | Responsibility |
|---|---|
| `detectors/pii`, `financial`, `secrets`, `credentials`, `confidential_data` | Layered regex + checksum (Luhn/Verhoeff/IBAN) + context + entropy detection |
| `detectors/prompt_injection` | Deterministic injection/jailbreak/exfiltration rules with normalization, obfuscation and decoding layers |
| `detectors/registry.py` | Detector registry; custom detectors register here |
| `policies/` | Policy schema, scope matching, deny-overrides evaluation, baseline defaults |
| `risk/` | Explainable 0-100 score, level, decision escalation |
| `sanitization/` | mask / redact / tokenize / hash with overlap merging and token vault |
| `pipelines/scan_pipeline.py` | Orchestrates the above and enforces fail-closed |
| `api/` | FastAPI: `POST /v1/scan`, `/health`, `/ready` (with canary self-test) |

Stateless: the gateway passes the policy inline; the engine holds no tenant data.

## services/policy-engine - *skeleton*
Will own policy authoring, versioning and storage. Phase 1 evaluation lives in the engine ([ADR-0003](adr/0003-policy-semantics.md)).
`/ready` returns 503 so callers cannot mistake the skeleton for a working dependency.

## services/token-vault (Python) - **implemented** ([README](../../services/token-vault/README.md))
Internal, plaintext-returning service for reversible tokenization: deterministic per-session tokens (`[TOK_EMAIL_1]`), Redis Hashes with an absolute
3600 s deadline, AES-256-GCM at rest, per-session HKDF keys, allow-listed entity types only, resilient client (timeout, retry, circuit breaker). Called
by the engine (tokenize) and the gateway (resolve). **Not verified against a real Redis server.**

## services/document-scanner (Python) - **implemented** ([README](../../services/document-scanner/README.md))
`POST /v1/extract` turns an untrusted file into safe text or a BLOCK: size cap, magic-byte sniffing against an allow-list (PDF, DOCX, XLSX, CSV, TXT, JSON,
PNG, JPEG, GIF, WEBP), a malware scan **before** any parser runs (clamd, or an EICAR-only baseline in dev), then OCR (Tesseract) or a parser in an isolated
child process with a hard timeout. Hidden/white/tiny/vanish text, comments, tracked deletions and metadata are extracted *and flagged*; macros, embeddings,
PDF JavaScript/Launch/embedded files and encryption are blocked. Uploads live in memory only. The gateway (`FileScanService`) then runs the extracted text
through the same engine and org policy as any prompt, verifies the scanner's sha256/size against the bytes it sent, and audits the result.
**Not verified for real:** ClamAV and Tesseract have never been run against it.

## services/ai-router (TypeScript) - **Gemini adapter + router implemented** (in-process library, [ADR-0005](adr/0005-ai-router-in-process.md))
`AIProvider` interface (`chat`, `generate`, `stream`, `validate`, `getModels`) with `GeminiProvider`, `OpenAIProvider` (also any OpenAI-compatible endpoint via base URL),
`AnthropicProvider` and `OllamaProvider`, a shared HTTP layer (typed non-leaky errors, header-only credentials, base-URL validation), retry with backoff,
SSE/NDJSON parsing and `AiRouter`. Only mocked network was used except for Ollama discovery. There is no automatic cross-provider fallback (policy bypass risk).

## packages
`shared-types` (TS contracts mirrored by the Python wire models), `sdk` (JS + Python), `security-rules` (versioned rule sets).

## Extension points
- **Custom detectors**: subclass `Detector`, register in `DetectorRegistry`.
- **Custom confidential terms**: `CustomTermDetector({term: severity})` for project names, customers, etc.
- **Providers**: implement `AIProvider`; register in the router.
