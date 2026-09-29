# Threat Model

## Assets
Customer prompts/responses (may contain regulated data), provider credentials, API keys, policies, audit trail, tenant isolation.

## Actors
External attacker via a customer app; malicious end user; malicious document/tool output (indirect injection);
compromised provider; curious/compromised tenant admin; insider with DB/log access; supply-chain attacker.

## Threats and mitigations

| # | Threat | Mitigation | Status |
|---|---|---|---|
| T1 | Sensitive data reaches a model | Detect -> policy -> sanitize -> **rescan** -> risk; fail closed | Engine implemented |
| T2 | Prompt injection / jailbreak / system-prompt extraction | Deterministic rules incl. normalization, homoglyph/leet/spacing/reverse/ROT13, base64/hex/percent decoding | Implemented (rules only) |
| T3 | Classifier is itself prompt-injected | No LLM reads attacker text ([ADR-0004](../architecture/adr/0004-deterministic-detection-first.md)) | Implemented |
| T4 | Detector bypass by novel encoding/paraphrase | Layered detectors; regression + independent red-team datasets | **Partial** - see gaps |
| T5 | ReDoS / oversized input | Linear-time patterns, `max_input_chars`, per-stage time budget, fail closed | Partial (re cannot be preempted) |
| T6 | Detector/policy/scanner outage silently bypasses security | Fail closed, `/ready` canary, unreachable engine => block | Implemented in engine and gateway; e2e-tested by killing the engine |
| T7 | Permissive policy exposes secrets | ALLOW rejected for credentials/cards/threats at load *and* evaluation | Implemented |
| T8 | Secrets leaked via logs/audit | Detections hold location + keyed digest only; logs carry entity types only; schema has no content column; an e2e test dumps every table and asserts no prompt/secret text | Implemented |
| T9 | Token-vault exposure | Per-request, in-memory; Redis+TTL+encryption planned | Partial |
| T10 | Cross-tenant access | `organization_id` on every tenant row, RLS with fail-closed default, composite FKs, append-only evidence, 40 isolation tests + e2e cross-org checks | Implemented; verified on PGlite, not a real server |
| T11 | Credential stuffing / API-key theft | HMAC-hashed API keys with pepper, constant-time compare, uniform 401, per-IP rate limit | API keys + scrypt password login implemented (uniform failures, dummy-hash timing equalisation, per-email and per-IP throttling, refresh reuse detection); MFA **planned**; limits are per-instance |
| T16 | XSS / token theft from the dashboard | Tokens only in HttpOnly cookies (browser JS never sees them), refresh cookie scoped to `/api`, nonce-based CSP with `strict-dynamic`, React escaping (tested with hostile strings), CSV-export formula guard | Implemented; not pen-tested |
| T17 | CSRF against the dashboard BFF | SameSite=Strict, custom header, Origin==Host check, proxy allow-list | Implemented + tested |
| T18 | Refresh-token replay via the BFF single-flight cache | 5 s sharing window, purge on logout, failures never cached; found and fixed via live replay test | Implemented; residual <=5 s window per instance |
| T19 | SSRF via provider base URL | Base URLs come only from operator env config, validated (http/https, no credentials); nothing in a request can select or alter one | Implemented; per-org provider URLs (future) will need an allow-list/egress policy |
| T20 | Provider error/response leaks prompt or key into logs/clients | Header-only credentials, error messages built from status only, contract-tested for all four providers | Implemented |
| T21 | API-key leakage from the SDKs (logs, repr, redirects, clear-text transport) | Key redacted from repr/inspect/JSON, never in errors, https-only (localhost excepted), redirects refused (urllib would re-send the key; mutation-tested), local key-shape validation | Implemented + tested |
| T22 | Untrustworthy gateway response released as content | SDK returns content only from a well-formed 200 and rejects self-contradictory results (e.g. blocked-with-text) | Implemented + tested |
| T23 | Privilege escalation / credential persistence via key management | Subset-of-own-permissions rule, user-session-only management, first-class audit, expiry + cap; the rule found and fixed an ADMIN<ANALYST permission inconsistency | Implemented + tested |
| T12 | Forged internal calls to the engine | `X-Internal-Token` (constant-time compare); production refuses to start without it; network policy | Token implemented; mTLS planned |
| T13 | Supply chain | Dependency + container scanning, SAST in CI, pinned lockfiles | CI written, not yet run |
| T14 | Output leaks secrets/PII back to user | Same engine scans model output (`direction=OUTPUT`) with output-leakage cases in the suite | Implemented; e2e-tested with a model reply that leaks a key |
| T15 | Malicious uploaded files (disguised type, macros, embedded objects, PDF JavaScript/Launch, malware) | Magic-byte allow-list (extension mismatch blocked), malware scan before parsing, macro/OLE/ActiveX/embedding/PDF-active-content blocked (incl. inside compressed PDF object streams), no persistence | Implemented; **ClamAV never run for real**, dev baseline sees only the raw EICAR string |
| T24 | Archive/parse DoS (zip bombs, huge PDFs, parser hangs/crashes) | Entry, ratio and read-budget caps, page cap, text cap that blocks rather than truncates, parsers in a child process killed on timeout | Implemented + tested with hostile samples |
| T25 | Indirect prompt injection hidden in a document (white/tiny/vanish text, comments, tracked deletions, metadata, hyperlink targets) | All of it is extracted and scanned like any prompt, hidden text is also flagged and raises the risk floor | Implemented for DOCX/XLSX; **PDF visually hidden text is extracted but not flagged as hidden** |
| T26 | XXE / entity-expansion via OOXML | `defusedxml` for every XML part | Implemented + tested |
| T27 | Scanner compromised or spoofed (fake "clean" verdict) | Internal token, gateway checks the returned sha256/size against its own bytes, BLOCK-with-text is rejected, only a synthetic `upload.<ext>` name is sent; scanner makes no outbound calls other than to clamd | Implemented; mTLS planned |
| T28 | Personal data in file names | Only the extension is ever sent, stored or logged | Implemented + tested |
| T30 | Truncated or oversized upload through the dashboard BFF is scanned as if it were the whole file (content hidden past the cut) | Bounded streaming read (413 past the cap, reading stops), `Content-Length` must match the bytes received (else 400), upload route kept out of Next middleware body-cloning (observed to truncate at 10 MB) | Implemented; mutation-tested and verified with a 15 MB upload on the real Next server |
| T31 | Secret split across streamed chunks slips out before it is recognised | Output look-ahead: text is released only after the scan covered it plus `STREAM_HOLDBACK_CHARS` more; buffered mode releases nothing before a whole-reply scan | Implemented; control test shows a split secret is invisible without it. **Limit:** values longer than the hold-back |
| T32 | Vault as an exfiltration path (plaintext returned on demand) | Internal token only; per-caller session derivation (SHA-256 of org+principal+session_id) so callers cannot name each other's sessions; default-deny type allow-list; encrypted at rest with per-session keys; absolute TTL; caps; only requested tokens returned | Implemented; e2e proves cross-caller and cross-org isolation. mTLS/network policy still to do |
| T33 | Model output tricks hydration (guessed/forged tokens, token floods) | Unknown tokens stay tokens (indistinguishable from foreign ones); 512 lookups per stream; batching; hydration happens after the scan | Implemented + tested |
| T34 | Vault outage silently changes behaviour | Prompt needing a token: fail-closed block (`vault_unavailable`); reply hydration: tokens left un-hydrated, `hydration: degraded` reported | Implemented; e2e kills the vault |
| T35 | Stream resource abuse (slow provider, endless output, connection hoarding) | Idle timeout, max duration, output cap, per-caller concurrency limit, abort on disconnect, backpressure | Implemented + tested |
| T29 | Text hidden in image pixels | OCR text is scanned; an image with no recognised text is allowed with an `ocr_no_text` finding | **Gap**: OCR cannot see what it cannot read; Tesseract never run for real |

## Known gaps

- **Partial NER**: a local spaCy model finds person names and places (about half of all names on public held-out data), but addresses remain heuristic, and usernames and IDs are mostly missed. Its CPU cost cuts engine throughput by about 70 % (docs/verification/11-pii-improvement-cycle.md).
- **No ML classifier**: paraphrased/semantic injections and jailbreaks can evade rules.
- **Business-data classifiers absent**: proprietary source code, architecture, contracts, pricing.
- **Obfuscated PII/secrets** (e.g. spaced-out emails or keys) are not normalized like injections are.
- **Self-authored evaluation set**: 100% pass demonstrates no regression on known cases, not resistance to unseen attacks.
- **Regex time limit**: Python `re` cannot be interrupted; a pathological pattern added later could stall a worker (mitigate by review + process-level timeout at the gateway).
- **MFA, SSO, email verification and password reset are not implemented.** Access tokens are not revocable before expiry (<= 15 min); role changes apply at next refresh.
- **Provider calls are tested against mocked APIs**; the real Gemini/OpenAI/Anthropic endpoints have never been called (wire formats follow their public docs and are unverified against live responses). Only Ollama discovery has run against a real server.
- **Streaming and the vault are new**: never run against a real Redis server, real provider SSE or a browser. See [streaming-and-tokenization.md](streaming-and-tokenization.md#known-limitations).
- **Released stream text cannot be recalled**, and the look-ahead is finite (values longer than `STREAM_HOLDBACK_CHARS` may have their start released before they are recognised).
- **Audit of policy changes is a separate transaction** from the change itself.
- **SDKs are unpublished and synchronous/non-streaming**; the API key still lives in the calling application's memory (use a secret manager; never ship it to browsers).
- **File scanning is only proven against synthetic files.** ClamAV and Tesseract have never been run against the scanner; production requires clamd, but that path is untested against a real daemon. Compressed content is invisible to the dev EICAR baseline.
- **A PDF scan takes about 3 s** (child-process start plus parser import), and hidden text in PDFs is not flagged.
- **Host antivirus can reset loopback connections carrying the EICAR string**, so EICAR is only tested in-process, not over sockets.
- **No user/team management endpoints**: users beyond the signup OWNER can only be created in the database.
