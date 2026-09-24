# Learning guide — the key design decisions in SentinelAI

Plain-English notes for the owner of this repository: for each important decision, what it is, why it was chosen, what
was rejected, what would break without it, which files to read, and three interview questions with model answers.

Read the files in the order listed; each list starts with the smallest, most central file.

---

## 1. API keys stored as HMAC-SHA256 (with a server-side pepper)

**What it is.** An API key looks like `snl_<8-char id>_<43-char secret>`. The plaintext is shown to the user exactly once.
The database stores only `HMAC-SHA256(pepper, key)` plus the 12-character prefix. The pepper is a secret that lives in
the gateway's environment, never in the database. To authenticate, the gateway finds the row by prefix, recomputes the
HMAC and compares the two with a constant-time comparison.

**Why.** API keys are long random strings, not human passwords, so they do not need a slow hash like bcrypt: brute force
is already hopeless, and a fast hash keeps authentication off the request's critical path. The HMAC with a pepper means a
stolen database dump is useless on its own: without the pepper an attacker cannot even check a guessed key offline.

**Rejected alternatives.**
* *Plain SHA-256*: a leaked table could be checked offline against candidate keys (for example keys leaked elsewhere).
* *bcrypt/argon2*: built for low-entropy passwords. On a high-entropy key it only adds 50–100 ms of CPU per request.
* *Storing the key encrypted*: anything that can decrypt it can leak it, and nothing needs the plaintext back.

**What breaks without it.** With plaintext keys, one database leak (a backup, a log, a SQL injection) hands out every
customer's working credentials. Without the constant-time compare and the dummy comparison for unknown prefixes, response
timing would reveal which prefixes exist.

**Read:** `apps/api/src/security/apiKeys.ts` → `apps/api/src/routes/apiKeyRoutes.ts` →
`scripts/database/migrations/0001_init.sql` (`app_find_api_key`, a `SECURITY DEFINER` lookup that works before a tenant is known).

**Interview questions**
1. *Why HMAC and not bcrypt for API keys?* — Bcrypt exists to slow down guessing low-entropy secrets. A 256-bit random key
   cannot be guessed, so the slowness only costs latency. HMAC with a pepper gives what matters: the stored value is
   useless without a secret that is not in the database.
2. *Why store a prefix?* — So the lookup is an indexed equality on a non-secret column, instead of hashing against every
   row. It also lets users and logs refer to a key ("snl_ab12cd34…") without exposing it.
3. *How do you rotate the pepper?* — It invalidates every stored hash, so rotation means issuing new keys. A production
   design would keep a pepper id per row and accept old and new peppers during a migration window. That is not built here.

---

## 2. Multi-tenancy with PostgreSQL row-level security (RLS)

**What it is.** Every tenant table has an `organization_id` column, row-level security enabled, and a policy
`tenant_isolation … USING (organization_id = app_org_id()) WITH CHECK (organization_id = app_org_id())`, where `app_org_id()`
reads the `app.org_id` setting. The gateway never queries tenant data directly: it goes through
`TenantDb.withTenant(orgId, fn)`, which opens a transaction and calls `set_config('app.org_id', orgId, true)`. The `true`
makes the setting transaction-local. With no org set, RLS returns no rows at all. The gateway connects as a restricted role (`sentinel_app`): not a superuser, no `BYPASSRLS`, not the
table owner. At startup it **refuses to run** in production if RLS would not actually apply (`checkRlsEnforced`).

**Why.** Isolation enforced by the database holds even when application code has a bug. A forgotten
`WHERE organization_id = $1` in one query becomes "no rows", not "another customer's data". Composite foreign keys
(`(organization_id, id)`) stop a row in one org from referencing a row in another.

**Rejected alternatives.**
* *`WHERE` clauses only*: one missed clause anywhere is a cross-tenant leak, and nothing detects it.
* *A database or schema per tenant*: stronger isolation, but migrations, connection pools and cross-tenant operations get
  much harder. It suits a few large tenants, not many small ones.

**What breaks without it.** Any query bug leaks data across customers. And a subtle trap the code guards against: Postgres
**silently skips RLS** for superusers, `BYPASSRLS` roles and table owners. Connecting as the image's default `postgres` user
would disable isolation with no error anywhere. The migrations use `ENABLE`, not `FORCE ROW LEVEL SECURITY`, so the table
owner *would* bypass RLS. That is why migrations run as the owner and the gateway as a separate non-owner role, and why the
gateway checks this at startup.

**Read:** `apps/api/src/db/tenantDb.ts` → `scripts/database/migrations/0001_init.sql` (the loop that enables RLS and creates `tenant_isolation` on every tenant table)
→ `scripts/database/provision-app-role.mjs` → `apps/api/tests/db/tenantIsolation.test.ts` (40 tests) and `rlsEnforcement.test.ts`.

**Interview questions**
1. *Why a transaction-local setting (`set_config(…, true)`) instead of a session-level `SET`?* — With a connection pool, a
   session-level setting would stay on the connection and leak into the next request for a different tenant. A
   transaction-local one ends with the transaction.
2. *How do you look up an API key before you know the tenant?* — Through a narrow `SECURITY DEFINER` function that takes a
   prefix and returns only what authentication needs. Once the key identifies the org, everything else runs under RLS.
3. *How did you test isolation?* — Two organizations with the same kinds of data, then every read and write path is tried
   across the boundary (40 tests), on PGlite and on a real PostgreSQL 18 server. The harness was mutation-checked (deliberately
   broken isolation must make tests fail), so a green run means the tests really depend on RLS. A separate suite
   (`rlsEnforcement.test.ts`) proves the gateway refuses to start as a role that would bypass RLS.

---

## 3. Refresh-token rotation with reuse detection

**What it is.** Login returns a short-lived JWT access token (15 min) and an opaque refresh token. Each refresh
**rotates**: the old refresh token is marked used and a new one is issued in the same *family*. If a token that was
already used is presented again, the whole family is revoked and an `auth.refresh_reuse_detected` event is written. Only a
hash of each refresh token is stored.

**Why.** Refresh tokens live for days, so theft is the main risk. With rotation, a stolen token is useful only until either
party uses it. If both the thief and the real user use it, the second use is a replay, and revoking the family logs out both,
which cuts the thief off. The rotation is a conditional update, so two concurrent refreshes of the same token cannot both succeed.

**Rejected alternatives.**
* *Long-lived access tokens with no refresh*: cannot be revoked short of a denylist checked on every request.
* *Non-rotating refresh tokens*: a stolen one works silently until it expires.

**What breaks without it.** A refresh token copied from a laptop or a log keeps producing access tokens for its whole
lifetime, and nothing ever notices. Separately, disabling a user now takes effect on the next request (sessions are
re-checked per request), not after the access token expires. That gap was found and fixed during v1.0 verification.

**Read:** `apps/api/src/services/authService.ts` (`refresh`) → `apps/api/src/repositories/authRepository.ts` (`rotate`, `revokeFamily`)
→ `scripts/database/migrations/0004_refresh_tokens.sql` → `apps/api/tests/db/authFlow.test.ts`.

**Interview questions**
1. *What happens if the legitimate client retries a refresh because of a network error?* — The retry replays a used token,
   so the family is revoked and the user must log in again. It is a deliberate trade-off (safety over convenience). Some
   systems allow a grace period of a few seconds; this one does not.
2. *Why store a hash of the refresh token?* — Same reason as API keys: a database leak must not yield working tokens.
3. *Why are access tokens JWTs but refresh tokens opaque?* — Access tokens are checked on every request, so a signature check
   without a database hit is useful. Refresh tokens are rare and must be revocable, so a database row is the right shape.

---

## 4. Fail-closed design

**What it is.** When a security dependency is down, slow or returns something unexpected, the request is **refused**
(`403` with `failed_closed: true` and a reason, or `503`), never passed through unscanned. This applies to the security
engine, token vault, document scanner, ClamAV, policy lookup, audit writes and the database. It also applies to the model's
reply: if the output scan fails, the reply is withheld.

**Why.** The product's promise is that sensitive data never reaches a model unless policy allows it. A gateway that
"degrades gracefully" by skipping the scan when the scanner is down breaks that promise exactly when an attacker can cause
an outage (for example by flooding the scanner).

**Rejected alternative.** *Fail-open* (log and continue). It keeps availability higher, but the security guarantee then depends
on uptime, and attackers can often influence uptime.

**What breaks without it.** An engine timeout, a vault restart or a ClamAV outage would silently turn into "everything is
allowed". Chaos testing (5 faults under load, over 1,600 requests) checks exactly this: no secret-bearing request gets
through in any fault.

**Read:** `apps/api/src/services/secureAiService.ts` → `apps/api/src/security/securityClient.ts` (`failClosedResult`) →
`services/security-engine/app/pipelines/scan_pipeline.py` (`FailClosed`) → `scripts/development/chaos.sh`.

**Interview questions**
1. *Isn't fail-closed bad for availability?* — Yes, by design. The mitigations are around it: timeouts and circuit breakers,
   so a dead dependency costs microseconds per request instead of hanging, plus health checks and restarts. Availability is
   engineered separately; it is never bought by skipping the security check.
2. *How do you tell a legitimate block from an outage?* — The response carries `failed_closed: true` and a machine-readable
   reason (`vault_unavailable`, `engine_timeout`…). The SDKs map this to a typed error, and the dashboard counts it separately.
3. *How did you prove it?* — Each dependency was stopped, frozen (`docker pause`), killed and network-partitioned while load
   ran, and an invariant was checked over every response: nothing secret-bearing was ever released.

---

## 5. Token vault: AES-256-GCM encryption with HKDF-derived per-session keys

**What it is.** With a `TOKENIZE` policy, a sensitive value (say an email address) is replaced by a token such as
`[TOK_EMAIL_1]` before the prompt goes to the model. When the reply comes back, the gateway swaps tokens back for the real
values ("hydration"). The vault stores the mapping in Redis with a 1-hour absolute TTL:
* A master key is expanded with **HKDF** (salt = hash of org + session) into per-session keys: an HMAC key and an AES key.
* The Redis field name is `HMAC(mac_key, value)`, so the keyspace does not reveal values.
* The value is sealed with **AES-256-GCM**, using the token as additional authenticated data (AAD), so a ciphertext cannot be
  moved onto another token.

**Why.** The model gets something it can reason about ("reply to [TOK_EMAIL_1]") without seeing the data. Per-session keys
mean the same email in another session or tenant gives an unrelated token and ciphertext, so a token is meaningless outside
its session. GCM detects tampering. Key ids allow master-key rotation without breaking live sessions.

**Rejected alternatives.**
* *Masking only (`j***@example.com`)*: safe, but irreversible, so the reply cannot be personalised.
* *One global key*: the same value would produce the same token everywhere, which is a cross-tenant correlation channel.
* *AES-CBC or unauthenticated encryption*: no tamper detection.

**What breaks without it.** Plaintext in Redis means a Redis compromise leaks every tokenized value. Deterministic global tokens
leak "these two tenants share this customer". If the vault is unreachable, the request is blocked (fail-closed, section 4);
the gateway never falls back to sending the raw value.

**Read:** `services/token-vault/app/crypto.py` → `services/token-vault/app/vault.py` → `services/token-vault/app/backend.py`
(timeouts, retries, circuit breaker, bounded blocking pool) → `apps/api/src/streaming/tokenWindow.ts` (hydration).

**Interview questions**
1. *Why HKDF instead of using the master key directly?* — So that each session and purpose has an independent key: a
   leaked session key exposes one session, and the two uses (MAC and encryption) never share a key.
2. *What is the AAD for?* — It binds the ciphertext to its token. Without it, someone with Redis write access could copy the
   ciphertext of a harmless value onto a different token and make the gateway hydrate the wrong data.
3. *What happens when Redis restarts?* — Sessions are lost (they are ephemeral by design, 1-hour TTL). Tokens in later
   replies stay as tokens, never guessed. New requests needing the vault fail closed until it is back.

---

## 6. Streaming output scanning (scan-before-release)

**What it is.** For `/v1/ai/stream`, the model's tokens are not forwarded as they arrive. The gateway keeps a look-ahead
buffer (`holdBack` characters) and only releases text that has been scanned **together with the text that follows it**. The
buffer is re-scanned as it grows, so a secret split across two chunks is seen whole before its first half leaves. A
separate 50-character sliding window hydrates vault tokens that may arrive split across network chunks.

**Why.** The model's reply can leak data too, for example by echoing a secret from its context. Scanning only the finished reply
would mean either no streaming (bad UX) or releasing unscanned text. The look-ahead is the compromise: small latency, and
nothing leaves unscanned.

**Rejected alternatives.**
* *Scanning each chunk on its own*: misses anything split across chunks, which a tokenizer does constantly.
* *Buffering the whole reply*: the safest option, and available as "buffered" mode, but it kills the point of streaming.

**What breaks without it.** A key like `AKIA…` streamed as `AKI` + `A…` would pass a per-chunk scanner. Known limit,
documented: a sensitive value longer than `holdBack` that only becomes detectable at its very end could have had its
beginning released. Buffered mode removes that risk.

**Read:** `apps/api/src/streaming/outputScreen.ts` → `apps/api/src/streaming/tokenWindow.ts` →
`apps/api/src/services/secureStreamService.ts` → `docs/security/streaming-and-tokenization.md`.

**Interview questions**
1. *How do you choose `holdBack`?* — It must exceed the longest pattern you need to see whole (keys, card numbers). Larger means
   safer and slower to first byte. It is configurable, and buffered mode is the safe limit.
2. *What if the client disconnects mid-stream?* — An `AbortController` cancels the upstream model call, and the partial
   output is still audited. Both are tested with real sockets.
3. *Why is hydration a separate window from scanning?* — They answer different questions: scanning decides what may be
   released; hydration only substitutes known tokens. Keeping them apart means a hydrated value is never re-scanned as
   model output, and a guessed token is never resolved.

---

## 7. Rate limiting: per-instance today, and the fix

**What it is.** `RateLimiter` in `apps/api/src/middleware/hardening.ts` is a fixed-window counter in the gateway's memory,
keyed by client IP (default 120/min; 600/min in the compose and Helm values), with stricter limiters on login/signup
(20/min per IP and 10/min per email address) and on file uploads (30/min).
`trustProxy` is off unless configured, so `X-Forwarded-For` cannot be spoofed to dodge it.

**The problem.** The counter is **per instance**. With N gateway replicas behind a load balancer, a client effectively gets
N × the limit (the Helm chart runs 2 replicas, so about 1,200/min). The limit also resets whenever a pod restarts.

**The fix (designed, NOT implemented).** Move the counter to Redis, which is already deployed for the vault: one atomic
`INCR` + `PEXPIRE` (a small Lua script) per request and window, keyed by `rl:<scope>:<ip or key>:<window>`. That gives one
shared limit for all replicas. It is not built because it is a new feature and outside this verification run. The honest
state today: correct on a single instance (verified: 573 of 700 served, 127 refused with `Retry-After`) and N× too permissive
with N replicas.

**Rejected alternatives.** *Sticky sessions* (clients can switch source IPs; they break with autoscaling). *Dividing the
limit by the replica count* (wrong whenever the replica count changes). *Rate limiting only at the ingress* (that is a
reasonable complement, but it cannot key by API key).

**What breaks without a fix.** Credential-guessing limits on login weaken linearly with the replica count. Per-key quotas can't
be enforced across the fleet.

**Read:** `apps/api/src/middleware/hardening.ts` → `apps/api/src/app.ts` (`trustProxy`) → `apps/api/src/routes/authRoutes.ts`
(auth limiter) → `scripts/development/ratelimit-verify.mjs`.

**Interview questions**
1. *Why fixed window and not token bucket?* — It is simple and cheap. Its weakness is a burst of up to 2× at the window
   boundary. A token bucket or sliding window smooths that, and in Redis it is a short Lua script either way.
2. *Why key by IP before authentication?* — Before the key is verified you don't know who the caller is, and limiting
   anonymous attempts is what slows credential guessing. After authentication, limits can key by API key.
3. *What if Redis is down: should the rate limiter fail closed too?* — For login, yes: refuse, because it protects credentials.
   For general traffic, many systems fail open to a local fallback limiter, since rate limiting protects capacity, not
   confidentiality. Whichever you pick, state it explicitly.

---

## 8. File-scanning defences: zip bombs, XXE, macros

**What it is.** `POST /v1/files/scan` runs a pipeline where every stage can block:
1. **Type by magic bytes, not by extension** (`file_validation/sniff.py`). Executables, scripts, legacy macro-capable Office
   files and unknown types are refused, and the extension must match the content.
2. **Malware scan** with ClamAV over its socket protocol (`malware/scanners.py`). Anything unexpected from ClamAV counts as an error,
   never as "clean".
3. **Safe ZIP access** for DOCX/XLSX (`file_validation/safe_zip.py`): caps on entries, total size, member size and
   **compression ratio** (a zip bomb inflates a tiny file into gigabytes). Reads are capped too, because header sizes can lie.
4. **XML parsed with defusedxml**, `forbid_dtd=True` (`parsers/ooxml.py`): no DTDs, no entity expansion (the
   "billion laughs" attack) and no external entities (**XXE**, which can read local files or reach internal URLs).
5. **Active content blocked**: `vbaProject.bin` (macros), embedded OLE objects, ActiveX, and external template/DDE relationships.
6. **Extraction in an isolated child process** (`extraction/isolated.py`) with time and memory limits, so a parser crash or
   hang kills only the child. **Image dimension checks run before OCR** (decompression-bomb images).
7. The extracted text then goes through **the same security engine and policy** as a prompt.

**Why.** Documents are the easiest way to smuggle data or attacks past a text-only gateway, and parsers are a classic
attack surface. Each layer assumes the one before it can be fooled.

**Rejected alternatives.** *Trusting the extension or Content-Type* (trivially spoofed). *Converting documents with a full
office suite* (a large attack surface, and slow). *Skipping the scan when the file is too complex* (fail-open).

**What breaks without it.** A 40 KB zip bomb exhausts memory. A DOCX with an external entity reads files from the scanner
host. A macro document is passed along to a model or user as "clean". A secret in a screenshot bypasses the text scanners
(hence OCR, verified with real Tesseract).

**Read:** `services/document-scanner/app/file_validation/sniff.py` → `safe_zip.py` → `parsers/ooxml.py` →
`extraction/isolated.py` → `malware/scanners.py` → `apps/api/src/services/fileScanService.ts` →
`services/document-scanner/tests/` (hostile synthetic files).

**Interview questions**
1. *How do you detect a zip bomb without decompressing it?* — Check the header sizes and ratio first, then enforce the same
   caps while reading (read `limit + 1` bytes and reject on overflow), because the headers can lie.
2. *What is XXE and how is it stopped here?* — An XML external entity makes the parser fetch a file or URL and inline it.
   defusedxml with `forbid_dtd=True` rejects any DTD, which blocks XXE and entity-expansion bombs at the root.
3. *Why a separate process for extraction?* — Parsers for PDF and Office formats are complex native code paths. A crafted
   file that crashes or hangs one must take down only a disposable child, never the service, and the pipeline treats a crash
   as a block.
