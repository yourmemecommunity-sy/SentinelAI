# 13 — Revoking an API key in the middle of a stream

**Question.** An API key is checked when a request starts. If the key is revoked while its `/v1/ai/stream` reply is still
flowing, does the reply stop? Measured before and after adding "quarantine on revoke", under concurrent load.

## 1. Method

`scripts/security/run-stream-revocation-test.sh <label>` against the running Docker stack (WSL2, i5-13420H, 12 vCPU, one
engine worker; load generator on the same machine):

* A mock Ollama (`scripts/development/perf/mock-ollama.mjs`, `MOCK_STREAM_TOKENS=400 MOCK_TOKEN_MS=25`) streams 400 numbered
  words, one every 25 ms. For every second trial (`LEAKTEST` prompts) it emits a fake credential-shaped value at 70 % of the
  reply, so the output checks have something to stop late in the stream.
* The gateway is recreated pointing at the mock, with the per-IP rate limit lifted (one load generator); restored afterwards.
* `scripts/security/stream-revocation-test.mjs` signs up a throwaway organization, then runs **24 trials, 4 at a time**. Each
  opens a stream with its own fresh API key, waits **1.5 s after the first delta**, revokes the key with
  `DELETE /v1/api-keys/:id` (a user session), and keeps reading. Meanwhile **16 background streams** on other keys run
  continuously: that is the concurrent load and the latency baseline.
* "After revocation" means after the DELETE returned 204. Only counts and timings are recorded, never content.

Raw results: [before.json](stream-revocation/before.json), [after.json](stream-revocation/after.json),
[after-light.json](stream-revocation/after-light.json).

## 2. Before: the reply keeps flowing

Gateway image of 2026-10-04 (before the change), full stack.

| Measure | Result |
|---|---|
| Streams that kept delivering text after revocation | **22 of 24** (the other 2 failed closed on the engine's time budget ~1.6 s after the revoke, by chance) |
| Words delivered after revocation | **5,723 in total**; per stream median 181, p95 364, max 364 |
| Characters delivered after revocation | 27,555 |
| Last word arrived after revocation (median · p95 · max) | **11.4 s · 15.1 s · 18.4 s** |
| Final events | 11 `done`, 13 `error/blocked` (11 fake credentials stopped by the hold-back scan, 2 engine time-budget fail-closes under load) |
| Fake credential reached a client | 0 (the existing output checks stopped it) |
| The revoked key used for a new request | refused (401) in 24 of 24 |

So revocation stopped *new* requests, but not the reply already streaming: a revoked key kept receiving text until the
provider finished.

## 3. The change

`RevocationWatcher` (`apps/api/src/security/revocationWatcher.ts`) plus quarantine in
`apps/api/src/services/secureStreamService.ts`. Design and limits: [streaming-and-tokenization.md](../security/streaming-and-tokenization.md#quarantine-on-revoke);
decisions D49–D54. In short: the revoke route notifies open streams on that instance at once (a 1 s batched poll covers other
replicas, expiry and deleted keys; a failed check quarantines too). From the next chunk nothing is released. The provider
finishes into a server-side buffer, the complete reply is scanned once with the output checks, and the unseen rest is
released (clean, release enabled, outcome audited) or dropped. The stream ends with `stream_quarantined`; every outcome is
an `audit_logs` row `stream.quarantine` without content. Output cap, idle timeout, maximum duration, provider errors and
client disconnects all drop.

## 4. After: same test, same load

Gateway image built from the change (2026-10-06 17:33 UTC), full stack.

| Measure | Before | **After** |
|---|---|---|
| Streams that kept delivering text after revocation | 22 of 24 | **0 of 24** |
| Words delivered after revocation (ordinary deltas) | 5,723 | **0** |
| Last word after revocation (median · max) | 11.4 s · 18.4 s | **— (none)** |
| Stream end after revocation (median · p95 · max) | 12.2 s · 15.1 s · 18.4 s | 8.9 s · 9.1 s · 9.2 s (the provider finishes into the buffer) |
| Words released after the whole-reply scan | — | 714 (2 streams) |
| Final events | 11 `done`, 13 `blocked` | **24 `stream_quarantined`**: 2 released, 22 dropped |
| Fake credential reached a client | 0 | 0 |
| The revoked key used for a new request | 401 in 24 of 24 | 401 in 24 of 24 |
| Revoke call (p50 · p95) | 37 · 349 ms | 32 · 39 ms |

**Why 22 were dropped.** The audit log (`stream.quarantine` rows) gives the reason for each:

| Outcome | Detail | Count |
|---|---|---|
| dropped | `timeout`: the engine's own time budget (1.5 s + 45 ms per 1,000 chars) ran out on the ~1,700-character whole-reply scan | 20 |
| dropped | `policy_block`: the fake credential was in the reply | 2 |
| released | — | 2 |

With 16 background streams plus 4 trials sharing one engine worker, the small hold-back scans still fit the budget (all 80
background streams ended `done`), but one large scan did not. The fail-closed path did its job: nothing was leaked. The
budget was deliberately not raised (D54). This is a capacity limit of the whole-reply scan, listed in the threat model.

**Latency impact on streams that are not revoked** (background streams, same load):

| | Before | After |
|---|---|---|
| First word (p50 · p95 · p99) | 2,925 · 3,632 · 3,893 ms | 2,731 · 3,833 · 4,051 ms |
| Full reply (p50 · p95 · p99) | 18,379 · 24,491 · 24,621 ms | 18,084 · 20,925 · 21,178 ms |
| Final events | 112 `done` | 80 `done` |

No measurable cost: the watcher is a map lookup per stream, and the batched poll is one query per organization per second.
(The two runs differ in how many background streams completed in the test window; run-to-run variance on this laptop is large.)

### 4.1 After, lighter load (4 background streams instead of 16)

Same image, same 24 trials; only `BG_STREAMS=4`, to see the release/drop split when the engine is not saturated.

| Measure | Result |
|---|---|
| Words delivered after revocation | **0** (0 of 24 streams) |
| Outcomes | **12 released** (every clean prompt) · **12 dropped, `policy_block`** (every prompt with the fake credential) · 0 timeouts |
| Words released after the whole-reply scan | 3,792 |
| Stream end after revocation (median · max) | 6.6 s · 6.8 s |
| Fake credential reached a client | 0 |
| Background streams: first word · full reply (p50) | 2.3 s · 10.4 s; 28 of 28 `done` |

So the release/drop decision works as designed when the engine has headroom; the 20 drops in §4 are load, not logic.
No "before" run was made at this lighter load, so it has no latency comparison.

## 5. Tests

`apps/api/tests/streaming/revocation.test.ts` (19 tests: release, drop by policy, engine fail-closed, release disabled, audit
missing or failing, output cap, idle timeout, provider error, maximum duration, client disconnect, revocation before the first
byte, unverifiable key, no revocation, revocation after the end, wire format; the watcher's notify, poll, fail-closed check,
unsubscribe and isolation of a throwing subscriber), `tests/streaming/streamRoute.test.ts` (over HTTP with hydration: at most one
in-flight segment, then the release, the audit row, the subscription released; a stream on another key unaffected),
`tests/db/apiKeyManagement.test.ts` (the revoke route notifies open streams; `revokedAmong` on PGlite: revoked, expired,
unknown and other-organization keys).

Two bugs were found by these tests and fixed before any measurement (D52, D53): a revocation between `open()` and the first
read was missed, and a quarantined reply that needed hydration was released empty.
