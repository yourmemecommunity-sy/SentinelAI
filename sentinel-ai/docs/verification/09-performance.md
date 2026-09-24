# Task 9 — Performance: gateway overhead and throughput

Run: **2026-09-27**, `bash scripts/development/perf-bench.sh 30` (k6 `grafana/k6:0.54.0`) against the Docker stack in WSL2.
**No suspend during the run** (wall time 497 s = VM uptime 497 s). **0 failed requests in all 12 measured runs**; every
response was checked for the expected status, verdict and content.

## Hardware and method

* **One laptop:** 13th Gen Intel Core i5-13420H, **12 vCPU / 7 GiB** visible to the WSL2 Docker VM, Docker 29.1.3. The load
  generator, gateway, security engine, token vault, Postgres (audit writes), Redis and the mock all share this machine.
  Absolute numbers are therefore conservative, and the load generator itself takes CPU from the system under test.
* **Mocked fast provider:** a tiny Ollama-compatible server (`scripts/development/perf/mock-ollama.mjs`) answers
  `/api/chat` instantly. The gateway's real Ollama adapter is pointed at it, so model time is ~0 and only gateway +
  engine + audit cost is measured. The per-IP rate limit is lifted for the benchmark only (one load generator = one IP),
  then restored (decision D9).
* **Paths:** `direct` = k6 → mock (the provider hop a client would pay anyway); `chat` = `POST /v1/ai/chat`, clean prompt
  (API-key auth → input scan → policy → provider → output scan → audit); `chat_pii` = same with an email (MASK path);
  `scan` = `POST /v1/security/scan` (auth → engine → audit, no provider).
* 30 s per run after a 10 s warm-up, at 1, 8 and 32 concurrent virtual users (VUs).

## Headline

| | p50 | p95 | p99 |
|---|---|---|---|
| **Latency the gateway adds to a chat request** (1 request in flight, `chat` − `direct`) | **42.4 ms** | **55.7 ms** | **84.1 ms** |
| Same, with PII masking | 44.0 ms | 63.5 ms | 107.4 ms |
| A standalone scan (`/v1/security/scan`, 1 in flight) | 22.9 ms | 32.3 ms | 52.9 ms |

| Throughput (saturated, 8–32 VUs) | req/s |
|---|---|
| `/v1/ai/chat` (two engine scans + provider + audit per request) | **≈ 44–68** |
| `/v1/security/scan` | **≈ 127–129** |

Reading: a chat costs about two scans (the input and the output are both scanned) plus audit writes. Beyond ~8 concurrent
requests the system is saturated on this machine, and extra concurrency only adds queueing: p50 grows to ~450 ms at 32 VUs
with no gain in throughput. Which component saturates first (gateway event loop, engine, Postgres audit writes, or the
load generator competing for the same CPUs) was **not profiled**; nothing was scaled out for this measurement.

## All runs
### Results (latency in ms as seen by the client; rps = completed requests per second)
| run | requests | ok checks | p50 | p95 | p99 | max | req/s |
|---|---|---|---|---|---|---|---|
| chat_pii_vu1 | 629 | 100.00% (0 failed) | 44.43 | 64.34 | 108.56 | 625.6 | 20.8 |
| chat_pii_vu32 | 1934 | 100.00% (0 failed) | 478.78 | 721.29 | 852.08 | 1481.5 | 62.9 |
| chat_pii_vu8 | 2068 | 100.00% (0 failed) | 109.85 | 185.24 | 225.14 | 582.7 | 68.3 |
| chat_vu1 | 671 | 100.00% (0 failed) | 42.75 | 56.48 | 85.23 | 188.9 | 22.2 |
| chat_vu32 | 2053 | 100.00% (0 failed) | 446.61 | 668.20 | 844.44 | 1226.9 | 67.1 |
| chat_vu8 | 1330 | 100.00% (0 failed) | 156.34 | 334.29 | 540.40 | 1252.3 | 43.8 |
| direct_vu1 | 50387 | 100.00% (0 failed) | 0.39 | 0.83 | 1.16 | 13.6 | 1679.5 |
| direct_vu32 | 352658 | 100.00% (0 failed) | 2.29 | 4.87 | 6.84 | 49.5 | 11754.1 |
| direct_vu8 | 337998 | 100.00% (0 failed) | 0.48 | 1.40 | 2.51 | 29.9 | 11266.3 |
| scan_vu1 | 1232 | 100.00% (0 failed) | 22.90 | 32.29 | 52.87 | 208.1 | 40.8 |
| scan_vu32 | 3849 | 100.00% (0 failed) | 242.40 | 315.35 | 360.76 | 464.3 | 126.6 |
| scan_vu8 | 3900 | 100.00% (0 failed) | 57.97 | 91.65 | 116.85 | 232.1 | 128.7 |

### Gateway overhead = gateway path minus the direct provider hop (same concurrency)
| concurrency | path | p50 overhead | p95 overhead | p99 overhead |
|---|---|---|---|---|
| 1 | chat | 42.36 | 55.65 | 84.07 |
| 1 | chat_pii | 44.04 | 63.51 | 107.40 |
| 8 | chat | 155.86 | 332.90 | 537.89 |
| 8 | chat_pii | 109.37 | 183.85 | 222.63 |
| 32 | chat | 444.32 | 663.33 | 837.60 |
| 32 | chat_pii | 476.49 | 716.43 | 845.24 |

Non-OK responses: **none**.

## Caveats (honest)

* **Run-to-run variance is visible**: `chat` at 8 VUs (p50 156 ms, 44 req/s) came out slower than the heavier `chat_pii`
  at 8 VUs (110 ms, 68 req/s). With everything on one laptop, background activity moves individual runs by tens of percent.
  Treat the numbers as ranges, not constants.
* An earlier attempt (2026-09-26) was **discarded**: the laptop suspended for ~40 min mid-run (wall 2,915 s vs VM 494 s),
  and in that attempt 18 of 2,391 `chat_pii` requests at 32 VUs were not OK. They did not reproduce in this clean run
  (0 of 1,934). The harness now logs the status and reason of any non-OK response so a recurrence can be diagnosed.
* The v1.0 release report quoted ~145–185 req/s for scans. That figure came from a different harness (`load-test.mjs`) and
  mix, and it is not directly comparable to the ≈128 req/s here.
* Single gateway replica, single engine process; no horizontal scaling, no soak (runs are 30 s).

## Raw output
```
READY: api=running/healthy clamav=running/healthy dashboard=running/healthy document-scanner=running/healthy migrate=exited/ ollama=running/healthy policy-engine=running/healthy postgres=running/healthy redis=running/healthy security-engine=running/healthy token-vault=running/healthy 
## Hardware / software
CPU: 13th Gen Intel(R) Core(TM) i5-13420H — 12 vCPU visible to the Docker VM; RAM 7 GiB
Docker 29.1.3; every component (load generator, gateway, engine, Postgres, vault, mock) shares this one machine

## Warm-up (discarded)
  warmup: exit 0
## Measured runs (30s each)
  direct_vu1: exit 0
  chat_vu1: exit 0
  chat_pii_vu1: exit 0
  scan_vu1: exit 0
  direct_vu8: exit 0
  chat_vu8: exit 0
  chat_pii_vu8: exit 0
  scan_vu8: exit 0
  direct_vu32: exit 0
  chat_vu32: exit 0
  chat_pii_vu32: exit 0
  scan_vu32: exit 0

## Results (latency in ms as seen by the client; rps = completed requests per second)
| run | requests | ok checks | p50 | p95 | p99 | max | req/s |
|---|---|---|---|---|---|---|---|
| chat_pii_vu1 | 629 | 100.00% (0 failed) | 44.43 | 64.34 | 108.56 | 625.6 | 20.8 |
| chat_pii_vu32 | 1934 | 100.00% (0 failed) | 478.78 | 721.29 | 852.08 | 1481.5 | 62.9 |
| chat_pii_vu8 | 2068 | 100.00% (0 failed) | 109.85 | 185.24 | 225.14 | 582.7 | 68.3 |
| chat_vu1 | 671 | 100.00% (0 failed) | 42.75 | 56.48 | 85.23 | 188.9 | 22.2 |
| chat_vu32 | 2053 | 100.00% (0 failed) | 446.61 | 668.20 | 844.44 | 1226.9 | 67.1 |
| chat_vu8 | 1330 | 100.00% (0 failed) | 156.34 | 334.29 | 540.40 | 1252.3 | 43.8 |
| direct_vu1 | 50387 | 100.00% (0 failed) | 0.39 | 0.83 | 1.16 | 13.6 | 1679.5 |
| direct_vu32 | 352658 | 100.00% (0 failed) | 2.29 | 4.87 | 6.84 | 49.5 | 11754.1 |
| direct_vu8 | 337998 | 100.00% (0 failed) | 0.48 | 1.40 | 2.51 | 29.9 | 11266.3 |
| scan_vu1 | 1232 | 100.00% (0 failed) | 22.90 | 32.29 | 52.87 | 208.1 | 40.8 |
| scan_vu32 | 3849 | 100.00% (0 failed) | 242.40 | 315.35 | 360.76 | 464.3 | 126.6 |
| scan_vu8 | 3900 | 100.00% (0 failed) | 57.97 | 91.65 | 116.85 | 232.1 | 128.7 |

## Gateway overhead = gateway path minus the direct provider hop (same concurrency)
| concurrency | path | p50 overhead | p95 overhead | p99 overhead |
|---|---|---|---|---|
| 1 | chat | 42.36 | 55.65 | 84.07 |
| 1 | chat_pii | 44.04 | 63.51 | 107.40 |
| 8 | chat | 155.86 | 332.90 | 537.89 |
| 8 | chat_pii | 109.37 | 183.85 | 222.63 |
| 32 | chat | 444.32 | 663.33 | 837.60 |
| 32 | chat_pii | 476.49 | 716.43 | 845.24 |

## Non-OK responses (status + reason), if any

wall 497s vs VM uptime delta 497s (equal = no suspend during the run)
```
