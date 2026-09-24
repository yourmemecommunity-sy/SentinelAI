# Task 4 — Real Redis

Run: **2026-09-26 07:50–08:31 UTC**.

| Check | Result |
|---|---|
| Token-vault suite against a real Redis server (`VAULT_TEST_REDIS_URL`, WSL-native **Redis 8.0.5**) | **112 passed, 0 failed, 0 skipped** |
| TTL: every session key gets the absolute expiry; the server really evicts it | Pass — unit test `test_redis_really_evicts_after_the_ttl` on the real server, and the live script below (PTTL 3,161 ms for a 3 s TTL: expiry is rounded **up** to the next whole second so Redis never evicts early; the exact deadline is enforced by the vault itself) |
| Circuit breaker against a **real, frozen** Redis (`docker pause`) | Pass — first 5 calls fail closed after ~515 ms each (0.25 s timeout × 2 attempts), then the breaker opens and calls fail in ~0.01–0.1 ms; still open right after Redis returns; recovers after the 2 s cooldown |
| The running `token-vault` service uses the compose Redis | `VAULT_BACKEND=redis` in the container; its readiness is part of `/ready` (step 2) |

The unit tests drive the breaker with injected failing clients; `scripts/development/vault-breaker-live.py` was added so the
breaker is also proven against a real server that stops answering. Its first run had a wrong bound in the harness (it
expected PTTL ≤ 3,000 ms and ignored the documented round-up); the bound was corrected, not the product.

## Live breaker + TTL run
```
# Token vault circuit breaker + TTL against a real Redis (2026-09-26T08:32:25Z)
real Redis 7.4.11 at redis://127.0.0.1:6390/0; op timeout 0.25s, retries 1, breaker threshold 5, cooldown 2.0s

PASS TTL is set on every key the session wrote
     token [TOK_EMAIL_1]; 3 Redis keys, PTTL(ms)=[3162, 3161, 3161]
PASS after the TTL the real server has evicted the session and the token no longer resolves
     keys left: 0; resolve -> {}
PASS healthy Redis: tokenize works
     ok in 7.2 ms
     frozen Redis, call 1: unavailable (vault store unavailable) in 523.2 ms
     frozen Redis, call 2: unavailable (vault store unavailable) in 526.4 ms
     frozen Redis, call 3: unavailable (vault store unavailable) in 522.3 ms
     frozen Redis, call 4: unavailable (vault store unavailable) in 509.3 ms
     frozen Redis, call 5: unavailable (vault store unavailable) in 509.9 ms
     frozen Redis, call 6: unavailable (vault store unavailable (circuit open)) in 0.1 ms
     frozen Redis, call 7: unavailable (vault store unavailable (circuit open)) in 0.0 ms
     frozen Redis, call 8: unavailable (vault store unavailable (circuit open)) in 0.0 ms
PASS every call fails closed while Redis is frozen (never a silent success)
     
PASS the first failures wait for the timeout (bounded, no hang)
     [523, 526, 522, 509, 510] ms
PASS after 5 consecutive failures the breaker OPENS: calls fail in microseconds
     [0.06, 0.01, 0.01] ms
PASS right after Redis returns, the breaker is still open (cooldown)
     unavailable (vault store unavailable (circuit open)) in 0.07 ms
PASS after the cooldown the breaker lets a trial call through and the vault recovers
     ok in 13.7 ms

VAULT BREAKER (REAL REDIS): ALL PASSED
[exit 0]
```

## Suite run
```
# STEP 4 - Real Redis  (2026-09-26T07:50:36Z)
server: redis_version:8.0.5 (WSL-native Redis, not fakeredis)

## Token-vault suite with VAULT_TEST_REDIS_URL (every test that takes the redis fixture talks to the real server)
pytest -> exit 0
============================= 112 passed in 5.49s ==============================

## TTL expiry and circuit-breaker tests (from the run above)
tests/test_api_and_settings.py::test_outage_is_503_and_ready_reflects_it PASSED [ 10%]
tests/test_api_and_settings.py::test_ttl_bounds_and_backend_values PASSED [ 14%]
tests/test_detokenize.py::test_vault_outage_degrades_to_unhydrated_tokens_and_recovers PASSED [ 29%]
tests/test_detokenize.py::test_json_outage_raises_by_default_and_can_pass_through PASSED [ 34%]
tests/test_resilience.py::test_connection_errors_are_retried_once_then_reported_as_unavailable PASSED [ 36%]
tests/test_resilience.py::test_the_circuit_breaker_opens_after_repeated_failures_and_recovers PASSED [ 39%]
tests/test_resilience.py::test_breaker_uses_its_clock PASSED             [ 41%]
tests/test_vault.py::test_ttl_is_applied_to_all_three_hashes PASSED      [ 77%]
tests/test_vault.py::test_reads_do_not_touch_the_ttl PASSED              [ 79%]
tests/test_vault.py::test_past_the_deadline_nothing_resolves_even_if_redis_has_not_evicted_yet PASSED [ 80%]
tests/test_vault.py::test_writing_after_expiry_starts_a_fresh_session PASSED [ 81%]
tests/test_vault.py::test_redis_really_evicts_after_the_ttl PASSED       [ 82%]

## The running token-vault service uses the compose Redis (live stack)
VAULT_BACKEND=redis
```
