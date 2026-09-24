# Benchmark (baseline policy, dataset v1.0)

Measured on the developer machine with `python scripts/security/run_evaluation.py` (Windows 11, Python 3.13, single process).
Reproduce with the same command; numbers below are from the last recorded run and must be refreshed after detector changes.

| Metric | Value |
|---|---|
| Records | 524 (464 critical, 50 benign controls, 10 non-critical) |
| Critical failures | **0 / 464** |
| Recall / detection rate | 1.000 |
| Precision | 1.000 |
| False-negative rate | 0.000 |
| False-positive rate (benign) | 0.000 |
| Policy accuracy | 1.000 |
| Latency (engine, per scan) | p50 0.42 ms, p95 1.26 ms, max ~39 ms (cold start) |

**Interpretation caveat:** these are results on a self-authored suite (see [methodology](methodology.md#threats-to-validity-read-before-trusting-the-numbers)).
Three defects were found and fixed by this suite during development (Maestro-range card prefixes, an over-broad exfiltration rule,
short-word spaced-letter obfuscation) and are pinned in `tests/regression/`.
