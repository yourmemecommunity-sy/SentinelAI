# PII improvement cycle — NER layer, card/IMEI fix, SSN and date-of-birth context (measured)

Run: **2026-09-28 → 2026-09-29**. One measured improvement cycle on the PII detectors, against the held-out numbers in
[10-pii-secrets-evaluation.md](10-pii-secrets-evaluation.md).

## Rules followed

* **Tuning used only the TRAIN splits** of ai4privacy `pii-masking-400k` / `pii-masking-300k` (English, same pinned revisions),
  via `run_data_leakage_evaluation.py --suite pii --split train --sample 6000`, a fixed seeded sample.
* **The held-out VALIDATION splits were read once**, for the final measurement below, after every detector change was
  final. Both files still match their pinned SHA-256.
* **Fail-closed kept and extended**: if the NER model cannot be loaded, `/ready` answers 503 and every scan is refused
  (`detector_unavailable:ner`). Production refuses to start with NER switched off. Any exception inside NER is a
  fail-closed `detector_error:ner:…`.
* **No existing test or detector was weakened.** Every existing engine test passes unchanged (132 existing + 29 new = 161).
  The self-authored evaluation gate still passes, and the card detector only got stricter (see "Honest caveats").

## What changed

| # | Change | Where |
|---|---|---|
| 1 | **Credit card**: issuer-prefix **and issued-length** rules per network (Visa, Mastercard incl. 2-series, Amex, Diners, JCB, Discover, UnionPay, Maestro, RuPay) and rejection right after device-ID words (IMEI/MEID/serial). IMEIs are 15 digits with a Luhn check digit, so Luhn + prefix alone cannot separate them from cards | `app/detectors/financial/detector.py` |
| 2 | **NER layer**: spaCy `en_core_web_md`, run locally. PERSON → `NAME` (MEDIUM, masked by default); GPE/LOC → `LOCATION` (LOW: detected and audited, allowed by default, maskable by policy). It covers the whole input in overlapping 5k-char windows and filters obvious model noise (digits, URLs, markup, lowercase, short acronyms, compass words, temperature units) | `app/detectors/ner/`, registry, settings |
| 3 | **SSN vs phone**: a 9–13 digit number with separators right after "social security number", "social number", "SIN", "national insurance"… is an SSN, and a number reported as an SSN is not also reported as a phone | `app/detectors/pii/detector.py` |
| 4 | **Date of birth**: more formats (ISO date-times, "May 5th, 1966", "January/88", "5th of May 1966") and a 60-char window after birth-related words (it used to be 30, too short across markup such as `Date of birth: <strong>`) | `app/detectors/pii/detector.py` |
| 5 | **Length-aware time budgets** (engine 1.5 s + 45 ms per 1,000 chars; gateway 2 s + 60 ms per 1,000 chars): NER costs ≈18 ms per 1,000 chars, and a flat budget would have failed every document over ~80k characters closed | `app/pipelines/scan_pipeline.py`, `apps/api/src/security/securityClient.ts` |
| 6 | **Verification of NER sanitization is value-based**: the post-masking re-scan fails closed if a *sanitized name or place* survives. It no longer fails when the contextual model tags a *different* word in the altered text, which had blocked ~1.2 % of records | `scan_pipeline.py` (D19) |
| 7 | **The engine's own placeholders are not context words**: "[DATE_OF_BIRTH_MASKED]" contains "BIRTH" and caused false re-scan failures. This also halves a pre-existing driver-licence variant | `app/detectors/base.py` (D20) |
| 8 | `NAME`, `LOCATION` added in lockstep to the TypeScript shared types (the gateway rejects unknown entity types from the engine, which would fail closed), the OpenAPI enum and the dashboard's PII set. The token vault already allowed both | `packages/shared-types`, `docs/api/openapi.yaml`, `apps/dashboard` |

## NER model selection (train split only)

1,500 random **train** records (750 per dataset), WSL2, 12 vCPU, spaCy 3.8.16, Presidio 2.2.364. Person spans =
given names and surnames; location spans = city / state / country.

| Candidate | Person recall / precision / F1 | Location F1 | p50 / p95 / p99 per record | Peak RSS | Package |
|---|---|---|---|---|---|
| spaCy `en_core_web_sm` | 0.29 / 0.30 / 0.30 | 0.34 | 10.6 / 19.4 / 26.9 ms | 146 MiB | 15 MB |
| **spaCy `en_core_web_md`** (chosen) | **0.42 / 0.38 / 0.40** | **0.43** | **11.7 / 21.5 / 30.5 ms** | **357 MiB** | **57 MB** |
| spaCy `en_core_web_lg` | 0.40 / 0.42 / 0.41 | 0.49 | 10.9 / 20.2 / 31.2 ms | 743 MiB | 445 MB |
| Presidio + `sm` | same as `sm` | same as `sm` | 16.1 / 33.7 / 52.9 ms | — | — |
| Presidio + `lg` | same as `lg` | same as `lg` | 17.3 / 33.3 / 46.3 ms | — | — |

`md` was chosen (D16). It is within 1 F1 point of `lg` on names and 5 on locations, at the same latency, with half the memory and
an 8× smaller download. `lg` would need roughly 3× the engine's 512 MB memory limit. Presidio runs the same spaCy model with
identical accuracy and 50–60 % more latency. A transformer model was not tried: it needs PyTorch and is far slower on CPU.

## Card / IMEI fix (train split)

On the 6,000-record train sample of `pii-masking-400k`, card detections on text the dataset did not label went from **105 to 26**.
Two labelled "cards" were no longer detected: a `35…` 16-digit number outside JCB's 3528–3589 range and a `22…` number
outside Mastercard's 2221–2720 range. Neither is a validly issued card number. Only **10 % of the dataset's labelled card
numbers pass the Luhn checksum** (they are random digits). Real cards always do, so the detector keeps requiring Luhn, and
card recall on this dataset is capped near 10 % by the labels, not by the detector.

Regression tests: synthetic IMEIs (valid Luhn, 15 digits) are never cards, with or without "IMEI" nearby; one synthetic card per
network is still detected at its issued lengths; mutation check: with the old prefix-only rule, 3 of these tests fail.

## Held-out result (validation splits, read once, after tuning)

### ai4privacy/pii-masking-400k (validation, 17,046 records)

| | Before | After |
|---|---|---|
| **PII-bearing records allowed through unchanged (ALLOW)** | **67.8 %** | **47.2 %** |
| Scans failed closed (blocked, no detections) | 5 | 3 |

| Label | Spans | Detector | Detection before | Detection after | Caught by any detector before → after |
|---|---|---|---|---|---|
| GIVENNAME | 2,947 | NAME | — | 48.4 % | 0.0 % → 53.4 % |
| SURNAME | 2,143 | NAME | — | 50.4 % | 0.0 % → 54.1 % |
| CITY | 1,955 | LOCATION | — | 46.0 % | 0.1 % → 64.5 % |
| USERNAME | 1,847 | none | — | — | 0.1 % → 0.6 % |
| EMAIL | 1,592 | EMAIL | 99.3 % | 99.3 % | 99.3 % → 99.3 % |
| TELEPHONENUM | 1,264 | PHONE | 62.7 % | 62.7 % | 62.9 % → 63.0 % |
| BUILDINGNUM | 1,006 | ADDRESS | 8.5 % | 8.5 % | 8.5 % → 8.5 % |
| IDCARDNUM | 1,003 | none | — | — | 5.7 % → 5.3 % |
| ACCOUNTNUM | 962 | BANK_ACCOUNT | 21.3 % | 21.5 % | 23.3 % → 23.1 % |
| ZIPCODE | 909 | ADDRESS | 0.0 % | 0.0 % | 0.0 % → 0.0 % |
| DATEOFBIRTH | 859 | DATE_OF_BIRTH | 19.9 % | 41.7 % | 19.9 % → 41.7 % |
| STREET | 816 | ADDRESS | 10.1 % | 10.1 % | 10.1 % → 33.1 % |
| SOCIALNUM | 730 | SSN | 35.5 % | 57.4 % | 72.9 % → 81.5 % |
| PASSWORD | 657 | PASSWORD | 8.7 % | 8.7 % | 8.7 % → 9.3 % |
| TAXNUM | 573 | none | — | — | 38.0 % → 38.2 % |
| DRIVERLICENSENUM | 531 | DRIVER_LICENSE | 31.3 % | 31.3 % | 33.1 % → 33.9 % |
| CREDITCARDNUMBER | 405 | CREDIT_CARD | 11.6 % | 9.9 % | 13.3 % → 11.6 % |

| Engine entity | Detections before → after | On unlabelled text (FP upper bound) before → after |
|---|---|---|
| NAME | — → 4,449 | — → 36.2 % (1,610) |
| LOCATION | — → 2,820 | — → 57.1 % (1,609) |
| EMAIL | 1,582 → 1,582 | 0.0 % (0) → 0.0 % (0) |
| PHONE | 1,409 → 1,313 | 4.6 % (65) → 5.0 % (65) |
| SSN | 467 → 630 | 0.2 % (1) → 0.2 % (1) |
| DATE_OF_BIRTH | 173 → 369 | 1.2 % (2) → 2.7 % (10) |
| BANK_ACCOUNT | 298 → 301 | 24.8 % (74) → 24.6 % (74) |
| DRIVER_LICENSE | 168 → 168 | 1.2 % (2) → 1.2 % (2) |
| CREDIT_CARD | 397 → 115 | 82.9 % (329) → 58.3 % (67) |
| ADDRESS | 86 → 86 | 0.0 % (0) → 0.0 % (0) |
| PASSWORD | 60 → 60 | 5.0 % (3) → 5.0 % (3) |
| AADHAAR | 21 → 21 | 9.5 % (2) → 9.5 % (2) |
| HIGH_ENTROPY_SECRET | 12 → 12 | 100.0 % (12) → 100.0 % (12) |
| DATA_EXFILTRATION | 7 → 7 | 0.0 % (0) → 0.0 % (0) |
| PROMPT_INJECTION | 2 → 2 | 100.0 % (2) → 100.0 % (2) |

### ai4privacy/pii-masking-300k (validation, 7,946 records)

| | Before | After |
|---|---|---|
| **PII-bearing records allowed through unchanged (ALLOW)** | **47.1 %** | **32.9 %** |
| Scans failed closed (blocked, no detections) | 51 | 19 |

| Label | Spans | Detector | Detection before | Detection after | Caught by any detector before → after |
|---|---|---|---|---|---|
| TIME | 3,766 | none | — | — | 0.1 % → 0.1 % |
| USERNAME | 2,786 | none | — | — | 0.4 % → 1.1 % |
| IDCARD | 2,656 | none | — | — | 4.6 % → 4.3 % |
| EMAIL | 2,612 | EMAIL | 98.5 % | 99.0 % | 98.5 % → 99.0 % |
| SOCIALNUMBER | 2,554 | SSN | 29.9 % | 64.6 % | 63.8 % → 79.6 % |
| PASSPORT | 2,424 | PASSPORT | 3.3 % | 3.4 % | 4.9 % → 5.7 % |
| DRIVERLICENSE | 2,420 | DRIVER_LICENSE | 53.8 % | 56.1 % | 55.8 % → 58.4 % |
| LASTNAME1 | 2,416 | NAME | — | 34.6 % | 0.1 % → 37.5 % |
| BOD | 2,317 | DATE_OF_BIRTH | 24.8 % | 65.0 % | 24.9 % → 65.4 % |
| IP | 2,166 | none | — | — | 0.0 % → 1.0 % |
| GIVENNAME1 | 2,019 | NAME | — | 33.7 % | 0.0 % → 36.1 % |
| CITY | 2,017 | LOCATION | — | 31.9 % | 0.0 % → 54.2 % |
| SEX | 2,010 | none | — | — | 0.1 % → 1.6 % |
| STATE | 2,002 | LOCATION | — | 17.7 % | 0.0 % → 19.3 % |
| TEL | 1,997 | PHONE | 63.0 % | 63.4 % | 63.0 % → 63.6 % |
| BUILDING | 1,943 | ADDRESS | 2.5 % | 2.6 % | 2.5 % → 2.6 % |
| TITLE | 1,926 | none | — | — | 0.3 % → 8.7 % |
| STREET | 1,910 | ADDRESS | 2.8 % | 2.8 % | 2.8 % → 25.4 % |
| POSTCODE | 1,907 | ADDRESS | 0.0 % | 0.0 % | 0.0 % → 0.1 % |
| DATE | 1,702 | none | — | — | 0.2 % → 1.6 % |
| PASS | 1,620 | PASSWORD | 39.5 % | 39.5 % | 39.7 % → 39.8 % |
| COUNTRY | 1,565 | LOCATION | — | 51.4 % | 0.0 % → 51.9 % |
| SECADDRESS | 859 | ADDRESS | 0.0 % | 0.0 % | 0.1 % → 0.5 % |
| LASTNAME2 | 634 | NAME | — | 39.9 % | 0.2 % → 43.1 % |
| GIVENNAME2 | 539 | NAME | — | 37.1 % | 0.0 % → 41.0 % |
| GEOCOORD | 216 | none | — | — | 0.0 % → 0.5 % |
| LASTNAME3 | 200 | NAME | — | 36.5 % | 0.0 % → 41.0 % |
| CARDISSUER | 1 | none | — | — | 0.0 % → 100.0 % |

| Engine entity | Detections before → after | On unlabelled text (FP upper bound) before → after |
|---|---|---|
| NAME | — → 3,194 | — → 17.2 % (549) |
| EMAIL | 2,662 → 2,674 | 3.1 % (83) → 3.1 % (83) |
| LOCATION | — → 2,664 | — → 20.7 % (551) |
| PHONE | 2,725 → 2,240 | 2.9 % (79) → 3.5 % (78) |
| SSN | 777 → 1,699 | 1.2 % (9) → 0.7 % (12) |
| DATE_OF_BIRTH | 588 → 1,574 | 1.4 % (8) → 1.8 % (28) |
| DRIVER_LICENSE | 1,381 → 1,444 | 2.2 % (31) → 2.3 % (33) |
| PASSWORD | 657 → 657 | 2.4 % (16) → 2.4 % (16) |
| PASSPORT | 81 → 83 | 0.0 % (0) → 0.0 % (0) |
| ADDRESS | 72 → 73 | 25.0 % (18) → 24.7 % (18) |
| AADHAAR | 39 → 39 | 5.1 % (2) → 5.1 % (2) |
| CREDIT_CARD | 25 → 12 | 8.0 % (2) → 8.3 % (1) |
| BANK_ACCOUNT | 5 → 5 | 20.0 % (1) → 20.0 % (1) |
| CONFIDENTIAL_MARKER | 5 → 5 | 100.0 % (5) → 100.0 % (5) |
| HIGH_ENTROPY_SECRET | 1 → 1 | 100.0 % (1) → 100.0 % (1) |

"FP upper bound" is the share of an entity's detections that overlap **no** labelled span. ai4privacy does not label every
name or place in its texts (famous people, companies, countries in passing), so for `NAME`/`LOCATION` much of it is label
noise. On the train split, most "unlabelled" names were real names (e.g. common surnames) and most unlabelled locations were
countries mentioned in passing.

### Summary

| | 400k before → after | 300k before → after |
|---|---|---|
| **PII-bearing records ALLOWED through unchanged** | **67.8 % → 47.2 %** | **47.1 % → 32.9 %** |
| Names (given name / surname, typed) | 0 % → 48.4 % / 50.4 % | 0 % → 33.7–39.9 % |
| Cities / countries (typed) | 0 % → 46.0 % (city) | 0 % → 31.9 % (city), 51.4 % (country) |
| Date of birth | 19.9 % → **41.7 %** | 24.8 % → **65.0 %** |
| Social number, typed as SSN | 35.5 % → **57.4 %** | 29.9 % → **64.6 %** |
| Social number caught by any detector | 72.9 % → 81.5 % | 63.8 % → 79.6 % |
| Email · phone · passport · driver's licence | unchanged (99 % · 63 % · 3 % · 31–56 %) | unchanged |
| Card detections on unlabelled text | **329 → 67** (−80 %) | 2 → 1 |
| Card detection rate | 11.6 % → 9.9 % | — |
| Scans failed closed | 5 → 3 | 51 → 19 |

### Honest caveats

* **Recall is still far from complete.** Half the names and most streets, postcodes, usernames, IDs and passports are missed.
  47 % / 33 % of PII-bearing records still pass unchanged.
* **The NER layer has real false positives.** On `pii-masking-400k`, 36 % of NAME and 57 % of LOCATION detections are on
  unlabelled text (17 % / 21 % on 300k). Part of this is label noise, part is the model (examples on train: units and
  acronyms, which are now filtered). Names are masked, so a false positive costs readability, not security.
* **Card detection rate fell from 11.6 % to 9.9 %**: 7 labelled numbers are no longer detected because they are not valid
  issued card numbers for any network. False card hits fell by 80 %.
* **Date-of-birth false positives rose** from 2 to 10 (400k) and 8 to 28 (300k) detections on unlabelled text: the wider
  window catches some other dates near "birth". That is still ≤ 2.7 %.
* **Locations are allowed by default** (D17). If an organisation needs them masked, a one-line policy rule does it (tested).
  Measured with MASK instead, the ALLOW rate would be lower (61.8 % / 71.9 % not-allowed on the train sample).
* **Remaining fail-closed scans** (3 / 19) are a pre-existing driver's-licence verification effect. Masking shortens the text,
  which brings an unrelated code within 40 characters of the words "driver license", and the re-scan then fails the request
  closed. It is safe but wrong; fixing it is left for a follow-up.
* **Self-authored gate**: still PASS (0 critical failures). The benign false-positive rate is now exactly the 2 % budget:
  "Dan sent the files to the team yesterday." is masked because "Dan" is a name. That is correct privacy behaviour, and the
  record was left as it is rather than relabelled.
* Indian identifiers (Aadhaar, PAN, UPI) are still not covered by these datasets.

## Performance cost of the NER layer

Same machine, same day, same `perf-bench.sh` (k6, instant mock model, 30 s per run). **Before** = the Docker images built
from the pre-NER code; **after** = engine and gateway rebuilt from this change. No suspend in either run (wall time = VM
uptime), and **0 failed requests** in all 24 runs.

| Measure | Before | After (NER) | Cost |
|---|---|---|---|
| Latency added to a **chat**, 1 in flight (p50 / p95 / p99) | 44.7 / 56.5 / 74.1 ms | **54.6 / 69.2 / 87.2 ms** | **+10 / +13 / +13 ms** |
| Latency added to a **chat with PII** (masking path), 1 in flight | 41.4 / 56.5 / 67.7 ms | **62.4 / 75.1 / 103.5 ms** | **+21 / +19 / +36 ms** |
| Standalone **scan**, 1 in flight (p50 / p95 / p99) | 20.9 / 28.0 / 36.7 ms | 28.7 / 36.3 / 49.5 ms | +8 / +8 / +13 ms |
| **Throughput, scan** (8–32 in flight) | ≈ 141–150 req/s | **≈ 43–44 req/s** | **−70 %** |
| **Throughput, chat** (8–32 in flight) | ≈ 66–78 req/s | **≈ 16–23 req/s** | **−70 % to −78 %** |
| Engine memory (docker stats, under load) | 43 MiB | **337 MiB** of its 512 MiB limit | +294 MiB |
| Engine image | — | 168 MB, spaCy 3.8.16 + en_core_web_md 3.8.0; Trivy 0 fixable HIGH/CRITICAL | |

**Reading.** Per request, the NER layer costs ≈ 10–20 ms at p50 and up to ≈ 36 ms at p99 (the PII path costs most: after
masking, the verification re-scan runs NER a second time). **Under load the cost is much larger: throughput drops by about
70 %.** NER is CPU-bound, the engine runs as a single process, and a chat request triggers several NER passes (input,
output, and the re-scans after masking). Once saturated, extra concurrency only adds queueing: p50 at 32 in flight rises from
≈ 0.46 s to 1.4–2.0 s.

This is the real price of catching names, and it is **not yet mitigated**. The options, in order of effort:
1. Run more engine workers or replicas. Each worker holds its own model, about 300 MB, so memory limits must follow.
2. Skip the NER pass in the verification re-scan when no NAME/LOCATION was sanitized.
3. Batch NER across concurrent requests.

Nothing was changed to hide it.

After the rebuild the container suite still passes (**81/81**, 0 skipped).

<details><summary>Raw benchmark tables</summary>

**Before**

## Results (latency in ms as seen by the client; rps = completed requests per second)
| run | requests | ok checks | p50 | p95 | p99 | max | req/s |
|---|---|---|---|---|---|---|---|
| chat_pii_vu1 | 698 | 100.00% (0 failed) | 41.68 | 57.41 | 69.12 | 199.3 | 23.1 |
| chat_pii_vu32 | 2061 | 100.00% (0 failed) | 457.26 | 631.50 | 746.79 | 1006.3 | 67.7 |
| chat_pii_vu8 | 2380 | 100.00% (0 failed) | 98.60 | 135.09 | 156.02 | 222.5 | 78.5 |
| chat_vu1 | 667 | 100.00% (0 failed) | 44.95 | 57.37 | 75.51 | 152.7 | 22.1 |
| chat_vu32 | 2021 | 100.00% (0 failed) | 464.70 | 668.12 | 771.62 | 975.0 | 66.3 |
| chat_vu8 | 2251 | 100.00% (0 failed) | 100.69 | 150.38 | 196.65 | 493.7 | 74.4 |
| direct_vu1 | 60878 | 100.00% (0 failed) | 0.27 | 0.90 | 1.38 | 9.7 | 2029.2 |
| direct_vu32 | 438508 | 100.00% (0 failed) | 1.75 | 4.17 | 6.16 | 92.6 | 14614.2 |
| direct_vu8 | 402697 | 100.00% (0 failed) | 0.41 | 1.11 | 1.96 | 20.0 | 13422.6 |
| scan_vu1 | 1410 | 100.00% (0 failed) | 20.87 | 28.00 | 36.66 | 147.6 | 46.7 |
| scan_vu32 | 4545 | 100.00% (0 failed) | 208.27 | 271.29 | 299.17 | 381.1 | 149.7 |
| scan_vu8 | 4250 | 100.00% (0 failed) | 55.42 | 76.37 | 91.36 | 171.0 | 140.5 |

## Gateway overhead = gateway path minus the direct provider hop (same concurrency)
| concurrency | path | p50 overhead | p95 overhead | p99 overhead |
|---|---|---|---|---|
| 1 | chat | 44.68 | 56.47 | 74.14 |
| 1 | chat_pii | 41.41 | 56.50 | 67.74 |
| 8 | chat | 100.28 | 149.28 | 194.69 |
| 8 | chat_pii | 98.19 | 133.98 | 154.06 |
| 32 | chat | 462.95 | 663.95 | 765.47 |
| 32 | chat_pii | 455.51 | 627.33 | 740.63 |

**After**

## Results (latency in ms as seen by the client; rps = completed requests per second)
| run | requests | ok checks | p50 | p95 | p99 | max | req/s |
|---|---|---|---|---|---|---|---|
| chat_pii_vu1 | 486 | 100.00% (0 failed) | 62.84 | 76.08 | 105.10 | 160.7 | 16.1 |
| chat_pii_vu32 | 496 | 100.00% (0 failed) | 2009.71 | 2380.49 | 2531.30 | 2618.0 | 16.0 |
| chat_pii_vu8 | 541 | 100.00% (0 failed) | 446.74 | 595.10 | 632.98 | 720.2 | 17.9 |
| chat_vu1 | 548 | 100.00% (0 failed) | 55.06 | 70.24 | 88.73 | 179.7 | 18.1 |
| chat_vu32 | 728 | 100.00% (0 failed) | 1357.46 | 1696.70 | 1788.28 | 1940.0 | 23.5 |
| chat_vu8 | 673 | 100.00% (0 failed) | 353.65 | 469.82 | 517.78 | 589.7 | 22.2 |
| direct_vu1 | 45630 | 100.00% (0 failed) | 0.44 | 1.03 | 1.57 | 15.0 | 1520.9 |
| direct_vu32 | 416779 | 100.00% (0 failed) | 1.87 | 4.39 | 6.18 | 84.5 | 13891.0 |
| direct_vu8 | 418750 | 100.00% (0 failed) | 0.40 | 1.05 | 1.72 | 10.3 | 13957.5 |
| scan_vu1 | 1055 | 100.00% (0 failed) | 28.65 | 36.30 | 49.53 | 195.2 | 34.9 |
| scan_vu32 | 1358 | 100.00% (0 failed) | 722.81 | 975.95 | 1061.88 | 1150.8 | 44.4 |
| scan_vu8 | 1290 | 100.00% (0 failed) | 185.56 | 261.90 | 296.16 | 346.7 | 42.7 |

## Gateway overhead = gateway path minus the direct provider hop (same concurrency)
| concurrency | path | p50 overhead | p95 overhead | p99 overhead |
|---|---|---|---|---|
| 1 | chat | 54.63 | 69.21 | 87.15 |
| 1 | chat_pii | 62.40 | 75.05 | 103.52 |
| 8 | chat | 353.25 | 468.77 | 516.06 |
| 8 | chat_pii | 446.34 | 594.05 | 631.26 |
| 32 | chat | 1355.59 | 1692.31 | 1782.10 |
| 32 | chat_pii | 2007.84 | 2376.10 | 2525.12 |

</details>

## Tests added

| Suite | New tests |
|---|---|
| `services/security-engine/tests/detectors/test_ner_detector.py` | 18: real-model detection, noise filters, window boundaries, offsets, names masked / locations allowed, policy can mask locations, ordinary prompts untouched, **unloadable model → unhealthy, `/ready` 503, every scan fails closed**, canary rejects a model that finds nothing, production refuses NER off, value-based verification (a surviving value fails closed; a new word in altered text does not), rule-based types keep strict verification, 100k-char input within budget |
| `…/test_financial_detector.py` | 5: IMEIs are Luhn-valid; IMEIs never cards; a card-shaped number after "IMEI" is not a card; every network still detected; non-issued lengths rejected (mutation-checked) |
| `…/test_pii_detector.py` | 6: SSN from context and not phone; plain phones stay phones; SSN wording alone does not create SSNs; new DOB formats; dates without birth wording ignored; placeholders are not context |
| `apps/api/tests/security/securityClient.test.ts` | 1: the gateway timeout grows with text length, and still fails closed when exceeded |

## Verification of this change (2026-09-29)

| Check | Result |
|---|---|
| Host regression: every suite | api 457/457 (after one fix: see below) · ai-router 61 · dashboard 67 · SDK-JS 61 · security-engine **161** · token-vault 112 · document-scanner 117 (+16 real-ClamAV/Tesseract tests, unchanged) · Python SDK 82 · repo security/regression 15 · evaluation gate PASS · `pnpm audit` clean · `tsc` 0 errors ×5 · structure validator |
| CI under `act` (all 8 jobs, from the real repository root) | all succeeded: structure, security-engine (161, gate PASS, 15 repo tests), document-scanner, **python-typecheck** (mypy strict, spaCy installed from the pinned wheel URL), token-vault, gateway (448 + 130 DB on real PostgreSQL + 82 Python SDK), **dependency-scanning** (pip-audit on the new requirements), secret-scanning |
| Container images | engine + gateway rebuilt; Trivy: **0 fixable HIGH/CRITICAL** in all 6 images; Dockerfile config scan clean |
| Running stack | `docker-verify.sh` **81/81**, 0 skipped; `/ready` 200 with the model loaded |
| Kubernetes / Helm / Terraform (kind) | **31/31**. The engine's memory **request** was raised from 128 Mi to 384 Mi (it uses ~340 Mi); the limit stays 512 Mi |
| gitleaks (default rules, no allow-list) on the commit file set | no leaks found |
| ruff 0.6.9 · mypy strict | clean |

One failure found and fixed on the way: `contractConsistency.test.ts` (which checks that Python, TypeScript, SQL and OpenAPI
list the same entity types) failed. The new enum lines had trailing comments that its parser does not read. The comments
were moved; the test was not changed.

## Reproduce

```
cd sentinel-ai
python scripts/security/run_data_leakage_evaluation.py --suite pii --split train --sample 6000   # tuning split only
python scripts/security/run_data_leakage_evaluation.py --suite pii --report pii.json            # held-out measurement
bash scripts/development/perf-bench.sh 30                                                        # latency (in WSL/Linux)
```
