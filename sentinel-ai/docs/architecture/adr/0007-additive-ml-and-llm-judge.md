# ADR-0007: An additive detection cascade — local classifier, then an optional LLM judge

**Status:** accepted (2026-10-03). Amends [ADR-0004](0004-deterministic-detection-first.md): the deterministic layer stays
first and authoritative, but a model now reads attacker text.

**Context.** On public held-out data the rules found 1.7 % of deepset's injections and 39.6 % of jackhhao's jailbreaks
(docs/verification/08-independent-evaluation.md). Paraphrased attacks need a model. A model that reads attacker text can be
manipulated by it (ADR-0004's original concern), costs money when external, and sees content.

**Decision.**
1. Tiers run in order and only *add*: tier 1 (rules + NER) decides first; tier 2 (a local ONNX classifier) and tier 3 (an
   LLM judge) run only when tier 1 did not already block, only on input, and can only turn ALLOW/MASK into BLOCK, never the
   reverse.
2. Tier 2 runs in-process on CPU: nothing leaves the machine. Tier 3 is called only for the classifier's uncertain band
   (cost-bounded on training data), only if a key is configured and the organisation allows it.
3. The judge never receives raw input, only text tier 1 has already sanitized.
4. The judge is treated as an attack surface: instructions only in the system prompt, untrusted text inside a nonce-wrapped
   block, schema-constrained output re-validated locally, any deviation = fail closed. It cannot ALLOW anything tier 1
   blocked, so a fully manipulated judge can at worst let an attack that only it would have caught through — the same
   outcome as having no judge.
5. Every tier is fail-closed and covered by `/ready` (classifier canary; the judge is not called by readiness probes), and
   every decision records which tier decided (explanations, replay).
6. The engine's only network egress is an allow-list proxy to the judge's API.

**Trade-offs.** ~1.2 GiB memory and ~50 ms per request for tier 2; a third party sees masked text for ~10–20 % of inputs when
the judge is on (cost ~USD 0.3 per 1,000 requests, capped). Tier-2 thresholds must be calibrated on realistic benign
traffic: calibrated only on a benchmark, the classifier blocked 39–54 % of ordinary business text (D43).
