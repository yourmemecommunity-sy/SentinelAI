# ADR-0004: Deterministic detection first; ML/LLM only as an additional layer

**Status:** accepted

**Context.** A classifier that is itself an LLM can be prompt-injected by the content it inspects. The spec also requires
the classifier be "hardened against prompt injection".

**Decision.** Layer 1 (implemented) is pure deterministic code: regex, checksums, entropy, context windows, Unicode
normalization, decoding. No model reads attacker text, so there is nothing to instruct. ML/NER classifiers (Phase 3)
will be *additive and can only raise severity/block*, never lower a deterministic decision, and will run with output
constrained to a fixed schema.

**Trade-off.** Rules miss paraphrased or novel attacks. This is a stated limitation; recall on unseen attacks must be
measured with independent red-team data, not the self-authored suite.
