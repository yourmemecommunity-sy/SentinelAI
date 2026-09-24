# ADR-0002: Critical components fail closed

**Status:** accepted

**Decision.** Whenever the pipeline cannot reach a safe decision - oversize input, detector error, timeout, missing
detectors, policy error, unverifiable sanitization, unexpected exception, or (gateway) unreachable/invalid engine response,
unknown provider or policy - the result is `BLOCK` with `failed_closed=true` and a reason code. The original text is never returned.
Every fail-closed event is audited.

**Details.**
- Time budget is checked between detectors. Python's `re` cannot be interrupted, so ReDoS is mitigated by linear-time
  patterns and the input-size cap, not by preemption (residual risk documented in the threat model).
- `/ready` runs a canary scan; an engine that cannot block a known-bad input reports 503.
- Production refuses to start without an internal service token.
- Explicitly empty detector registries stay empty and fail closed (regression-tested).

**Consequence.** Availability is traded for safety on purpose; operators must monitor the fail-closed rate.
