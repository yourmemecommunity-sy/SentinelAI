# ADR-0003: Policy semantics and where evaluation lives

**Status:** accepted (ambiguities in the spec resolved to the safest maintainable default)

1. **Deny-overrides.** Multiple matching rules for one detection -> the most restrictive action wins
   (`ALLOW < HASH < MASK < TOKENIZE < REDACT < QUARANTINE < BLOCK`).
2. **Unmatched detections use a severity baseline**: CRITICAL -> BLOCK, HIGH -> REDACT, MEDIUM -> MASK, LOW -> ALLOW;
   threat signals (injection, jailbreak, exfiltration, prompt extraction) -> BLOCK. Never default-allow HIGH/CRITICAL.
3. **Non-overridable floors.** Live credentials (private keys, cloud/GitHub/JWT/OAuth tokens, API keys, passwords,
   connection strings), payment cards, and threat signals cannot be `ALLOW`ed. Rejected at policy load (422) *and*
   re-enforced at evaluation time. They can be sanitized (e.g. `CREDIT_CARD: TOKENIZE`) or blocked.
4. **Rule severity is a floor** used for risk scoring: `max(detection severity, rule severity)`.
5. **Scope semantics.** A scoped dimension with no matching request-context value means the rule does not apply
   (so a scoped `ALLOW` can never leak to unattributed requests). `time_window_utc` is UTC only.
6. **`min_confidence` unmet -> baseline**, never allow.
7. **Secrets are never partially revealed**: `MASK`/`HASH` on CRITICAL data is escalated to `REDACT`. Last-4 masking is
   limited to card/account/Aadhaar/SSN/phone.
8. **Location.** Phase 1 evaluates policies in-process in the security engine (`app/policies`) for low latency and a
   single fail-closed boundary. `services/policy-engine` will own authoring/versioning/storage and share this schema.
