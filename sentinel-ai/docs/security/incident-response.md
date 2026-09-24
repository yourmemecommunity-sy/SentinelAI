# Incident Response (runbook outline)

| Incident | First actions |
|---|---|
| Secret/PII reached a provider | Identify `event_id`s via audit; revoke/rotate the credential; add the missed pattern to `datasets/` as a critical case; fix detector; run the evaluation gate; document in `docs/evaluation/regression.md` |
| Spike in `failed_closed` events | Check `/ready` of security-engine, resource limits, recent detector/regex changes; roll back detector bundle version if needed |
| Suspected cross-tenant access | Freeze affected keys, review RLS/isolation tests, snapshot audit logs, notify affected orgs |
| Leaked SentinelAI API key | Revoke by key id, review usage, rotate `API_KEY_HASH_PEPPER` only if the pepper itself is suspect |
| Vulnerability report | Follow `SECURITY.md`; triage severity; patch; regression test first |

Every incident ends with a regression test and an evaluation-suite update.
