# Policies

Schema implemented in `services/security-engine/app/policies/policy.py` (JSON contract in [openapi.yaml](openapi.yaml)).

```json
{
  "policy_id": "engineering-policy",
  "version": 3,
  "rules": [
    { "entity": "API_KEY", "action": "BLOCK", "severity": "CRITICAL" },
    { "entity": "EMAIL",   "action": "MASK",  "severity": "MEDIUM" },
    { "entity": "CREDIT_CARD", "action": "TOKENIZE",
      "scope": { "environments": ["production"], "providers": ["gemini", "openai"] } }
  ]
}
```

- **Actions:** `ALLOW HASH MASK TOKENIZE REDACT QUARANTINE BLOCK`.
- **Scopes:** users, teams, applications, providers, models, environments, `ip_cidrs`, `time_window_utc` (UTC `HH:MM`), directions. Organization scoping is by policy ownership.
- **Semantics:** deny-overrides; unmatched detections use the severity baseline; credentials/cards/threats can never be `ALLOW` ([ADR-0003](../architecture/adr/0003-policy-semantics.md)).
- `min_confidence` gates a rule on detection confidence; unmet -> baseline (never allow).
