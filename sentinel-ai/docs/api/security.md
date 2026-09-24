# Security Scan API

**Implemented today:** the internal security-engine endpoint `POST /v1/scan` (contract in [openapi.yaml](openapi.yaml)).
The public gateway routes `/v1/security/scan` and `/v1/security/check` are planned and will wrap it.

## Request

```json
{
  "text": "My email is user@example.com",
  "direction": "INPUT",
  "organization_id": "org-1",
  "context": { "user_id": "u1", "provider": "gemini", "environment": "production" },
  "policy": { "policy_id": "eng", "rules": [{ "entity": "EMAIL", "action": "REDACT", "severity": "MEDIUM" }] }
}
```
Unknown fields and invalid/unsafe policies are rejected with 422 - **callers must treat 422, 401, timeouts and network errors as BLOCK**.

## Response (abridged)

```json
{
  "decision": "REDACT",
  "failed_closed": false,
  "detections": [{ "entity": "EMAIL", "confidence": 0.95, "severity": "MEDIUM",
                   "location": { "start": 12, "end": 28 }, "detector": "pii", "detector_version": "1.0.0", "value_digest": "9f2c..." }],
  "risk": { "risk_score": 33, "risk_level": "MEDIUM", "decision": "REDACT", "factors": [ ... ] },
  "sanitized_text": "My email is [EMAIL_REDACTED]",
  "policy_id": "eng"
}
```

`sanitized_text` is `null` when the decision is `BLOCK` or `QUARANTINE`. Only forward `sanitized_text` to a model; never the original.
Authentication between gateway and engine: `X-Internal-Token` (required when `SECURITY_ENGINE_TOKEN` is set; mandatory in production).

## Fail-closed reasons
See [data-flow](../architecture/data-flow.md#fail-closed-edges).
