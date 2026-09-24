# Privacy and Data Handling

- **Default: zero retention of content.** Prompts, responses and uploaded files are processed in memory and not stored.
- **Audit records** contain: event id, organization, user, application, provider, model, timestamp, direction, risk level,
  detected *entity types*, policy id, action, detector version. They never contain raw passwords, API keys, card numbers,
  tokens, private keys, or other matched values.
- **Digests.** Detections carry a 64-bit keyed HMAC prefix (`value_digest`) so repeated leakage of the same value can be correlated
  without storing it. Key: `SENTINEL_DIGEST_KEY` from the secret manager; a random per-process key is used if unset.
- **Tokenization vault** maps tokens to raw values only for the request lifetime (in memory now; encrypted Redis with short TTL planned).
- **Retention** is configurable per organization (`organizations.audit_retention_days`). **Zero-retention orgs** (`organizations.zero_retention`, the default) keep only the metadata event row and usage counters: no per-detection offsets and no digests are written to `scan_results`. Both modes are tested, and an end-to-end test proves no prompt/response/secret text exists anywhere in the database.
- `security_events`, `scan_results` and `audit_logs` are append-only for the application role (no UPDATE/DELETE); retention deletion will run under a separate privileged maintenance role (job not yet written).
- **Uploads** are not persisted unless the organization policy explicitly enables it.
- **Development data** is synthetic only. Real customer data must never enter `datasets/`, fixtures, logs, docs, or Git.
