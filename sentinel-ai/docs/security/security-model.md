# Security Model

## Principles
1. **Defense in depth** - independent detectors (regex, checksum, context, entropy, rules), policy floors, risk escalation, post-sanitization rescan.
2. **Fail closed** - unsafe or unknown => block + audit ([ADR-0002](../architecture/adr/0002-fail-closed.md)).
3. **No sensitive values in evidence** - detections carry `entity`, `confidence`, `severity`, `location`, detector/version, keyed digest.
4. **Least privilege & deny-overrides** - most restrictive rule wins; some data can never be allowed ([ADR-0003](../architecture/adr/0003-policy-semantics.md)).
5. **Verified sanitization** - sanitizing is checked by scanning the result again.
6. **Explainability** - every risk score lists its factors (`data_sensitivity`, `threat_probability`, `detection_volume`, `model_context`, `user_context`, `risk_escalation`).

## Risk scoring (implemented)
`score = min(100, max(data_sensitivity, threat) + volume + context)`; severity weights LOW 10 / MEDIUM 30 / HIGH 60 / CRITICAL 85, times confidence.
Sanitized detections count at half weight; blocked/allowed at full weight. Levels: >=80 CRITICAL, >=60 HIGH, >=30 MEDIUM.
CRITICAL escalates any non-withholding decision to BLOCK; risk can only make a decision stricter.

## Detection layers
| Layer | Used by |
|---|---|
| Regex / pattern | all detectors |
| Checksums (Luhn, Verhoeff, IBAN mod-97) | cards, Aadhaar-like, IBAN |
| Context windows | passports, driver licences, DOB, SSN (unformatted), bank accounts, AWS secret keys, IFSC |
| Entropy | high-entropy secret safety net |
| Normalization / decoding | prompt-injection (Unicode, homoglyph, leet, spaced, reversed, ROT13, base64/hex/percent) |
| NER / ML | **not implemented** |

## Hardening in code
Internal token on the engine; strict request models (`extra=forbid`); policy validation; no raw text in logs; structured JSON logs;
non-root containers; no secrets in the repo (validator + `.gitignore` + gitleaks in CI + tests build secret-shaped fixtures at runtime).

## Implemented and verified
* Authentication (scrypt password hashing, JWT access + rotating refresh tokens with reuse detection), RBAC, and
  session state re-checked on every request, so disabling or demoting a user takes effect immediately.
* Tenant isolation through PostgreSQL RLS, with the gateway refusing to start in production on a database role that
  would bypass it (superuser, `BYPASSRLS`, or table owner).
* Rate limiting, strict CORS (wildcards refused in production), CSRF defences and secure headers on the dashboard BFF
  (HttpOnly/SameSite=Strict/Secure cookies, CSP with a per-request nonce and no `unsafe-inline` scripts).
* **Encryption at rest for per-organization provider credentials** (AES-256-GCM, bound to `organization:provider`,
  key rotation supported, decryption failure fails closed) — see `docs/api/organization.md`.
* Invitation tokens stored only as HMACs; API keys stored only as peppered hashes; both shown exactly once.
* Dependency scanning (pnpm audit, pip-audit) and **container image scanning** (Trivy: 0 fixable HIGH/CRITICAL across
  all six images) in CI; Python SAST (bandit); Kubernetes manifest misconfiguration scanning.
* Container/pod hardening: read-only root filesystems, all capabilities dropped, no privilege escalation, non-root uids,
  resource limits, and NetworkPolicies confining each component (Kubernetes) — all asserted against running containers.

## Not implemented
SSO/SAML/OIDC/SCIM, MFA, audit retention/rotation jobs, DAST, NER/ML detection, per-organization rate limits
(the limiter is per client IP). See `docs/future-roadmap.md`.
