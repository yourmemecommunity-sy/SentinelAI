# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately to the maintainers (do not open a public issue).
Include reproduction steps and affected component. Never include real secrets or customer data.

## Security posture and claims

SentinelAI targets **100% enforcement of explicitly defined prohibited-data policies** and a
**100% pass rate on critical cases of the SentinelAI Security Evaluation Suite**. These are
measurable engineering targets for *defined* policies and suites - not a claim that the system is
universally or mathematically "100% secure".

Critical security components **fail closed**: if a safe decision cannot be made, the request is blocked.

## Rules for contributors

- Never commit real secrets, credentials, or customer data (datasets are synthetic only).
- Never log raw sensitive values; log entity types, offsets, and hashes only.
- Any change to `services/security-engine` must pass the evaluation suite; a critical regression fails CI.

Details: `docs/security/`.
