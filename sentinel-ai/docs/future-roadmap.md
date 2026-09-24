# SentinelAI — future roadmap (post v1.0)

Everything here is **deliberately out of scope** for v1.0. Nothing below is implemented.

## Blocked on the owner, not on design
| Item | Needs |
|---|---|
| Real Gemini / OpenAI / Anthropic verification | An API key per provider (platform `.env` or a test organization's own key) |
| GitHub Actions on GitHub-hosted runners | A GitHub remote (the workflow already passes under `act`) |

## Product gaps deferred past v1.0
| Item | Note |
|---|---|
| Dashboard pages: models, applications, audit logs, security evaluation | No backing APIs yet |
| Async Python SDK | Synchronous only |
| De-tokenization across sessions / long-lived vaults | Sessions expire absolutely at 3600 s by design |
| MFA, SSO (SAML/OIDC), SCIM provisioning, email verification, password reset | Enterprise identity |
| Invitation delivery by email | Links are shown once to the inviter, who delivers them |
| Per-organization rate limits and quotas | The limiter is per client IP and per gateway instance |
| Redis-backed distributed rate limiting | Limits are per gateway instance today |
| Policy change audit in the same transaction as the change | Currently two transactions |
| Re-sealing stored provider credentials under a new master key | Old keys stay readable while configured; there is no bulk re-wrap job yet |

## Deployment
| Item | Note |
|---|---|
| Cloud Terraform modules (EKS/RDS, AKS, GKE/Cloud SQL) | Needs an account to apply and destroy against |
| Helm: HorizontalPodAutoscaler, PodDisruptionBudget, Ingress | Not in the chart |
| Multi-node, rolling-upgrade-under-load and node-failure testing | Verified on a single kind node only |
| Distroless / non-Debian base for the Python images | Removes the unfixed Debian base CVEs (see the release report) |

## Detection and security research
| Item | Note |
|---|---|
| ML-assisted prompt-injection classifier | Rules only today; paraphrase evades them |
| Named-entity recognition for names and addresses | Names are not detected at all; addresses are heuristic |
| Business-data classifiers (source code, contracts, pricing) | Not attempted |
| Normalization of obfuscated PII and secrets | Injection inputs are normalized; PII is not |
| Independent, externally sourced red-team datasets | The evaluation set is self-authored, so 100% is necessary but not sufficient |
| Semantic output-leakage detection | Exact and pattern matching only |

## Platform and scale
| Item |
|---|
| AWS Bedrock, Azure OpenAI, Mistral, Cohere adapters |
| AI usage discovery (finding shadow AI traffic) |
| Behavioural analytics and anomaly detection per user/team |
| SIEM integration (Splunk, Sentinel, Elastic) and threat-intelligence feeds |
| Advanced governance: approval workflows, data-residency routing, retention policies per tenant |
| Horizontal scale testing, multi-region, HA Postgres/Redis |
| OpenTelemetry tracing and metrics across all services |
| A security research platform for evaluating detectors against public corpora |
