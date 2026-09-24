# SentinelAI Helm chart

Deploys the gateway (`api`), security engine, token vault, document scanner and dashboard, plus (optionally, for
evaluation) PostgreSQL, Redis and ClamAV.

```bash
kubectl create namespace sentinel
kubectl -n sentinel create secret generic sentinel-secrets --from-env-file=secrets.env   # keys below
helm install sentinel infrastructure/helm/sentinel-ai -n sentinel --set secrets.existingSecret=sentinel-secrets
```

## Secret keys (`secrets.existingSecret`)

| key | used by | notes |
|---|---|---|
| `postgres-password` | migrate Job, bundled PostgreSQL | database OWNER; never given to the gateway |
| `app-db-password` | gateway | the restricted `sentinel_api` login (RLS enforced) |
| `api-key-hash-pepper` | gateway | >= 32 chars |
| `jwt-access-secret` | gateway | >= 32 chars, different from the pepper |
| `security-engine-token` | gateway, engine | service-to-service bearer token |
| `document-scanner-token` | gateway, scanner | |
| `vault-token` | gateway, engine, vault | |
| `vault-master-keys` | vault | `k1:<base64 32 bytes>[,k2:...]` |
| `redis-password` | vault, bundled Redis | |
| `provider-credential-keys` | gateway (optional) | `p1:<base64 32 bytes>`; without it organizations cannot store their own provider keys |
| `gemini-api-key`, `openai-api-key`, `anthropic-api-key` | gateway (optional) | platform-level provider keys |

`scripts/development/docker-secrets.sh` generates suitable values (as a `.env` file) for evaluation.

## Security properties of the rendered manifests

* Every SentinelAI container: non-root fixed uid, read-only root filesystem, all capabilities dropped,
  `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`, no service-account token, memory limits.
* NetworkPolicies: default deny for the release; each component may only talk to the peers it needs. The gateway may reach
  the internet on 443 only for **public** addresses (private ranges and 169.254.0.0/16 - cloud metadata - excluded).
* Migrations run in a Job holding the owner credentials; gateway pods wait for the schema as the restricted role.

## Validation

`scripts/development/k8s-verify.sh` lints and renders the chart, validates it with kubeconform and Trivy, installs it on a
local kind cluster, and checks readiness, the security pipeline, fail-closed behaviour and NetworkPolicy enforcement.
