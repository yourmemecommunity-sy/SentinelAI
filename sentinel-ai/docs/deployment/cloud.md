# Cloud (Terraform)

| Module | Status |
|---|---|
| `infrastructure/terraform/modules/kubernetes` | **Implemented and VERIFIED** — applied and destroyed against a real (kind) cluster on 2026-09-23 |
| `infrastructure/terraform/environments/kind` | **Implemented and VERIFIED** — the environment used for that run |
| `modules/aws`, `modules/azure`, `modules/gcp` | **NOT IMPLEMENTED** — no cloud account to apply, verify and destroy against |

Cluster creation is intentionally separate from the application. `modules/kubernetes` takes a cluster as given and
deploys SentinelAI into it (namespace with the restricted Pod Security standard, secret, Helm release), so it behaves
the same on kind, on a managed cluster, or on a cluster your platform team already runs.

```hcl
module "sentinel" {
  source          = "github.com/<org>/sentinel-ai//infrastructure/terraform/modules/kubernetes"
  namespace       = "sentinel"
  existing_secret = "sentinel-secrets"   # keeps secret material OUT of Terraform state
  image_prefix    = "ghcr.io/acme/sentinel-ai/"
  image_tag       = "1.0.0"
  cors_origins    = "https://sentinel.acme.com"
}
```

Without `existing_secret` the module generates every credential and stores it in the state file — acceptable for a
throwaway cluster, not for production. Provider credentials never appear in code; state and `*.tfvars` are git-ignored.

## What the verification run covered (2026-09-23)

`bash scripts/development/k8s-verify.sh --terraform`:

* `terraform fmt -check`, `init`, `validate`;
* variable validation **refuses** a wildcard CORS origin and **refuses** disabling the NetworkPolicies;
* `plan` (13 resources) → `apply`: 6 pods running, Helm release `status=deployed`, namespace carries
  `pod-security.kubernetes.io/enforce=restricted`;
* `destroy` removed everything it created.

## Not verified

Managed Postgres/Redis, KMS-backed secrets, workload identity/OIDC, object storage and cloud networking are untouched —
they need an account. Until then, treat any cloud module as unwritten rather than as a draft to trust.
