# Terraform

| path | status |
|---|---|
| `modules/kubernetes` | **Implemented and verified.** Deploys SentinelAI (namespace + secret + Helm release) into an existing cluster. Applied for real against a kind cluster by `scripts/development/k8s-verify.sh --terraform`. |
| `environments/kind` | **Implemented and verified.** The local environment used for that verification. |
| `modules/aws`, `modules/azure`, `modules/gcp` | **NOT IMPLEMENTED.** Creating managed clusters/databases (EKS/RDS, AKS, GKE/Cloud SQL) cannot be written responsibly without an account to apply and destroy it against; an unapplied cloud module is a guess, not infrastructure. |

Cluster creation is deliberately separate from the application: `modules/kubernetes` takes a cluster as given, so it works
the same on kind, on a managed cluster, or on an existing platform.

## Using it

```hcl
module "sentinel" {
  source          = "github.com/<org>/sentinel-ai//infrastructure/terraform/modules/kubernetes"
  namespace       = "sentinel"
  existing_secret = "sentinel-secrets"   # recommended: keeps secrets out of Terraform state
  image_prefix    = "ghcr.io/acme/sentinel-ai/"
  image_tag       = "1.0.0"
  cors_origins    = "https://sentinel.acme.com"
}
```

Without `existing_secret` the module generates every credential itself and stores it in the state file - fine for a
throwaway cluster, not for production.
