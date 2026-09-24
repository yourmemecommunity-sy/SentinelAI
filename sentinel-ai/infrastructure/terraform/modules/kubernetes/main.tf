// Deploys SentinelAI into an EXISTING Kubernetes cluster: namespace, secret, and the Helm chart.
//
// The cluster itself is not created here - that is the job of a cloud module (see ../aws, ../azure, ../gcp) or of your
// existing platform tooling. This module is what turns "a cluster" into "a running, isolated SentinelAI".

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.32" }
    helm       = { source = "hashicorp/helm", version = "~> 2.15" }
    random     = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

resource "kubernetes_namespace" "this" {
  count = var.create_namespace ? 1 : 0
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/part-of" = "sentinel-ai"
      // Baseline for the whole namespace: no privileged or root containers, matching what the chart already enforces per pod.
      "pod-security.kubernetes.io/enforce"         = "restricted"
      "pod-security.kubernetes.io/enforce-version" = "latest"
    }
  }
}

// Secrets are generated here and kept in Terraform state (mark the state as sensitive storage) unless `existing_secret`
// names a Secret managed elsewhere - which is what production should do (external-secrets, sealed-secrets, cloud KMS).
resource "random_password" "generated" {
  for_each = var.existing_secret == "" ? toset([
    "postgres-password", "app-db-password", "api-key-hash-pepper", "jwt-access-secret",
    "security-engine-token", "document-scanner-token", "vault-token", "redis-password",
  ]) : toset([])
  length  = 48
  special = false
}

resource "random_bytes" "master_keys" {
  for_each = var.existing_secret == "" ? toset(["vault-master-keys", "provider-credential-keys"]) : toset([])
  length   = 32
}

resource "kubernetes_secret" "this" {
  count = var.existing_secret == "" ? 1 : 0
  metadata {
    name      = "${var.release_name}-secrets"
    namespace = var.namespace
  }
  type = "Opaque"
  data = merge(
    { for k, v in random_password.generated : k => v.result },
    {
      "vault-master-keys"        = "k1:${random_bytes.master_keys["vault-master-keys"].base64}"
      "provider-credential-keys" = "p1:${random_bytes.master_keys["provider-credential-keys"].base64}"
    },
    var.provider_api_keys,
  )
  depends_on = [kubernetes_namespace.this]
}

resource "helm_release" "sentinel" {
  name      = var.release_name
  chart     = var.chart_path
  namespace = var.namespace
  version   = var.chart_version

  wait          = true
  wait_for_jobs = true
  timeout       = var.timeout_seconds
  atomic        = var.atomic

  values = [yamlencode(merge({
    secrets = { existingSecret = var.existing_secret != "" ? var.existing_secret : kubernetes_secret.this[0].metadata[0].name }
    images = {
      pullPolicy      = var.image_pull_policy
      api             = { repository = "${var.image_prefix}api", tag = var.image_tag }
      dashboard       = { repository = "${var.image_prefix}dashboard", tag = var.image_tag }
      securityEngine  = { repository = "${var.image_prefix}security-engine", tag = var.image_tag }
      tokenVault      = { repository = "${var.image_prefix}token-vault", tag = var.image_tag }
      documentScanner = { repository = "${var.image_prefix}document-scanner", tag = var.image_tag }
    }
    api = {
      replicas    = var.api_replicas
      corsOrigins = var.cors_origins
      // Open self-service signup stays off unless the operator asks for it.
      signupEnabled = var.signup_enabled
    }
    networkPolicy   = { enabled = var.network_policy_enabled }
    documentScanner = { enabled = var.document_scanner_enabled }
    clamav          = { bundled = { enabled = var.document_scanner_enabled } }
  }, var.extra_values))]

  depends_on = [kubernetes_namespace.this, kubernetes_secret.this]
}
