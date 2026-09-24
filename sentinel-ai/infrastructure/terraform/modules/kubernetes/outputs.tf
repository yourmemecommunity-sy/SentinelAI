output "namespace" {
  value = var.namespace
}

output "release_name" {
  value = helm_release.sentinel.name
}

output "release_status" {
  value = helm_release.sentinel.status
}

output "gateway_service" {
  description = "In-cluster address of the gateway."
  value       = "http://${helm_release.sentinel.name}-api.${var.namespace}.svc.cluster.local:4000"
}

output "dashboard_service" {
  value = "http://${helm_release.sentinel.name}-dashboard.${var.namespace}.svc.cluster.local:3000"
}

output "secret_name" {
  description = "The Secret the release reads its credentials from."
  value       = var.existing_secret != "" ? var.existing_secret : kubernetes_secret.this[0].metadata[0].name
}
