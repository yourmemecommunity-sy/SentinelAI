variable "namespace" {
  description = "Namespace to deploy into."
  type        = string
  default     = "sentinel"
}

variable "create_namespace" {
  description = "Create the namespace (with the restricted Pod Security standard) or expect it to exist."
  type        = bool
  default     = true
}

variable "release_name" {
  description = "Helm release name; also the prefix of every object the chart creates."
  type        = string
  default     = "sentinel"
}

variable "chart_path" {
  description = "Path to (or repository URL of) the SentinelAI chart."
  type        = string
  default     = "../../../helm/sentinel-ai"
}

variable "chart_version" {
  description = "Chart version; empty means whatever `chart_path` contains."
  type        = string
  default     = null
}

variable "existing_secret" {
  description = <<-EOT
    Name of a Secret holding the credentials (see the chart README for the keys). RECOMMENDED in production: it keeps
    secret material out of Terraform state. Empty means this module generates the secrets itself (evaluation only).
  EOT
  type        = string
  default     = ""
}

variable "provider_api_keys" {
  description = "Optional platform-level AI provider keys, e.g. { \"openai-api-key\" = \"...\" }. Only used when this module creates the Secret."
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "image_prefix" {
  description = "Registry/repository prefix for the images, e.g. \"ghcr.io/acme/sentinel-ai/\"."
  type        = string
  default     = "sentinel-ai/"
}

variable "image_tag" {
  description = "Image tag to deploy. Pin to a digest or an immutable tag in production."
  type        = string
  default     = "local"
}

variable "image_pull_policy" {
  type    = string
  default = "IfNotPresent"
  validation {
    condition     = contains(["Always", "IfNotPresent", "Never"], var.image_pull_policy)
    error_message = "image_pull_policy must be Always, IfNotPresent or Never."
  }
}

variable "api_replicas" {
  type    = number
  default = 2
  validation {
    condition     = var.api_replicas >= 1
    error_message = "api_replicas must be at least 1."
  }
}

variable "cors_origins" {
  description = "Comma-separated browser origins allowed to call the gateway. A wildcard is refused by the gateway in production."
  type        = string
  default     = "https://sentinel.example.com"
  validation {
    condition     = !can(regex("(^|,)\\s*\\*\\s*(,|$)", var.cors_origins))
    error_message = "A wildcard CORS origin is not allowed."
  }
}

variable "signup_enabled" {
  description = "Open self-service signup. Off by default: organizations are normally created by an operator."
  type        = bool
  default     = false
}

variable "network_policy_enabled" {
  description = "Deploy the NetworkPolicies that confine each component. Turning this off removes tenant-infrastructure isolation."
  type        = bool
  default     = true
  validation {
    condition     = var.network_policy_enabled
    error_message = "network_policy_enabled=false is not supported: the policies are part of the security model. Override in the chart values if you truly must."
  }
}

variable "document_scanner_enabled" {
  description = "Deploy the document scanner and its ClamAV (file scanning). Needs ~3Gi of memory for the signature database."
  type        = bool
  default     = true
}

variable "timeout_seconds" {
  type    = number
  default = 900
}

variable "atomic" {
  description = "Roll back the release if it fails to become ready."
  type        = bool
  default     = true
}

variable "extra_values" {
  description = "Extra chart values merged over the ones this module computes."
  type        = any
  default     = {}
}
