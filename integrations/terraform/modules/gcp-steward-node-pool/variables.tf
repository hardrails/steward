variable "name" {
  description = "Short name for the regional Managed Instance Group."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,47}[a-z0-9]$", var.name))
    error_message = "name must be 3-49 lowercase letters, digits, or hyphens, start with a letter, and end with a letter or digit."
  }
}

variable "project_id" { type = string }
variable "region" { type = string }
variable "subnetwork_self_link" {
  description = "Existing private subnetwork. The template creates no external access configuration."
  type        = string
}
variable "source_image" {
  description = "Approved image self-link with Docker, gVisor, systemd, cloud-init, curl, timeout, and sha256sum."
  type        = string
}
variable "service_account_email" {
  description = "Dedicated least-privilege service account. The module grants no roles and requests no OAuth scopes."
  type        = string
}
variable "kms_key_self_link" {
  description = "Customer-managed Cloud KMS CryptoKey self-link for the boot disk."
  type        = string
}
variable "machine_type" {
  type    = string
  default = "n2-standard-2"
}
variable "capacity" {
  description = "Initial target size. Terraform ignores later size changes so it cannot select an undrained node for scale-in."
  type        = number
  default     = 2
  validation {
    condition     = var.capacity >= 1 && var.capacity <= 1000 && floor(var.capacity) == var.capacity
    error_message = "capacity must be an integer from 1 through 1000."
  }
}
variable "root_volume_gib" {
  type    = number
  default = 80
  validation {
    condition     = var.root_volume_gib >= 32 && var.root_volume_gib <= 65536 && floor(var.root_volume_gib) == var.root_volume_gib
    error_message = "root_volume_gib must be an integer from 32 through 65536."
  }
}
variable "zones" {
  description = "Optional explicit zones within region. Empty lets Google distribute the regional group."
  type        = list(string)
  default     = []
}
variable "release_version" { type = string }
variable "installer_url" { type = string }
variable "installer_sha256" { type = string }
variable "release_mirror" {
  type = object({
    artifact_url    = string
    artifact_sha256 = string
    manifest_url    = string
    manifest_sha256 = string
  })
  default = null
}
variable "labels" {
  description = "Non-secret labels applied to the instance template."
  type        = map(string)
  default     = {}
}
