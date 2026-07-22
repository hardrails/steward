variable "name" {
  description = "Name for the Virtual Machine Scale Set."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,47}$", var.name))
    error_message = "name must be 2-48 lowercase letters, digits, or hyphens and start with a letter."
  }
}
variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "subnet_id" {
  description = "Existing private subnet. The scale set creates no public IP configuration."
  type        = string
}
variable "network_security_group_id" {
  description = "Existing network security group with no public ingress and only approved egress."
  type        = string
}
variable "source_image_id" {
  description = "Approved image ID with Docker, gVisor, systemd, cloud-init, curl, timeout, and sha256sum."
  type        = string
}
variable "disk_encryption_set_id" {
  description = "Customer-managed Disk Encryption Set resource ID for the OS disk."
  type        = string
}
variable "admin_ssh_public_key" {
  description = "Public SSH key for break-glass administration. No private key or password enters state."
  type        = string
  validation {
    condition     = can(regex("^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com) [A-Za-z0-9+/]+={0,3}( .*)?$", trimspace(var.admin_ssh_public_key)))
    error_message = "admin_ssh_public_key must be an Ed25519, ECDSA, or security-key OpenSSH public key; RSA keys are not accepted by this hardened module."
  }
}
variable "sku" {
  type    = string
  default = "Standard_D2as_v5"
}
variable "capacity" {
  type    = number
  default = 2
  validation {
    condition     = var.capacity >= 1 && var.capacity <= 1000 && floor(var.capacity) == var.capacity
    error_message = "capacity must be an integer from 1 through 1000."
  }
}
variable "zones" {
  description = "Availability zones used by the scale set."
  type        = list(string)
  default     = ["1", "2", "3"]
  validation {
    condition     = length(var.zones) >= 2 && alltrue([for zone in var.zones : contains(["1", "2", "3"], zone)])
    error_message = "zones must contain at least two Azure availability zones selected from 1, 2, and 3."
  }
}
variable "root_volume_gib" {
  type    = number
  default = 80
  validation {
    condition     = var.root_volume_gib >= 32 && var.root_volume_gib <= 32767 && floor(var.root_volume_gib) == var.root_volume_gib
    error_message = "root_volume_gib must be an integer from 32 through 32767."
  }
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
variable "tags" {
  description = "Non-secret tags applied to the scale set."
  type        = map(string)
  default     = {}
}
