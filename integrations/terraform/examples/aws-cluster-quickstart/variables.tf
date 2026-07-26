variable "name" {
  description = "Lowercase cluster and AWS resource prefix."
  type        = string
  default     = "steward"
}

variable "server_count" {
  description = "One server for an evaluation cluster or three for HA."
  type        = number
  default     = 1
  validation {
    condition     = contains([1, 3], var.server_count)
    error_message = "server_count must be 1 or 3."
  }
}

variable "architecture" {
  description = "CPU architecture for every server."
  type        = string
  default     = "amd64"
  validation {
    condition     = contains(["amd64", "arm64"], var.architecture)
    error_message = "architecture must be amd64 or arm64."
  }
}

variable "instance_type" {
  description = "Optional EC2 instance type override."
  type        = string
  default     = null
}

variable "steward_release_version" {
  description = "Testing-only release override. Leave null to use the module's release lock."
  type        = string
  default     = null
}

variable "steward_installer_sha256" {
  description = "Testing-only installer hash paired with steward_release_version."
  type        = string
  default     = null
}

variable "vpc_cidr" {
  description = "Private address range for the disposable quick-start VPC."
  type        = string
  default     = "10.73.0.0/16"
  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be a valid IPv4 CIDR."
  }
}

variable "tags" {
  description = "Non-secret tags applied to quick-start resources."
  type        = map(string)
  default = {
    "steward.io/deployment" = "terraform-quickstart"
  }
}
