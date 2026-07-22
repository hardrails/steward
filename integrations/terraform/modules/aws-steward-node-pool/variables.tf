variable "name" {
  description = "Short name for the Auto Scaling Group and launch template."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,47}$", var.name))
    error_message = "name must be 2-48 lowercase letters, digits, or hyphens and start with a letter."
  }
}

variable "ami_id" {
  description = "Approved Linux AMI with Docker, gVisor, systemd, cloud-init, curl, timeout, and sha256sum already installed."
  type        = string
  validation {
    condition     = can(regex("^ami-[a-f0-9]+$", var.ami_id))
    error_message = "ami_id must be an EC2 AMI identifier."
  }
}

variable "instance_type" {
  description = "EC2 instance type for every node in this homogeneous pool."
  type        = string
  default     = "m7i.large"
}

variable "subnet_ids" {
  description = "At least two private subnets in distinct availability zones."
  type        = set(string)
  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "subnet_ids must contain at least two private subnets."
  }
}

variable "security_group_ids" {
  description = "Security groups with no public ingress and only approved egress."
  type        = set(string)
  validation {
    condition     = length(var.security_group_ids) > 0
    error_message = "security_group_ids must contain at least one hardened security group."
  }
}

variable "kms_key_arn" {
  description = "Customer-managed KMS key ARN for the encrypted root volume."
  type        = string
  validation {
    condition     = can(regex("^arn:[^:]+:kms:[^:]+:[0-9]{12}:key/.+$", var.kms_key_arn))
    error_message = "kms_key_arn must be a customer-managed AWS KMS key ARN."
  }
}

variable "instance_profile_name" {
  description = "Optional least-privilege instance profile. Leave null when the staged node needs no AWS API access."
  type        = string
  default     = null
}

variable "capacity" {
  description = "Initial pool bounds. Terraform ignores later capacity changes so it cannot select an undrained node for scale-in."
  type = object({
    min     = number
    desired = number
    max     = number
  })
  default = { min = 2, desired = 2, max = 10 }
  validation {
    condition = (
      var.capacity.min >= 0 &&
      var.capacity.min <= var.capacity.desired &&
      var.capacity.desired <= var.capacity.max &&
      var.capacity.max <= 1000 &&
      floor(var.capacity.min) == var.capacity.min &&
      floor(var.capacity.desired) == var.capacity.desired &&
      floor(var.capacity.max) == var.capacity.max
    )
    error_message = "capacity must contain integer values 0 <= min <= desired <= max <= 1000."
  }
}

variable "root_volume_gib" {
  description = "Encrypted gp3 root-volume size. Agent state should use a separately designed persistent-state backend."
  type        = number
  default     = 80
  validation {
    condition     = var.root_volume_gib >= 32 && var.root_volume_gib <= 16384 && floor(var.root_volume_gib) == var.root_volume_gib
    error_message = "root_volume_gib must be an integer from 32 through 16384."
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

variable "instance_warmup_seconds" {
  description = "Time allowed for image boot and release staging during a rolling refresh. Enrollment is a separate gate."
  type        = number
  default     = 900
  validation {
    condition     = var.instance_warmup_seconds >= 60 && var.instance_warmup_seconds <= 7200
    error_message = "instance_warmup_seconds must be from 60 through 7200."
  }
}

variable "tags" {
  description = "Non-secret tags applied to the group, instances, and root volumes."
  type        = map(string)
  default     = {}
}
