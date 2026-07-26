variable "name" {
  description = "Lowercase cluster and AWS resource prefix."
  type        = string
  default     = "steward"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,31}$", var.name))
    error_message = "name must be 2-32 lowercase letters, digits, or hyphens and start with a letter."
  }
}

variable "vpc_id" {
  description = "VPC that contains the cluster subnets."
  type        = string
  validation {
    condition     = can(regex("^vpc-[a-f0-9]+$", var.vpc_id))
    error_message = "vpc_id must be an AWS VPC identifier."
  }
}

variable "subnet_ids" {
  description = "Subnets used in order for the first and joining servers. Supply three subnets in distinct availability zones for HA."
  type        = list(string)
  validation {
    condition = (
      length(var.subnet_ids) >= 1 &&
      length(var.subnet_ids) <= 3 &&
      length(distinct(var.subnet_ids)) == length(var.subnet_ids) &&
      alltrue([for id in var.subnet_ids : can(regex("^subnet-[a-f0-9]+$", id))])
    )
    error_message = "subnet_ids must contain one to three distinct AWS subnet identifiers."
  }
}

variable "server_count" {
  description = "One server for evaluation or three servers for an HA etcd quorum."
  type        = number
  default     = 1
  validation {
    condition     = contains([1, 3], var.server_count)
    error_message = "server_count must be 1 or 3."
  }
}

variable "ami_id" {
  description = "Optional approved Amazon Linux 2023 AMI. Null selects the newest AWS-owned AL2023 AMI for the requested architecture at apply time."
  type        = string
  default     = null
  validation {
    condition     = var.ami_id == null ? true : can(regex("^ami-[a-f0-9]+$", var.ami_id))
    error_message = "ami_id must be null or an EC2 AMI identifier."
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
  description = "Optional EC2 instance type. Null selects m7i.large for amd64 or m7g.large for arm64."
  type        = string
  default     = null
  validation {
    condition     = var.instance_type == null ? true : can(regex("^[a-z][a-z0-9]*[0-9][a-z0-9.]*$", var.instance_type))
    error_message = "instance_type must be null or a valid-looking EC2 instance type."
  }
}

variable "kms_key_arn" {
  description = "Customer-managed KMS key used for root volumes and the short-lived RKE2 token rendezvous."
  type        = string
  validation {
    condition     = can(regex("^arn:[^:]+:kms:[^:]+:[0-9]{12}:key/.+$", var.kms_key_arn))
    error_message = "kms_key_arn must be a customer-managed AWS KMS key ARN."
  }
}

variable "associate_public_ip_address" {
  description = "Attach public IPs for direct outbound bootstrap. The module never creates public ingress. Keep false in private subnets with controlled egress."
  type        = bool
  default     = false
}

variable "additional_security_group_ids" {
  description = "Additional security groups attached to every server."
  type        = set(string)
  default     = []
  validation {
    condition     = alltrue([for id in var.additional_security_group_ids : can(regex("^sg-[a-f0-9]+$", id))])
    error_message = "additional_security_group_ids must contain AWS security group identifiers."
  }
}

variable "egress_ipv4_cidrs" {
  description = "IPv4 destinations reachable during connected bootstrap. Narrow this to reviewed mirrors or egress gateways in production."
  type        = set(string)
  default     = ["0.0.0.0/0"]
  validation {
    condition     = length(var.egress_ipv4_cidrs) > 0 && alltrue([for cidr in var.egress_ipv4_cidrs : can(cidrnetmask(cidr))])
    error_message = "egress_ipv4_cidrs must contain at least one valid IPv4 CIDR."
  }
}

variable "root_volume_gib" {
  description = "Encrypted gp3 root volume size for RKE2, etcd, images, and logs."
  type        = number
  default     = 100
  validation {
    condition     = var.root_volume_gib >= 40 && var.root_volume_gib <= 16384 && floor(var.root_volume_gib) == var.root_volume_gib
    error_message = "root_volume_gib must be an integer from 40 through 16384."
  }
}

variable "steward_release_version" {
  description = "Exact Steward release. The default is locked to this module's release."
  type        = string
  default     = null
  validation {
    condition = var.steward_release_version == null ? true : (
      length(var.steward_release_version) <= 128 &&
      can(regex("^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\\.([0-9A-Za-z-]+))*)?$", var.steward_release_version))
    )
    error_message = "steward_release_version must be null or one exact semantic release tag."
  }
}

variable "steward_installer_sha256" {
  description = "SHA-256 of install-steward.sh. Required when overriding steward_release_version."
  type        = string
  default     = null
  validation {
    condition     = var.steward_installer_sha256 == null ? true : can(regex("^[a-f0-9]{64}$", var.steward_installer_sha256))
    error_message = "steward_installer_sha256 must be null or 64 lowercase hexadecimal characters."
  }
}

variable "steward_release_origin" {
  description = "Credential-free release origin. The module appends /download/<version>/install-steward.sh."
  type        = string
  default     = "https://github.com/hardrails/steward/releases"
  validation {
    condition = (
      length(var.steward_release_origin) <= 384 &&
      can(regex("^https://[^/@[:space:]?#]+(/[^[:space:]?#]*)?$", var.steward_release_origin)) &&
      length(regexall("^https://[^/]*@", var.steward_release_origin)) == 0
    )
    error_message = "steward_release_origin must be a credential-free HTTPS URL without query or fragment."
  }
}

variable "rendezvous_ttl_hours" {
  description = "Lifetime of the encrypted server-token rendezvous. It expires automatically after initial cluster formation."
  type        = number
  default     = 2
  validation {
    condition     = var.rendezvous_ttl_hours >= 1 && var.rendezvous_ttl_hours <= 24 && floor(var.rendezvous_ttl_hours) == var.rendezvous_ttl_hours
    error_message = "rendezvous_ttl_hours must be an integer from 1 through 24."
  }
}

variable "bootstrap_timeout_minutes" {
  description = "Bound for downloads, first-server readiness, and token retrieval."
  type        = number
  default     = 45
  validation {
    condition     = var.bootstrap_timeout_minutes >= 15 && var.bootstrap_timeout_minutes <= 120 && floor(var.bootstrap_timeout_minutes) == var.bootstrap_timeout_minutes
    error_message = "bootstrap_timeout_minutes must be an integer from 15 through 120."
  }
}

variable "enable_session_manager" {
  description = "Attach AmazonSSMManagedInstanceCore so operators can inspect nodes without SSH."
  type        = bool
  default     = true
}

variable "permissions_boundary_arn" {
  description = "Optional IAM permissions boundary applied to both EC2 roles."
  type        = string
  default     = null
  validation {
    condition     = var.permissions_boundary_arn == null ? true : can(regex("^arn:[^:]+:iam::[0-9]{12}:policy/.+$", var.permissions_boundary_arn))
    error_message = "permissions_boundary_arn must be null or an IAM policy ARN."
  }
}

variable "tags" {
  description = "Non-secret tags applied to cluster resources."
  type        = map(string)
  default     = {}
}
