variable "ami_id" { type = string }
variable "subnet_id" { type = string }
variable "security_group_ids" { type = list(string) }
variable "kms_key_id" { type = string }
variable "installer_url" { type = string }
variable "installer_sha256" { type = string }
variable "steward_version" { type = string }
variable "artifact_url" { type = string }
variable "artifact_sha256" { type = string }
variable "checksum_manifest_url" { type = string }
variable "checksum_manifest_sha256" { type = string }

module "steward" {
  source           = "../../modules/steward-node"
  release_version  = var.steward_version
  installer_url    = var.installer_url
  installer_sha256 = var.installer_sha256
  bootstrap_mode   = "stage"
  release_mirror = {
    artifact_url    = var.artifact_url
    artifact_sha256 = var.artifact_sha256
    manifest_url    = var.checksum_manifest_url
    manifest_sha256 = var.checksum_manifest_sha256
  }
}

resource "aws_instance" "steward" {
  ami                         = var.ami_id
  instance_type               = "m7i.large"
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = var.security_group_ids
  associate_public_ip_address = false
  user_data                   = module.steward.cloud_init
  # Enrollment state lives on the root disk. A later bootstrap-template change
  # must never replace a running node; upgrades use Steward's release activator.
  user_data_replace_on_change = false

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    encrypted  = true
    kms_key_id = var.kms_key_id
  }

  lifecycle {
    # User data is a first-boot transport, not an upgrade channel. Ignoring
    # later template changes prevents replacement or a provider-driven reboot.
    ignore_changes = [user_data]
  }

  tags = { Name = "steward-node" }
}
