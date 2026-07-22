# AWS Steward node pool

This module creates a private, multi-zone EC2 Auto Scaling Group from an existing
AMI, subnets, security groups, KMS key, and exact Steward release. It uses IMDSv2,
metadata hop limit one, encrypted gp3 storage, detailed monitoring, launch-template
versioning, and an Auto Scaling Group that can span private subnets.

The machine image must already contain Docker, gVisor, systemd, cloud-init, curl,
`timeout`, and `sha256sum`. The module stages Steward but does not enroll nodes.
That separation keeps enrollment credentials and private keys out of Terraform
state, launch-template user data, and EC2 console history.

```hcl
module "steward_nodes" {
  source = "./steward/integrations/terraform/modules/aws-steward-node-pool"

  name               = "agents-prod"
  ami_id             = var.approved_steward_ami
  subnet_ids         = var.private_subnet_ids
  security_group_ids = [aws_security_group.steward_nodes.id]
  kms_key_arn        = aws_kms_key.steward_nodes.arn

  release_version  = var.steward_release
  installer_url    = var.steward_installer_url
  installer_sha256 = var.steward_installer_sha256
  release_mirror   = var.steward_release_mirror
}
```

New instances are VM-healthy before they are Steward-ready. Enroll each node and
run the node doctor before expecting Control to place work there. EC2 health alone
must not be used as proof of enrollment or policy continuity. Do not enable
automatic scale-in until its termination workflow cordons and drains the selected
node. Terraform creates initial capacity but ignores later `min_size`,
`desired_capacity`, and `max_size` changes, and it does not start instance refresh.
After a drain, use an explicit Auto Scaling operation to terminate or replace that
exact instance. The module deliberately creates no cloud-specific Lambda or shared
join credential.
