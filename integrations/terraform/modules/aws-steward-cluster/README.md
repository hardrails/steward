# AWS Steward management cluster

This module turns one or three Amazon Linux 2023 instances into Steward's pinned,
hardened RKE2 management cluster. It creates the instances, private cluster
security group, least-privilege EC2 roles, encrypted root volumes, gVisor runtime,
and an expiring join-token rendezvous. It does not require SSH or put plaintext
join credentials in Terraform state.

```hcl
module "steward_cluster" {
  source = "./steward/integrations/terraform/modules/aws-steward-cluster"

  name         = "agents"
  vpc_id       = var.vpc_id
  subnet_ids   = var.subnet_ids
  server_count = 3
  kms_key_arn  = aws_kms_key.steward_cluster.arn
}
```

Run `terraform apply`, wait for cloud-init, then use the emitted
`session_commands` and `doctor_commands`. The module selects an AWS-owned Amazon
Linux 2023 AMI by default, installs required signed operating-system packages,
verifies the exact Steward installer SHA-256, verifies a pinned gVisor archive
SHA-512 and inventory, and delegates RKE2 installation to Steward's existing
cluster installer.

For a reviewed production image, set `ami_id` explicitly. Keep
`associate_public_ip_address = false` and use private subnets with controlled
HTTPS egress or approved mirrors. The included quick-start example uses public
egress with zero public ingress to avoid requiring a NAT gateway for an evaluation
cluster.

## Secret boundary

The first server receives an IAM role that can write one exact SSM parameter.
Joining servers can read only that parameter. KMS permissions are limited to the
supplied key. The first server publishes its RKE2-generated token as an Advanced
`SecureString` with an expiration policy. Terraform records the parameter name,
not its value. AWS account administrators, IAM, KMS, SSM, EC2, and the hypervisor
remain in the bootstrap trust boundary.

Do not add the token as a Terraform variable, output, provisioner argument, or
managed `aws_ssm_parameter.value`. Terraform's `sensitive` marker hides display;
it does not remove a value from state.

The rendezvous is for initial formation. After it expires, replacing a server
requires the documented RKE2 backup/recovery or secure join procedure. First-boot
user data is intentionally ignored after creation and is not an upgrade channel.

The module records `server_count` and the exact Steward release identity in
Terraform state on the first apply. Later plans fail before changing
infrastructure if those values differ. This prevents Terraform from terminating
embedded-etcd members without coordinated removal, adding members after the
short-lived join rendezvous has expired, or changing release tags and outputs
without upgrading the hosts.

Do not scale this management cluster by changing `server_count`, and do not
upgrade it by changing `steward_release_version`. Use a reviewed RKE2 membership
procedure for topology changes.

For a software upgrade, first follow Steward's documented node upgrade procedure
on every server and verify the cluster. Then update the pinned version and hash
and reconcile Terraform's non-secret record:

```console
terraform apply \
  -replace=module.steward_cluster.terraform_data.release_contract
```

Review the complete plan before approving it. The separate topology contract
still rejects a `server_count` change. When retaining the existing cluster is
unnecessary, `terraform destroy` remains available even if the requested
formation values have changed; recreate the cluster from reviewed inputs.

## Costs and prerequisites

The module creates EC2 instances and one short-lived Advanced Parameter Store
parameter. The caller supplies the VPC, subnets, and customer-managed KMS key.
Detailed EC2 monitoring is enabled. Public IPv4 addresses, NAT gateways, instance
hours, storage, KMS, and Parameter Store may incur AWS charges.

The Terraform identity needs permission to manage EC2, security groups, IAM roles
and instance profiles, and to pass the created roles to EC2. The instances need
connected HTTPS egress to the Steward release, the pinned RKE2 and gVisor
artifacts, Amazon Linux repositories, and AWS APIs. Use the manual air-gap workflow
when those destinations are unavailable.
