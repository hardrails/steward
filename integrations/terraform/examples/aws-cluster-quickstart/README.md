# AWS cluster quick start

This complete example creates a VPC, three subnets, Internet egress, a
customer-managed KMS key, and a one- or three-server Steward management cluster.
It creates no SSH key and no public ingress rule. EC2 instances use temporary
public addresses only for connected outbound bootstrap; operate them through AWS
Systems Manager Session Manager.

Configure an AWS CLI profile or environment credentials and select a region:

```console
export AWS_REGION=us-west-2
./up.sh
```

The wrapper initializes Terraform, shows the complete plan, asks for approval,
applies it, waits through Session Manager, and runs the real Steward cluster
doctor on every server. Use three servers:

```console
./up.sh --ha
```

For non-interactive automation, add `--yes`. This creates billable resources, so
review `terraform plan` and your AWS account before using it.

If Terraform is already your normal workflow:

```console
terraform init
terraform apply
./wait.sh
```

The default one-server topology is for evaluation and does not survive server
loss. The three-server topology forms an etcd quorum across three availability
zones. The example deliberately optimizes first use and cost clarity rather than
private-network architecture: instances have public IPs but a security group with
no public ingress. For production, call the underlying
`aws-steward-cluster` module from your own private subnets, keep public IPs
disabled, and route connected bootstrap through reviewed NAT or egress gateways.

Destroy the example when finished:

```console
./down.sh
```

The wrapper deletes the encrypted SSM rendezvous without reading it, then shows
the Terraform destroy plan. Use `./down.sh --yes` in automation. If you run
`terraform destroy` directly, the rendezvous still expires automatically.
AWS may bill for EC2, EBS, public IPv4, KMS, detailed monitoring, and the
short-lived Advanced Parameter Store value until resources or the parameter are
removed.
