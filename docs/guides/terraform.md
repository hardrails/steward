---
title: Bootstrap Steward with Terraform
description: Provision secret-free Steward cloud nodes with provider-neutral cloud-init, an AWS hardened example, and a safe boundary for a future Terraform provider.
section: How-to
---

# Bootstrap Steward with Terraform

Steward ships a provider-neutral module at
`integrations/terraform/modules/steward-node`. It renders cloud-init that pins the
installer by SHA-256 and Steward by exact release tag.

```hcl
module "steward" {
  source           = "./steward/integrations/terraform/modules/steward-node"
  release_version  = "v1.4.0"
  installer_url    = "https://mirror.example/steward/install-steward.sh"
  installer_sha256 = var.steward_installer_sha256
  bootstrap_mode   = "stage"
}

resource "example_linux_server" "agent_node" {
  user_data = module.steward.cloud_init
}
```

`stage` installs versioned files but does not enroll, configure, or start the node.
This is the production default. Deliver enrollment credentials later through an
authenticated ephemeral channel, run the transactional node configurator, and
remove the bundle. Terraform stores variables and rendered user data in state; do
not pass bearer tokens, private keys, credentials, or secret-manager results into
the module.

`local` creates a loopback-only evaluation node and generates host-local tokens on
first boot. It does not enable signed tenant admission automatically because a
workload node should not invent the enterprise site root that authorizes itself.

## AWS hardened example

`integrations/terraform/examples/aws-hardened` demonstrates a private EC2 instance
with no public IP, IMDSv2 required, hop limit one, metadata tags disabled, and a
KMS-encrypted root device. Supply security groups with no public inbound rule and
only the outbound destinations needed for your internal package mirror and
enrollment service.

Steward's agent egress proxy also blocks private, loopback, link-local, and metadata
addresses by default. This protects against ordinary SSRF and hostile networks. It
does not protect node memory or keys from AWS account administrators, host root, or
the hypervisor. Excluding those actors requires confidential VMs, measured boot,
remote attestation, and attestation-bound enrollment; Docker + gVisor alone cannot
make that claim.

## Why there is no in-repository Terraform provider yet

The Executor API intentionally binds loopback and uses a host-administrator token.
Exposing it remotely just so Terraform can create an instance would weaken the
boundary. A future provider belongs in a separate Go module/repository because the
Terraform SDK must not enter Steward's zero-dependency binary. Its resource model
should be:

- create: submit signed capsule + instance intent;
- read: observe admitted generation, immutable digests, effective grants, and state;
- update: replace with a strictly higher generation, never mutate a container in place;
- delete: destroy workload while retaining or explicitly purging lineage state;
- import: use tenant/node/instance identity, not a raw Docker name;
- credentials: mTLS or attestation-bound short-lived identity, never the loopback token.

Terraform is appropriate for servers, disks, security groups, and node bootstrap.
Steward remains responsible for dynamic agent lifecycle, crash reconciliation,
generation fencing, and enforcement receipts.
