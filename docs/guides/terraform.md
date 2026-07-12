---
title: Bootstrap Steward with Terraform
description: Render non-secret Steward bootstrap data with provider-neutral cloud-init, an AWS EC2 example, and a security boundary for a future Terraform provider.
section: How-to
---

# Bootstrap Steward with Terraform

The provider-neutral module at `integrations/terraform/modules/steward-node`
generates cloud-init that pins the installer by SHA-256 and Steward by exact release
tag.

```hcl
module "steward" {
  source           = "./steward/integrations/terraform/modules/steward-node"
  release_version  = "<release-tag>"
  installer_url    = "https://mirror.example/steward/install-steward.sh"
  installer_sha256 = var.steward_installer_sha256
  bootstrap_mode   = "stage"
  release_mirror = {
    artifact_url    = "https://mirror.example/steward-node_<tag>_amd64.deb"
    artifact_sha256 = var.steward_artifact_sha256
    manifest_url    = "https://mirror.example/checksums.txt"
    manifest_sha256 = var.steward_manifest_sha256
  }
}

resource "example_linux_server" "agent_node" {
  user_data = module.steward.cloud_init
}
```

`stage` installs versioned files without enrolling, configuring, or starting the
node. The base image must already provide systemd and a local `docker` group; the
Docker daemon does not need to run during staging. This is the production default.
Later, deliver enrollment credentials through an authenticated temporary channel
and run `configure-node`, which restores the prior configuration if validation
fails. Remove the enrollment bundle afterward. Terraform stores variables and
rendered user data in state, and a cloud provider may retain user-data history.
Never pass bearer tokens, private keys, credentials, secret-manager results, or
authenticated URLs to this module.
The mirror object is optional. When present, cloud-init verifies both
artifact and manifest hashes before the installer confirms that the manifest lists
the artifact. It never falls back to a public release endpoint.

For a multi-tenant Executor, deliver the enrollment bundle through that separate
channel and apply it in one host-local transaction:

```console
sudo /usr/local/libexec/steward/configure-node \
  --control-plane-url https://control.customer.example \
  --steward-credential /secure/enrollment/steward.json \
  --executor-credential /secure/enrollment/executor-node.json \
  --ca-file /secure/enrollment/control-plane-ca.pem \
  --admission-policy /secure/enrollment/site-policy.dsse.json \
  --site-root-public-key /secure/enrollment/site-root.public \
  --site-root-key-id site-root-1 \
  --node-id node-a
```

The node-scoped credential's node ID must match `--node-id` and every signed
instance and command statement. The site policy does not contain a node ID. Include
tenant command public keys with explicit operation scopes in that site-root-signed
policy, and require verified HTTPS. Tenant signing private keys stay in the control
plane and never enter Terraform state or cloud-init. Delete the delivered bundle
after successful configuration.

`local` creates a loopback-only evaluation node and generates host-local tokens on
first boot. It does not enable signed tenant admission because a workload node must
not create the site root key that authorizes itself. Staged bootstrap does
not touch Docker, so `install_gvisor = true` is invalid with
`bootstrap_mode = "stage"`. Preinstall gVisor in the machine image.

## AWS hardened example

`integrations/terraform/examples/aws-hardened` creates a private Amazon Elastic
Compute Cloud (EC2) instance with no public IP. It requires Instance Metadata
Service v2 (IMDSv2), sets the metadata
hop limit to one, disables metadata tags, and encrypts the root device with an AWS
Key Management Service (KMS) key. Supply existing security groups with no public
inbound rule and allow outbound traffic only to the internal package mirror and
enrollment service.

The example records a root-owned completion stamp and rejects a symlinked marker. A
successful stamp uses the installed release manifest's version and is written only
after that value matches the requested release tag. A
change to rendered user data does not replace the instance, and later user-data
drift is ignored. Upgrade through Steward's staged release workflow instead of
replaying first-boot enrollment.

Steward's agent egress proxy blocks private, loopback, link-local, and metadata
addresses by default. This limits ordinary server-side request forgery (SSRF) and
exposure to hostile networks. It cannot protect node memory or keys from AWS account
administrators, host root, or the hypervisor. Defending against those actors
requires confidential VMs, measured boot, remote attestation, and enrollment that
issues credentials only after verifying that attestation. Steward does not yet
implement that attestation-bound enrollment. Docker plus gVisor does not provide
the guarantee by itself.

## Why there is no in-repository Terraform provider yet

Executor intentionally binds its API to loopback and uses a host-administrator
token. Exposing that API remotely for Terraform would weaken this boundary. A
future provider belongs in a separate Go module or repository so the Terraform SDK
does not enter Steward's zero-dependency binary. Its resource model should be:

- create: submit signed capsule + instance intent;
- read: observe admitted generation, immutable digests, effective grants, and state;
- update: replace with a strictly higher generation, never mutate a container in place;
- delete: destroy workload while retaining or explicitly purging its
  persistent-state lineage;
- import: use tenant/node/instance identity, not a raw Docker name;
- credentials: mutual TLS (mTLS) or attestation-bound short-lived identity, never
  the loopback token.

Use surrounding Terraform configuration for servers, disks, and security groups;
use this module for node bootstrap data. Steward handles dynamic agent lifecycle,
crash reconciliation, generation fencing, and enforcement receipts.
