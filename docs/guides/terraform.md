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
Later, deliver the node credential, evidence config, receipt key pair, CA, and
signed-admission trust through an authenticated temporary channel and run
`configure-node`, which restores the prior configuration if validation fails.
Remove the enrollment handoff afterward. Terraform stores variables and rendered
user data in state, and a cloud provider may retain user-data history. Never pass
bearer tokens, private keys, credentials, secret-manager results, or authenticated
URLs to this module.
The mirror object is optional. When present, cloud-init verifies both
artifact and manifest hashes before the installer confirms that the manifest lists
the artifact. It never falls back to a public release endpoint.

## Bootstrap the controller host without putting authority in state

The provider-neutral module at
`integrations/terraform/modules/steward-control` renders cloud-init for one
systemd Linux controller host. It creates no cloud resources and requires no
provider. Pass its output to the user-data field of the server resource managed by
your chosen provider:

```hcl
variable "steward_release_tag" {
  type = string
}

variable "steward_control_installer_sha256" {
  type = string
}

variable "steward_control_manifest_sha256" {
  type = string
}

module "steward_control" {
  source = "./steward/integrations/terraform/modules/steward-control"

  release_version = var.steward_release_tag
  installer_url = format(
    "https://github.com/hardrails/steward/releases/download/%s/install-control.sh",
    var.steward_release_tag,
  )
  installer_sha256 = var.steward_control_installer_sha256
  manifest_sha256  = var.steward_control_manifest_sha256
}

resource "example_linux_server" "control" {
  user_data = module.steward_control.cloud_init
}
```

The module accepts one exact semantic release tag plus independently obtained
SHA-256 values for `install-control.sh` and that release's `checksums.txt`. It
always verifies the manifest before running the installer and passes the verified
local file to it. The manifest binds the controller archive bytes, so replacing the
manifest and archive together at a mutable release origin does not bypass the
out-of-band pin. Each fetch disables curl configuration files, applies an
operating-system file-size limit, removes partial failures, and accepts only a
non-empty, single-link regular file within that limit. Release tags are capped at
128 characters. Download URLs must be credential-free printable ASCII HTTP(S),
contain no query or fragment, and be at most 512 characters. Rendered cloud-init is
limited to 16 KiB raw and
21,848 bytes after base64 encoding. An optional `release_mirror` supplies the
controller archive URL and independent archive pin plus the manifest URL; it uses
the same required top-level manifest pin and never falls back to a public artifact.

Bootstrap installs and starts the controller only on
`http://127.0.0.1:8443`. It creates or recovers the first site-administrator token
at `/root/steward-control-admin.token`, proves that bearer against the bounded
loopback tenant-list API, and only then writes a root-only completion marker bound
to the release and controller binary digest. The bearer is supplied to the probe
through standard input rather than process arguments and is not printed. Terraform
outputs only the token path, loopback endpoint, marker path, and handoff
instructions. Before each request and after a successful response, bootstrap
requires systemd's active `MainPID`, `/proc` executable, service UID, exact
loopback process arguments, and root-owned installed configuration to agree. The
pinned installer has already proved the credential against an ephemeral instance
of that installed binary before publishing the token file.

If first boot is interrupted before the completion marker, replay re-enters the
installer's bounded bootstrap-recovery path and must prove the recovered token
against the running controller before completion. A replay of a completed bootstrap
validates the same release and binary digest without downloading or rerunning the
installer. A different release fails: cloud-init is not an upgrade mechanism.

Retrieve the token through an authenticated host channel, move it to protected
operator storage, and remove the host copy. Use an authenticated SSH tunnel for the
loopback API, or deliver the TLS certificate and owner-only key through a separate
secret channel, stage both as root-owned single-link files under a root-owned
non-writable directory chain, and reconfigure with `install-control.sh`. Never
expose the loopback HTTP listener directly.

Host root, systemd, and the kernel remain trusted. The fixed-listener identity
checks run before each request and after a successful response. They sharply narrow
and reject ordinary listener substitution, but cannot eliminate the scheduling
window between the final check and connection or defend against an actor that can
forge systemd or `/proc` state. Do not place site-administrator authority on a host
whose operating-system control plane is outside your trust boundary.

Do not pass the site-administrator bearer, operator bearers, enrollment
capabilities, TLS private key, CA private key, or tenant command keys through
Terraform variables, data sources, provisioners, outputs, or cloud-init. Terraform
state and cloud user-data history can retain those values after configuration is
removed. Keep `/var/lib/steward-control` on persistent encrypted storage and treat
server replacement as a restore or a fresh site, not an in-place update.

The public controller API is suitable for an independently implemented Terraform
provider, but Steward ships no provider. Creating tenants and reading inventory are
conventional resource operations. Secret issuance and signed command delivery are
not: response loss, retries, and destroy semantics can consume or revoke authority.
Any future provider must expose stable request IDs, write secrets only to an
explicit secure destination, mark them sensitive, and retain enough state to retry
the same issuance instead of minting another credential.

Validate the controller module after changing it:

```console
bash integrations/terraform/modules/steward-control/tests/test.sh
```

The script always runs static secret-boundary checks. When Terraform is installed,
it also runs formatting, validation, public and mirrored renders, authenticated
handoff checks, maximum-size rendering, and negative-input cases.

For a multi-tenant Executor, deliver the enrollment bundle through that separate
channel and apply it in one host-local transaction:

```console
sudo /usr/local/libexec/steward/configure-node \
  --control-plane-url https://control.customer.example:8443 \
  --executor-credential /secure/enrollment/executor-node.json \
  --ca-file /secure/enrollment/control-plane-ca.pem \
  --admission-policy /secure/enrollment/site-policy.dsse.json \
  --site-root-public-key /secure/enrollment/site-root.public \
  --site-root-key-id site-root-1 \
  --node-id node-a \
  --executor-evidence-config /secure/enrollment/executor-evidence.env \
  --executor-evidence-private-key /secure/enrollment/node-receipts.private.pem \
  --executor-evidence-public-key /secure/enrollment/node-receipts.public
```

The node-scoped credential's node ID must match `--node-id`, the evidence handoff,
and every signed instance and command statement. The receipt key pair is created
outside Terraform and delivered through the same short-lived authenticated
channel. The site policy does not contain a node ID. Include tenant command public
keys with explicit operation scopes in that site-root-signed policy, and require
verified HTTPS. Tenant signing private keys stay on a trusted signing station or
separate signing service; they enter neither Steward Control nor Terraform state or
cloud-init. Delete the delivered handoff bundle after successful configuration.

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
