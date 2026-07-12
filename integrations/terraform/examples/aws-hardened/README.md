# Hardened AWS bootstrap example

This example creates a private Amazon Elastic Compute Cloud (EC2) instance with
Instance Metadata Service v2 (IMDSv2) required, metadata hop limit one, metadata
tags disabled, and Key Management Service (KMS)-backed root storage. Supply
security groups with no inbound rule from the public Internet and allow only the
outbound destinations required for your internal package mirror and later
enrollment. The example requires independently
pinned URLs and SHA-256 values for the installer, release package, and checksum
manifest, so first boot does not fall back to a public release endpoint.
Set `artifact_url`, `artifact_sha256`, `checksum_manifest_url`, and
`checksum_manifest_sha256` from the same approved release bundle; the module
rejects incomplete or malformed pins.

The instance is staged, not enrolled. This is intentional: reusable credentials in
Terraform variables, user data, tags, outputs, or provisioners become recoverable
from Terraform state or EC2 console history. Deliver the enrollment bundle later
through your approved temporary channel, such as a short-lived AWS Systems Manager
Session Manager session,
then run `/usr/local/libexec/steward/configure-node` and remove the bundle.

Later rendered user-data changes are ignored rather than applied to the enrolled EC2
instance, and the bootstrap script records successful completion so it cannot be
replayed accidentally. Apply software upgrades through Steward's staged release
workflow; replacing this resource would also replace its enrolled root-disk state.

AWS account administrators and the EC2 hypervisor remain in the host trust boundary.
Steward does not currently exclude the cloud operator. If that threat is in scope,
use a separately evaluated confidential-VM and remote-attestation enrollment design;
Steward does not provide one. Docker plus gVisor cannot make that claim.
