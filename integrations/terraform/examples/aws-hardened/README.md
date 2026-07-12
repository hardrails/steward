# Hardened AWS bootstrap example

This example creates a private EC2 instance with IMDSv2 required, hop limit one,
metadata tags disabled, and KMS-backed root storage. Supply security groups that
have no inbound Internet rule and only the outbound destinations required for your
internal package mirror and later enrollment.

The instance is staged, not enrolled. This is intentional: reusable credentials in
Terraform variables, user data, tags, outputs, or provisioners become recoverable
from Terraform state or EC2 console history. Deliver the enrollment bundle later
through your approved ephemeral channel (for example, a short-lived SSM session),
then run `/usr/local/libexec/steward/configure-node` and remove the bundle.

AWS account administrators and the EC2 hypervisor remain in the host trust boundary.
Use a future confidential-VM/attestation profile when the cloud operator itself must
be excluded; Docker plus gVisor cannot make that claim.
