---
title: Reuse cloud secret rendezvous for cluster bootstrap
description: Why Terraform creates cluster infrastructure while nodes exchange short-lived RKE2 join material through a cloud-native encrypted parameter.
section: Architecture decision
---

# Reuse cloud secret rendezvous for cluster bootstrap

- Status: Accepted
- Date: 2026-07-25
- Rung: native-platform

## Context

An operator should be able to turn ordinary cloud instances into a working
Steward management cluster with one Terraform apply. The RKE2 server token needed
by joining servers is secret material. Terraform variables, rendered user data,
resource attributes, provisioners, and outputs are retained in state or cloud API
history, even when Terraform marks a value as sensitive. Putting the token in any
of those places would make the easy path weaker than the manual installer.

Cloud providers already supply instance identity, encrypted secret storage,
machine lifecycle, and session access. Steward's differentiating responsibility is
the deterministic, pinned, fail-closed transition from a clean host to a healthy
cluster node.

## Decision

Decision: use `native-platform` for the first AWS implementation. Terraform
creates EC2 instances, least-privilege instance profiles, a KMS-encrypted
Parameter Store rendezvous, and the required private cluster network rules. The
first server publishes its RKE2-generated server token directly from the host to
an expiring `SecureString`. Joining servers retrieve it at boot through their EC2
identity. The plaintext never crosses Terraform.

Steward owns the checksum-pinned release bootstrap, pinned gVisor installation,
bounded wait and retry behavior, RKE2 installation, node doctor, completion
markers, and actionable outputs. The module accepts an existing VPC, subnets, and
KMS key. A separate quick-start example creates disposable networking so a new
operator can run the same module without first becoming an AWS networking expert.

**Tradeoff:** this adds one cloud-specific integration while keeping authority out
of Terraform state and avoiding a new always-on bootstrap service.

**Rejected:** generating or reading the token through Terraform because sensitive
values remain state data. Rejected: a custom Steward secret broker because AWS
already provides encrypted storage, instance authentication, audit logs, and
availability for this short bootstrap exchange. Rejected: remote-exec provisioners
because they require inbound administration and make retry ownership ambiguous.

## Consequences

- One `terraform apply` can form a one- or three-server AWS management cluster
  without SSH, a prebuilt Steward image, or a token variable.
- AWS IAM, KMS, SSM, and the account administrator are inside this bootstrap trust
  boundary. Operators that do not accept that boundary use the existing offline
  installer and their own credential-transfer ceremony.
- The rendezvous expires after initial formation. Replacing a server later is a
  reviewed RKE2 recovery or join operation, not a replay of first-boot user data.
- Provider-specific modules may implement the same contract with equivalent native
  services. The core cluster installer remains cloud-neutral.
- Revisit if Steward gains attestation-backed node enrollment or if a portable
  secret exchange can reduce cloud authority without adding an always-on service.
