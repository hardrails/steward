---
title: "ADR 0059: Require independent elastic-pool membership"
description: Why Steward counts signed, node-specific membership instead of treating provider labels or Control as fleet authority.
section: Architecture decision
---

# ADR 0059: Require independent elastic-pool membership

- Status: Accepted
- Date: 2026-07-22
- Rung: in-house

## Context

An infrastructure provider can create machines and attach labels, but those
facts do not prove that a machine has the approved boot image, scheduling policy,
tenant scope, or Steward identity. Control can also be compromised. Letting
either source declare pool membership would turn an operational convenience into
authority to expand the fleet.

Reusable join tokens are worse: cloud metadata, user data, Terraform state, or
one compromised node could expose a credential able to enroll siblings.

## Decision

Each provider-neutral `NodePool` may name an independent Ed25519 membership
authority. A short-lived DSSE statement binds one Control instance, exact pool
membership generation and creation identity, node, canonical tenant set,
architecture, boot identity digest, scheduling-policy digest, and validity
window. The node presents the exact statement with its own enrolled credential.
Control retains the envelope and rejects signature failure, scope changes,
expiry, renewal rollback within one pool lineage, and disagreement with the
node's current authenticated boot and scheduling-policy observation. Executor
derives the scheduling-policy digest from its effective limits; a provisioning
or measured-boot integration supplies the boot identity.

When a pool configures this authority, `scale_out_needed` counts only eligible
members. Label-only nodes remain visible as `membership_unverified`, but they do
not satisfy desired capacity or become scale-in candidates.

The statement does not grant workload authority. Tenant delegations continue to
name exact node IDs. A later pool-scoped delegation must be verified by Executor
against the same statement before it can replace that finite set.

## Consequences

- Control and provider labels cannot independently make a node eligible.
- There is no reusable pool secret to steal from a machine image or node.
- Operators can verify the retained envelope without trusting Control's status.
- A separate signer or workload-identity adapter must verify boot claims.
  Steward compares the signed value with Executor's current authenticated
  report and recomputes the scheduling-policy digest, but it does not measure
  the machine or turn a self-report into hardware attestation.
- Tenant, architecture, or authority changes increment a separate membership
  generation and require new node statements. Capacity-only updates do not
  invalidate otherwise valid membership.
- Automatic cloud attestation and pool-scoped placement remain explicit
  follow-on work rather than implied security claims.
