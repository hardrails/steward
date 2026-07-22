---
title: "ADR 0058: Separate node-pool capacity from workload authority"
description: Why Steward models provider-neutral desired capacity without treating self-reported node labels or a cloud autoscaler as tenant execution authority.
section: Architecture decision
---

# ADR 0058: Separate node-pool capacity from workload authority

- Status: Accepted
- Date: 2026-07-21
- Rung: in-house

## Context

Steward already schedules across recent authenticated node observations and
atomically reserves locally enforced resources. Tenant-signed controller
delegations still name a finite set of exact node IDs. That finite scope is a
security property: compromising Control cannot authorize the tenant workload on
a newly invented node.

Elastic fleets need a provider-neutral desired-capacity contract, but cloud
instances currently choose their own scheduling labels. Treating a matching
label as execution authority would let a compromised Control enroll a node,
claim a pool label, and widen a tenant delegation. Coupling Steward directly to
an AWS, Azure, Google Cloud, Kubernetes, or Nomad autoscaler would also make an
otherwise portable control plane depend on one infrastructure authority.

## Decision

Build a bounded `NodePool` resource in Control that declares a desired, minimum,
and maximum node count for one reserved pool label. Control derives registered
and ready counts from existing authenticated scheduling observations. It exposes
an exact scale-out deficit and names scale-in candidates only after a node is
drained, empty, and still belongs to that pool. Each observation returns no more
scale-in candidates than the current surplus above desired capacity.

The resource is operational intent, not workload authority. It does not create
machines, issue enrollment credentials, expand a tenant delegation, or authorize
instance placement. Existing exact-node delegation checks remain unchanged.
Provider drivers may poll the public API and reconcile infrastructure, but must
not destroy a node unless Steward names it as a post-drain scale-in candidate.

**Tradeoff:** Operators gain one stable contract for Terraform, Cluster API,
autoscaling groups, bare-metal controllers, and offline provisioning without
giving Control new signing authority. Fully automatic placement onto newly
created nodes remains blocked until Steward ships offline-verifiable pool
membership that both Control and Executor validate.

**Rejected:** mandatory Kubernetes or Nomad, because Steward still needs the same
authority and evidence contract when neither exists. Rejected direct cloud SDKs,
because they add vendor credentials and dependencies to Control. Rejected
self-reported labels as tenant authority, because Control compromise could then
widen placement. Rejected implementing a general infrastructure autoscaler,
because provider lifecycle and quota behavior belong in a replaceable driver.

## Consequences

The first `NodePool` implementation is useful for capacity reconciliation and
safe scale-in coordination but deliberately does not make elastic workload
placement automatic. Documentation and API descriptions must keep that boundary
explicit.

The short-lived node membership statement is now implemented as described in
[ADR 0059]({{ '/decisions/0059-independent-elastic-pool-membership/' | relative_url }}).
It makes provider capacity accounting independently verifiable. Before enabling
pool-scoped delegation, Executor must also verify its own membership and the
tenant's pool-scoped delegation without trusting Control's interpretation. A
cloud workload identity may supply attestation evidence, but must sit behind the
vendor-neutral statement rather than becoming the protocol.
