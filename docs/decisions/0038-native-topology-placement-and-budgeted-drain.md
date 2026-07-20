# 0038. Keep topology placement and budgeted drain in the narrow controller

- Status: Accepted
- Date: 2026-07-20
- Rung: in-house

## Context

Steward can place workloads within tenant-signed hard constraints and can cordon
or quarantine a node. It still treats every eligible node as equivalent except
for its assigned-workload count, and a cordoned node must be emptied through
manual runtime operations. That makes failure recovery safe, but planned fleet
maintenance remains slow and error-prone.

Kubernetes and Nomad already provide topology spreading, eviction, disruption
budgets, and rollout controllers. Requiring either would remove Steward's useful
single-host and small-fleet profile. Reimplementing their general scheduling
surface would add ownership without improving Steward's authority boundary.

## Decision

Decision: use `in-house` for a bounded topology scorer and restart-safe node
drain because both must be coordinated with Steward's tenant delegation,
instance generation, workload lease, transactional capacity check, and evidence
courier. Continue to use `native-platform` Docker, gVisor, and the existing
single-writer store. Rejected: a mandatory Kubernetes or Nomad control plane
because ordinary customer-owned Linux remains a supported production shape.

Tenant-signed placement may contain soft label preferences and one topology
label used for spreading replicas. Control records why it selected a node. Soft
preferences never make an otherwise ineligible node valid; Executor continues to
recheck hard isolation, label, taint, resource, and generation constraints.

A node drain first cordons the node, then moves only stateless instances whose
deployment disruption budget has room. Control records each in-progress move
before sending `stop`, completes `destroy`, advances the tenant-bounded instance
generation, and places the replacement through the normal scheduler. A restart
at any transition resumes from durable state. Control does not move persistent
state until a quota-capable snapshot backend exists.

**Tradeoff:** this closes the common small-fleet maintenance path with no new
service or dependency, but it deliberately omits preemption, autoscaling,
surge-based zero-downtime rollout, and stateful migration.

## Consequences

- A tenant can express preferred failure domains without weakening hard
  placement policy.
- Operators can explain a selected node from retained controller state.
- Planned drain respects each deployment's maximum unavailable instances and
  fails closed for stateful workloads or exhausted generation authority.
- A stateless drain may have bounded downtime because Steward does not invent an
  undelegated surge replica.
- Canceling a node drain stops new moves; an instance already being stopped
  continues forward because reversing an ambiguous lifecycle effect is unsafe.

Revisit the in-house scheduler when supported users require preemption,
autoscaling, scheduler high availability, or cluster-scale placement. Revisit
stateful drain after a ZFS, CSI, or equivalent backend passes quota, snapshot,
clone, lineage, and authority-scrubbing conformance.
