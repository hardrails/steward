# 0037. Keep controller node placement state native and bounded

- Status: Superseded in part by [0038](0038-native-topology-placement-and-budgeted-drain.md)
- Date: 2026-07-20
- Rung: in-house

## Context

Steward's controller can now place delegated workloads across nodes, but it has
no durable operator control for planned maintenance or incident containment.
The existing Executor maintenance cordon is node-local: it correctly closes the
admission race on one host, but the controller can still select that node until
the node becomes stale. A compromised node must also be isolatable from new
command delivery without deleting its evidence identity.

## Decision

Store one bounded, controller-owned placement state on each node:
`schedulable`, `cordoned`, or `quarantined`. Site administrators change it
through explicit transitions. Cordon excludes only new placement. Quarantine
also makes assigned workloads unavailable to the reconciler and stops the
controller from leasing commands to that node; authenticated health and evidence
reports remain available for investigation. Reasons and transition times are
durable and visible to tenant operators.

This state complements, rather than replaces, Executor maintenance. A safe
planned procedure cordons the controller first and then enters the node-local
maintenance cordon before destroying exact runtimes.

**Tradeoff at this decision:** the narrow state machine fit Steward's signed
command and evidence boundaries without importing a general scheduler, but did
not yet provide Kubernetes-style eviction, topology spreading, or disruption
budgets. Decision 0038 adds a bounded subset of those operations.
**Rejected:** requiring Kubernetes or Nomad because Steward must retain a useful
single-host and air-gapped deployment; using only Executor maintenance because
the controller would keep scheduling until observation expiry; and revoking the
node for every incident because revocation also destroys the authenticated
evidence and recovery channel.

## Consequences

The control-store state and transaction formats advanced to version 8. Decision
0038 later added stateless controller-driven drain with disruption budgets; a
portable state backend is still required before stateful evacuation is safe.
