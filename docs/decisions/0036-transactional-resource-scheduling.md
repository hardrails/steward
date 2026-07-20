# Transactional resource scheduling

## Status

Accepted.

## Date

2026-07-20.

## Rung

In-house, built on Steward's existing Executor limits, tenant-signed delegation,
generation fence, durable Control store, and HTTP transport.

## Context

Control currently filters eligible nodes and chooses the node with the fewest
assigned instances. Executor independently checks per-workload, per-tenant, and
host CPU, memory, process, and workload limits before it creates a container.
This fails closed, but it is not a scheduler: Control can repeatedly choose a
node that cannot accept the workload, and concurrent reconciliation can
overcommit capacity before either command reaches Executor.

Kubernetes and Nomad provide mature general-purpose scheduling. They do not,
however, enforce Steward's tenant-signed delegation, instance generation,
finite workload lease, Gateway authority, or evidence chain. Making either one
mandatory would also remove Steward's single-host installation and macOS
development profile. A database or message broker would add an operational
dependency without fixing the authority boundary.

The capacity ceiling already exists in `executor.HostPolicy`. Duplicating it as
manually maintained Control configuration would create two sources of truth.
Treating a scheduler decision as authority would be unsafe because unmanaged
containers and stale observations can still consume host resources.

## Decision

Decision: use `in-house` for narrow, transactional resource scheduling because
the reservation must be coordinated with Steward's signed admission and
generation fence. Use `built-in` Steward components for persistence and
transport. Rejected: a mandatory Kubernetes or Nomad control plane, a second
database, a message broker, and a second capacity configuration surface.

Executor publishes a bounded, authenticated scheduling observation for its
node. The observation reports the exact host and tenant ceilings already
enforced by `HostPolicy`, together with scheduling attributes such as
architecture, isolation, labels, and taints. Control records when it received
the observation; a node cannot choose an earlier trusted timestamp. Publishing
capacity is best effort and never blocks command polling or workload-lease
renewal.

Control requires a recent scheduling observation before placing a new
instance. Existing assigned instances remain manageable when observations are
missing or stale, so an upgrade or temporary telemetry failure cannot prevent a
lease renewal, stop, or destroy. Nodes running an older Executor therefore keep
their existing workloads but do not receive new placements until they upgrade.

Control reserves CPU, memory, process, tenant, and workload-slot capacity in the
same durable transaction that advances an instance to admission and inserts its
signed command. The reservation is derived from the retained instance intent
and node assignment rather than stored as a second mutable record. Concurrent
reconcilers recheck capacity while holding the store mutex, so at most the
available capacity can be admitted. Executor remains authoritative at execution
time and rechecks actual Docker usage; this protects against unmanaged
workloads, observation drift, and a stale Control decision.

A reservation is released only after Steward has durable evidence that the
workload is absent, or after a generation-bound lease has expired and the
instance is safely replaced. Failed and outcome-unknown mutations retain their
reservation because the workload may still exist. This favors safety over
utilization and gives operators an explicit degraded condition to investigate.

Scheduling covers the resources Executor can enforce portably today: CPU,
memory, process count, workload count, and per-tenant equivalents. Disk and
persistent-state byte quotas are excluded. Docker volumes do not provide a
portable hard-quota contract, so advertising disk capacity would imply an
isolation guarantee Steward cannot provide. Revisit disk scheduling with a
quota-capable ZFS, CSI, or equivalent storage backend and a conformance suite.

Revisit an external scheduler backend when users require preemption,
autoscaling, high-availability scheduler consensus, or cluster-scale placement.
Any backend must pass the same conformance contract: tenant authority cannot be
widened, admission and reservation are atomic, ambiguous effects remain
reserved, and generation fencing precedes replacement.

## Consequences

- Control can explain why a workload cannot fit before sending a command.
- Concurrent reconciliation cannot overcommit capacity recorded by Control.
- Executor still rejects unsafe execution when real host use differs from the
  controller's reservation view.
- A node upgrade automatically publishes its configured limits; operators do
  not maintain duplicate capacity values.
- Missing or stale observations stop new placement but do not interrupt
  lifecycle management for assigned workloads.
- Ambiguous effects can temporarily strand capacity until an operator resolves
  the degraded instance. Releasing it automatically would risk duplicate or
  overcommitted workloads.
- Steward owns deterministic filtering, scoring, reservations, migration, and
  conformance tests, but not a general-purpose cluster scheduler.
