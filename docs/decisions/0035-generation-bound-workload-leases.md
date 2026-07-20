# Generation-bound workload leases

## Status

Accepted.

## Date

2026-07-20.

## Rung

In-house, built on Steward's existing signed delegation, durable admission fence,
command courier, and fail-closed Executor reconciliation.

## Context

Control currently leaves an instance assigned when its node stops reporting. That
is safe but not recoverable: a stale heartbeat does not prove that the old agent
stopped, so starting the same logical instance elsewhere could create two active
agents. Kubernetes or Nomad could provide a scheduler, but neither can infer or
enforce Steward's tenant-signed authority, Gateway grants, instance generation,
or receipt chain. Requiring either system would also remove Steward's useful
single-host profile.

A Control-only timeout is not a fence. The old node must hold finite authority
that expires locally even when it cannot contact Control. Replacement must also
remain within the tenant-signed generation range and must not imply portable
state that Steward does not yet provide.

## Decision

Decision: use `in-house` for a narrow generation-bound workload lease and use
`built-in` Steward components for its enforcement. Tradeoff: Steward owns lease
renewal, clock-skew bounds, restart behavior, containment evidence, and recovery
state, but gains an enforceable answer to whether an isolated agent may continue
using managed authority. Rejected: treating node heartbeat expiry as proof of
workload termination. Rejected: making Kubernetes or Nomad a mandatory
dependency. Revisit an external scheduler backend after the local backend and
its conformance suite have stable reservation and fencing semantics.

The online controller may issue a signed `renew` operation only when that verb is
present in the tenant-signed delegation. The operation binds one tenant, node,
instance, claim generation, instance generation, command sequence, and bounded
expiry. Executor persists the accepted expiry in the same owner-only admission
fence that already protects generation rollback. A lease cannot be shortened by
a stale command, extended beyond the configured maximum, moved to another
generation, or reconstructed from an unsigned heartbeat.

For lease-managed deployments, `start` requires a current local lease. Executor's
startup reconciliation and periodic reconciliation stop the agent, its trusted
relay, and its Gateway authority when the lease expires. Control renews well
before expiry. If the node becomes unavailable, Control waits until the last
Executor-accepted expiry plus the command clock-skew bound before advancing the
instance generation and selecting another eligible node. The tenant-signed
delegation remains the ceiling: no replacement may exceed its generation range or
node allowlist.

Lease enforcement narrows managed authority; it is not hardware fencing. Host
root, Docker, gVisor, the Executor supervisor, and the machine clock remain in the
trusted computing base. Packages must configure Executor for automatic restart,
and startup reconciliation runs before polling or accepting new mutations.

Only stateless instances are automatically replaceable. Local persistent state
cannot be copied safely to another node, and a stopped old volume is not a
portable snapshot. A stateful deployment records a clear recovery blocker until
a quota-enforced portable storage backend can prove snapshot and attach
semantics.

Existing delegations without `renew` remain readable and retain the prior
non-relocatable behavior. New recoverable deployment applications require
`admit`, `renew`, `start`, `stop`, and `destroy`. This avoids silently changing
the failure semantics of retained deployments during an upgrade.

## Consequences

- A disconnected lease-managed agent loses Steward-mediated external authority
  before another generation may start elsewhere.
- A stale or replayed renewal cannot revive an older generation.
- Control can recover stateless instances without receiving tenant private keys
  or direct Docker access.
- Lease and replacement transitions must be durable, bounded, observable, and
  covered by restart, clock-skew, stale-node, and concurrent-reconcile tests.
- Temporary loss of Control eventually stops lease-managed agents. Operators
  choose the lease duration as an availability-versus-recovery bound; Steward
  ships a conservative default and renews early.
- Stateful automatic replacement, preemption, consensus scheduling, and hardware
  fencing remain out of scope for this decision.
