# Authority-preserving in-place rollouts

## Status

Accepted.

## Context

A durable deployment could converge its first generation, but a live generation
change had only two unsafe or incomplete outcomes: overwrite the signed authority
that still owned a runtime, or refuse the update until an operator removed every
instance. A general deployment system can sequence container replacement, but it
does not know which tenant-signed delegation must authorize each lifecycle command.
Making Kubernetes, Nomad, or a rollout controller mandatory would also weaken the
single-host and disconnected installation path.

## Decision

Build a narrow rollout cursor inside the existing single-writer reconciler. The
deployment's top-level fields become the signed target. A bounded rollout record
retains the exact source capsule and delegation until every target instance is
running. Each instance remains under source authority while running, stopping,
destroying, and awaiting a proven destroy result. Only then does Control advance
the signed instance generation and select target authority for admission and
start.

Use the existing disruption budget for node drains and rollouts. Spending a slot,
checking deployment revision, and writing the per-instance cursor happen under the
store mutex in one durable mutation. Node drain and rollout markers are mutually
exclusive. Controller restart resumes from the durable cursor; it does not infer
progress from elapsed time.

The first implementation is replacement-only. It retains the assigned node,
requires the target delegation to allow that node, and creates no surge replica.
It accepts only a ready deployment with the same ordered instance and lineage set
and strictly higher delegated generations. A failed or outcome-unknown lifecycle
command degrades the deployment and is not retried automatically. Rollback is a
new forward generation with fresh signed authority, never a reduction of a
generation fence.

## Consequences

- Control never discards the authority needed to stop or destroy a possible source
  runtime.
- Executor still verifies every source and target command independently; Control
  gains no tenant private key and cannot widen either delegation.
- `max_unavailable: 1` replaces one replica at a time and remains safe across
  controller restart and concurrent reconciliation.
- A one-replica deployment has rollout downtime. Target placement or capacity can
  block admission after source destroy, so operators must preflight material
  resource and constraint changes.
- Automatic rollback, surge capacity, health-based promotion, scaling, and
  state migration remain outside this state machine until their authority and
  failure semantics are explicit.

This decision narrows and supersedes the statements in ADR 0030 and ADR 0034 that
all deployment rollout must remain external. ADR 0017's separate operator-driven,
proof-carrying qualification rollout remains appropriate for release promotion;
this controller state machine handles routine convergence of already signed
deployment generations.
