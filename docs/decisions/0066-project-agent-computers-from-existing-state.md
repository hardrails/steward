---
title: Project agent computers from existing signed state
description: Why the console presents workspaces as a joined view of deployments and Executor observations instead of introducing a second lifecycle model.
section: Architecture decision
---

# Project agent computers from existing signed state

- Status: Accepted
- Date: 2026-07-25
- Rung: in-house

## Context

Operators think about an agent's computer, not the separate deployment,
instance, command, snapshot, connector, and node records that implement it.
Steward already retains signed desired deployments and bounded Executor
observations. Adding an independently mutable `workspace` resource would make
the control plane reconcile two sources of lifecycle truth and create ambiguous
failure recovery.

The product still needs to distinguish managed agents, replicated fleets,
resumable forks, and temporary workers. It must also show the exact connector
and egress routes observed for each instance without implying that the agent
possesses their credentials.

## Decision

Present **Agent computers** as a deterministic console projection over retained
deployments and exact tenant-and-instance Executor observations:

- a single ordinary deployment is a managed agent computer;
- a multi-instance deployment is a replicated fleet;
- a snapshot-backed deployment without an expiry is a resumable fork; and
- a snapshot-backed deployment with an expiry is a temporary worker.

The projection joins an observation only when both tenant and instance identity
match. It selects the newest observed generation, reports unmatched observations
separately, and never turns observation into authority. Deployment endpoints
remain the only mutable desired-state contract.

Connector and route identifiers are displayed as delegated paths. Secret values
remain at Gateway or the host-local materialization boundary and are never
returned to the console.

**Decision: use in-house: a small deterministic projection over the existing
React console data. Tradeoff: this makes the agent-computer model understandable
without adding a resource, service, dependency, or reconciliation loop.
Rejected: a new workspace API and durable store because it would duplicate the
signed deployment lifecycle before a distinct server-side invariant requires
one. Revisit if pause-to-zero, wake-on-request, or checkpoint retention needs
durable state that cannot be expressed by deployments and signed commands.**

## Consequences

The workspace view can be changed or removed without migrating durable control
state. API clients continue to use deployment, task, event, and operations
projections directly.

The lifecycle labels are descriptions of the retained deployment shape. They do
not weaken admission, extend expiry, grant connector access, or authorize a
restore. In particular, `managed` does not claim that state is persistent: the
current deployment projection does not prove that. A future lifecycle mutation
must continue to enter through a signed deployment generation or exact signed
command.

Directly managed and historical runtimes remain visible in a separate,
collapsed section. This preserves strict-sovereign and migration evidence
without pretending Control owns their desired lifecycle.
