# 0016. Derive fleet attention from retained control state

- Status: Accepted
- Date: 2026-07-16
- Rung: in-house

## Context

Steward Control retains node observations, evidence checkpoints and sticky
findings, command delivery state, terminal ambiguity, credentials, and bounded
capacity. Operators currently have to query separate exact resources and infer
which conditions need intervention. That is slow during an incident and makes
capacity failures visible only after a request is rejected.

A generic observability stack can store and visualize events, but it cannot
define Steward's tenant projection, replay semantics, or the difference between
a retryable delay and a sticky ambiguous effect.

## Decision

Derive a bounded action-required view, command inventory, credential inventory,
and capacity summary directly from the controller's already retained state.
Expose the same deterministic facts through authenticated HTTP, CLI, MCP, and
opt-in operational metrics. Stable reason codes identify stale or never-seen
nodes, stale or unwitnessed evidence, rollback or equivocation, overdue
deliveries, failed or ambiguous commands, and approaching capacity limits.

The view never dismisses a sticky finding, changes command state, retries an
effect, or turns an observation into authority.

**Tradeoff:** Steward owns the small projection and threshold contract, while
external dashboards remain optional consumers rather than the source of truth.

**Rejected:** model-generated incident classification, automatic ambiguity
clearing, and a webhook-first design because they can invent state, duplicate an
external effect, or make Internet delivery part of sovereign operation.

## Consequences

Tenant operators see only their tenant's projected records. Site administrators
can inspect site-wide capacity without receiving command bytes or credential
secrets. Notification delivery remains a separate concern; a future durable
outbox can consume these stable reason codes without changing enforcement.

Revisit if operators need acknowledged notification delivery with retention and
backpressure guarantees rather than polling or exporting the derived view.
