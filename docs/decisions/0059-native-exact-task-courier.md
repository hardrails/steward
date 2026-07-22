---
title: "ADR 0059: Build a native exact-task courier over existing control links"
description: Why Steward durably transports exact tenant-signed tasks and bounded results through Control and Executor instead of embedding a broker or workflow engine.
section: Architecture decision
---

# ADR 0059: Build a native exact-task courier over existing control links

- Status: Accepted
- Date: 2026-07-21
- Rung: in-house for authority and state transitions; external for future bulk artifacts and multi-writer storage

## Context

Steward already has the components needed to authorize and execute one exact task:
a tenant-signed permit, Gateway signature and binding verification, one-use replay
evidence, and a lifecycle result digest. It also has a hash-chained Control store
and an authenticated outbound Executor uplink. What was missing was a practical
remote workflow: the owner had to reach each node-local Gateway, stay connected,
and manually retain every artifact.

A general broker or workflow engine would improve transport scale, but it would
not define Steward's critical semantics: which exact signed bytes may be delivered
to which admitted generation, how redelivery avoids a duplicate external effect,
and when cancellation or outcome must be reported as uncertain. Embedding NATS,
PostgreSQL, or a workflow SDK would also add dependencies, backup authorities, and
air-gap update work before Steward needs multi-writer throughput.

## Decision

Build a bounded exact-task courier in Steward's existing standard-library Control
store and Executor uplink. Control durably retains an exact request and permit,
leases them only to the assigned authenticated node, and fences every report by a
monotonic delivery generation. Executor submits and observes only through the
host-local Gateway. Gateway remains the sole permit authenticator and one-use
dispatch fence.

Retain public lifecycle metadata separately from private payloads. List and get
responses expose identities, state, digests, byte counts, and uncertainty. An
explicit operator-scoped result endpoint returns the bounded terminal observation
reported by the authenticated node only when it is at most 512 KiB. Control checks
its canonical encoding, digest, and byte count but does not independently verify
signed Gateway evidence for it. Requests, permits, and results remain
in the owner-only Control store and are excluded from ordinary inventory, metrics,
logs, and support bundles.

**Tradeoff:** the first implementation provides crash-safe remote work without a
new service, but it inherits Control's single-writer scale and stores sensitive
task content. Task permits remain short-lived, bounded to 15 minutes. Individual
results are limited to 512 KiB; courier material and results each have independent
16 MiB per-tenant and 64 MiB site-wide ceilings. Large results require a future
artifact backend. A compromised node can forge lifecycle or result reports for
its workloads. Control compromise can disclose or withhold retained content and
replay exact permits until expiry, but cannot mint new tenant authority or alter a
signed request successfully.

**Rejected:** a task table that stores metadata only, because remote work is not
useful if the owner cannot retrieve the result. A model-facing general workflow
engine was rejected because it would combine planning, authority, and dispatch.
An embedded broker or database was rejected at this scale because it creates more
operational authority without strengthening signature or replay enforcement.

## Consequences

Delivery is at-least-once, while external dispatch is exact-per-permit because
Gateway replays a recorded identity for the same spent permit. Cancellation is
definitive only before dispatch; later cancellation records intent and preserves
`outcome_may_continue`. The store evicts only terminal tasks when its per-tenant
or site cap is reached.

This decision extends ADR 0057. Agent-reported task projections remain bounded,
untrusted read models. Submitted task requests are a separate canonical courier
state and never accept an agent event as authority.

Revisit an external service when Steward needs multi-writer Control, result
payloads beyond the bounded local contract, or sustained task volume that exceeds
the published store limits. Prefer an operator-selected standard broker, database,
and S3-compatible artifact store behind narrow interfaces. Do not move signature
verification, admission-generation binding, replay decisions, or uncertainty
semantics out of Steward.
