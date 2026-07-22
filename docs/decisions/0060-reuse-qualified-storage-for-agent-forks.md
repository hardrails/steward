---
title: "ADR 0060: Reuse qualified storage snapshots for agent forks"
description: Why Steward composes its existing storage backend and deployment reconciler instead of adding a snapshot service.
section: Architecture decision
---

# ADR 0060: Reuse qualified storage snapshots for agent forks

- Status: Accepted
- Date: 2026-07-22
- Rung: native-platform

## Context

Steward already has a qualified storage-backend protocol, an OpenZFS worker,
immutable cold snapshots, copy-on-write clones, signed Executor operations, fork
lineage, and restart-safe TTL cleanup. The remaining operator flow required manual
coordination: snapshot metadata did not bind its node, the standard authorization
command could not grant a fork's resume and cleanup lifecycle, and Control did not
bound descendants from one snapshot.

Adding another snapshot service or database would duplicate lineage and ownership
state, enlarge disconnected installation and recovery, and introduce a second
place that could claim a clone exists. It would not strengthen authority or node
isolation.

## Decision

Compose agent forks from Steward's existing storage-backend and deployment
reconciliation contracts. Bind the source node into portable snapshot metadata
and every fork plan. Let the tenant-side CLI derive the exact fresh fork authority
from that plan, while Control retains no private signing key. Enforce a configurable
per-snapshot live-descendant ceiling atomically when desired state is accepted.
Keep the ordinary controller-delegation lifetime at 24 hours, but allow up to 31
days only when the delegation names one node, one instance, resume admission, and
both clone and purge authority. This preserves cleanup authority for a 30-day fork.

**Tradeoff:** the workflow is complete for cold, node-local snapshots and keeps one
lineage authority, but a fork remains pinned to its source node. The descendant
ceiling controls fanout, not retained bytes.

**Rejected:** a new Steward snapshot service or embedded database, because it
duplicates qualified native storage and adds an authority surface without solving
portable state transfer.

## Consequences

Snapshot creation, byte quotas, copy-on-write behavior, and deletion remain owned
by the qualified storage backend. Steward owns signed intent, tenant and node
scope, immutable lineage, descendant admission, cleanup, and evidence.

Revisit this decision when a supported backend can export a verifiable encrypted
archive and restore it on a different node. At that point, add a narrow portable
snapshot catalog and archive interface; do not move admission or signing authority
into the storage provider.
