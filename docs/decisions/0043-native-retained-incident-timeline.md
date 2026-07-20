---
title: Derive a retained incident timeline in Steward Control
description: Why Steward joins current incident facts itself without claiming to provide a complete audit log.
---

# 0043. Derive a retained incident timeline in Steward Control

- Status: Accepted
- Date: 2026-07-20
- Rung: in-house

## Context

Containment, evidence divergence, credential revocation, and failed workload
state already exist as bounded Steward Control records. During an incident, an
operator otherwise has to query several inventories and manually order their
timestamps. A generic logging system can store emitted messages, but it cannot
derive Steward's tenant projection, current authority state, or evidence meaning.

Calling the result an audit log would be misleading. Most source records retain
the latest transition rather than every historical transition, and bounded
retention can remove facts.

## Decision

Steward Control derives a deterministic, newest-first incident timeline from its
current durable metadata. The categories are containment, evidence, access, and
workload. Site-wide facts that affect a tenant remain visible in that tenant's
projection. Multi-tenant node facts are projected once per visible tenant.

The HTTP API, CLI, support bundle, and console reuse the existing store, operator
scope, opaque cursor, response-size limit, and React surfaces. Timeline events
cannot contain command envelopes, result bodies, bearer credentials, prompts,
request or response bodies, or logs.

**Tradeoff:** The view is immediately useful and adds no logging infrastructure,
but it cannot reconstruct overwritten transitions or unmanaged activity.

**Rejected:** adopting a logging or SIEM stack as a Steward dependency, because
that adds operational infrastructure and still cannot derive Steward-specific
trust semantics; and creating a new append-only controller ledger in this change,
because its retention, export, signing, and upgrade contract require separate
design and threat analysis.

## Consequences

Documentation and interfaces call this a retained incident timeline, never a
complete audit log. Operators that require historical reconstruction must export
events to their own log or SIEM system and preserve signed Executor and Gateway
evidence outside the affected host.

Revisit an append-only event ledger when a concrete regulatory or forensic
requirement defines the required sources, retention, signing, export, and
cross-host timestamp model.
