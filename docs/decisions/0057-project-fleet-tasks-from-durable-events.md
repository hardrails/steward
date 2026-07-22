---
title: "ADR 0057: Project fleet tasks from durable events"
description: Why Steward first builds a bounded task read model over its existing outbox instead of adding a broker or retaining prompts in Control.
section: Architecture decision
---

# ADR 0057: Project fleet tasks from durable events

- Status: Superseded in part by ADR 0059
- Date: 2026-07-21
- Rung: in-house

ADR 0059 later added a separate canonical courier for exact tenant-signed task
requests and bounded terminal results. This decision still governs agent-reported
task projections: they remain untrusted read models and never authorize work.

## Context

Gateway already records task authorization, dispatch, and terminal observations in
a signed receipt ledger. Running instances can also send bounded status and finding
events through a durable, backpressured Gateway-to-Executor-to-Control outbox.
Control retains those events but exposes only a raw event list, so operators cannot
see task-correlated progress and findings as one fleet object.

This slice does not require another payload queue. Raw prompts and result bodies
remain in the owner's private run directory or a separately governed artifact
store. Adding NATS, PostgreSQL, or a workflow engine now would introduce another
durable authority, installation dependency, backup target, and disconnected-update
surface without solving Steward's distinctive authorization-to-outcome binding.

## Decision

Build a bounded, read-only task projection inside Control from accepted instance
events. Update it durably in the same WAL transaction that accepts each source
event, but retain it independently from the raw event window. A projection is
scoped by tenant, task ID, instance ID, and generation. It reports agent-authored
progress and findings as untrusted observations, detects conflicting run
identities, and never becomes command or result authority. Pagination and
response-size limits reuse Control's existing HTTP and store boundaries.

**Tradeoff:** This creates useful fleet task visibility without retaining prompts,
result bodies, credentials, or a second event stream. It does not make Control a
task dispatcher, cancellation service, artifact store, or proof that agent-reported
work is correct.

**Rejected:** NATS, PostgreSQL, or a workflow engine, because the distinguishing
requirement is a bounded projection of existing durable metadata, not a new queue
or general workflow runtime. Client-only grouping was also rejected because every
CLI, MCP, console, and API consumer would otherwise reimplement ordering,
conflict, and retention semantics.

## Consequences

Task projections have their own oldest-first retention limits: 1,024 per tenant
and 4,096 across the site. Raw-event eviction therefore cannot erase a terminal
task observation, although an old projection eventually leaves this separate
bounded window. A malicious agent can report false progress or reuse a task ID;
Steward preserves the workload identity and exposes conflicts instead of treating
the report as verified task state.

Revisit the external-service decision when asynchronous fleet submission requires
multi-writer high availability, when task payloads must survive without an owner
client, or when a separately governed artifact service becomes mandatory. At that
point, prefer a standard, operator-selected substrate behind a narrow Steward
contract rather than implementing consensus, object storage, or a general broker.
