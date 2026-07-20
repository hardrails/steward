---
title: Keep the operational command freeze in the narrow controller
description: Why Steward Control owns a durable site and tenant command-delivery fence without treating it as revocation.
section: Decisions
---

# 0039. Keep the operational command freeze in the narrow controller

- Status: Accepted
- Date: 2026-07-20
- Rung: in-house

## Context

An incident responder needs one bounded operation that stops Steward Control from
creating or delivering more lifecycle work. Stopping the controller process also
stops node heartbeats, terminal reports, and evidence intake, removes tenant
scoping, and does not leave a clear durable explanation. A firewall rule or an
external workflow system has the same visibility and consistency gaps and cannot
participate in Control's atomic command and reconciliation transactions.

The operation must not claim to recall a command that Executor already leased or
to revoke authority that a running workload already holds. Those actions cross a
different enforcement boundary.

## Decision

Decision: use `in-house` for a durable, optimistic command-delivery freeze in the
existing single-writer controller. Site administrators can freeze the whole site
or one tenant; tenant operators can freeze only their own tenant. Control checks
the effective freeze in the same transaction that would retain a new command and
at each reconciliation command boundary. Node polling skips frozen tenant work
but continues to accept heartbeats, reports, and signed evidence.

**Tradeoff:** the controller can provide a race-safe, tenant-aware delivery fence
without a new service, but the fence cannot retroactively cancel a leased command
or remove authority already accepted by a node.

**Rejected:** stopping Control, adding a general incident workflow engine, or
depending on a network firewall because none can atomically fence the controller's
durable command queue while preserving its observation channels.

## Consequences

- Freeze changes survive restart and use revisions so stale responders cannot
  restore old state.
- An exact retry of an already retained command remains idempotent during a freeze;
  different or new work fails closed.
- Existing delivery leases and running workloads remain bounded by their original
  signed authority and lease. Operators use quarantine and revocation separately.
- The console displays the effective freeze but does not mutate it, keeping the
  browser outside incident authority.

Revisit this decision if Steward supports a transactional external controller that
can preserve the same tenant projection, command-boundary atomicity, offline
operation, and continued evidence intake.
