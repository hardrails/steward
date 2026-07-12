---
layout: default
title: "Decision 0003: keep degraded containment separate from journal recovery"
nav_order: 3
parent: Decisions
---

# Decision 0003: keep degraded containment separate from journal recovery

Status: accepted

## Context

Executor can restart with a valid operation journal whose latest mutation has no
terminal `committed` or `compensated` record. A lost response may mean the external
change happened even though Executor could not record its outcome. Refusing to run
strands remote cleanup authority. Guessing an outcome can replay an irreversible
operation or widen authority.

## Decision

Decision: use the existing signed `stop` endpoint, Docker lifecycle API, and Gateway
control socket for containment. Executor remains reachable and can narrow authority
without adding a recovery engine or another durable state machine. Automatic journal
recovery was rejected because the retained journal does not contain enough evidence
to infer whether every external step committed. Revisit this decision if the journal
format records a complete, independently verifiable recovery protocol for each
mutation type.

Normal startup accepts a pending journal and reports readiness 503. Admission,
start, destroy, and state purge remain blocked. A signed stop may:

- derive the Gateway grant and relay names from the retained tenant, instance, and
  generation fence;
- deactivate that deterministic grant;
- stop an agent whose managed identity, workload fingerprint, image config, and
  fence all match;
- stop a relay whose deterministic full specification and fingerprint match; and
- re-inspect each affected boundary before returning success.

The containment path does not prepare or settle a journal entry, append a claimed
commit outcome, update a fence, recreate or adopt an object, or remove state. If one
boundary cannot be verified, it returns 503 without undoing confirmed local stops.

Reconciliation uses the same authority-narrowing rule: repairs may stop or
deactivate objects but cannot start or recreate them. It plans the bounded host-wide
scan before applying repairs. If any signed runtime is ambiguous, that pass may
contain exactly identified objects but cannot start a relay, register a grant, or
activate a grant elsewhere on the host.

## Consequences

Operators retain remote containment during a partial failure, including through the
outbound uplink. Readiness clearly distinguishes this state from normal operation.
The unresolved journal entry still requires explicit operator recovery; Steward does
not claim to know an outcome it cannot prove.
