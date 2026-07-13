---
title: Record portable task lifecycle evidence without claiming task correctness
description: Why Steward links exact authorization, dispatch acceptance, and agent-reported terminal state in a task-local signed chain.
section: Architecture decision
---

# Record portable task lifecycle evidence without claiming task correctness

- Status: Accepted
- Date: 2026-07-13
- Rung: in-house

## Context

Steward can require an off-node tenant key to authorize one exact service request,
spend that authorization before the external effect, and record the dispatch
outcome in a signed ledger. The remaining operational gap begins after a service
accepts the request. An operator needs to determine whether the agent service later
reported a terminal state, resume that observation after Gateway restarts, and
carry evidence for one task across an air gap without exporting records about other
tenants.

A service response such as `completed` is untrusted application output. Signing an
observation does not prove that the agent followed its instructions, produced a
correct answer, or changed the intended system. Steward must preserve that
distinction while making the observable lifecycle useful.

The task records share one hash-linked connector ledger. Copying the whole ledger
would expose cross-tenant metadata. Copying only selected records would break the
global hash chain unless the selected records also have a task-local continuity
proof. A copied ledger head is useful context, but it is not an independently
retained trust anchor and cannot prove that a later suffix was not removed.

Recent protocols and research show active work on durable agent tasks, scoped
authorization, and auditable execution. The experimental
[Model Context Protocol task utility](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks)
defines a durable task state machine, and
[Agent2Agent](https://github.com/a2aproject/A2A/blob/173695755607e884aa9acf8ce4feed90e32727a1/docs/specification.md) defines interoperable
remote-agent task exchange. Neither defines Steward's exact tenant-signed request,
spend-before-effect ledger, task-local signed evidence, or disconnected verifier.
[PAuth](https://www.microsoft.com/en-us/research/publication/pauth-precise-task-scoped-authorization-for-agents/)
reinforces the value of precise task-scoped authority. NIST's
[software and AI agent identity concept paper](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd)
highlights authorization, provenance, auditing, and non-repudiation as areas of
interest. This draft paper and the protocols above are design signals, not evidence
that any one mechanism proves agent correctness.

## Decision

Build a narrow, agent-neutral HTTP task lifecycle on top of Steward's existing task
permit, standard-library HTTP client, and signed connector ledger. An accepted task
follows this durable sequence:

1. `authorize`: verify and record the exact tenant-signed request before dispatch;
2. `dispatch`: record a service-accepted run identifier; and
3. `terminal`: record the first valid agent-reported `completed`, `failed`, or
   `cancelled` state, its exact response digest, and its byte length.

A request rejected, expired, or revoked after authorization, or a dispatch whose
outcome becomes ambiguous, instead follows `authorize` → `terminal failure`. It has
no dispatch-acceptance receipt and is never redispatched automatically.

Gateway derives the observation destination from validated operator configuration,
the active grant established by signed admission, the permit-bound operation-policy
digest, and the stored run identifier. The caller cannot choose a URL, path, query,
header, redirect, or response decoder. Observation uses one bounded request, one
strict JSON contract, and a policy-bounded deadline. Nonterminal reports remain
live observations and do not append ledger records. A terminal observation becomes
immutable once its receipt is durable.

Each lifecycle receipt adds a sequence number and hash link within its task. This
task-local chain permits a compact evidence packet containing the task permit and
only that task's signed receipts. Offline verification requires authentic tenant
task-authority and Gateway receipt public keys obtained outside the evidence packet;
keys embedded in a packet are not trust roots. The verifier reports task-chain
verification separately from global-ledger and externally anchored suffix
verification.

Steward does not retain raw prompts, requests, results, workspaces, or credentials
in the lifecycle ledger or evidence packet. A client may explicitly save the one
bounded terminal response to an owner-only file after its digest and length match
the durable receipt. Steward cannot replay those bytes after they disappear from
the agent service.

Lifecycle commands are generic: submit, inspect durable status, make one bounded
observation, wait with a bounded overall deadline and policy-enforced minimum poll
interval, export evidence, and verify evidence. Agent-specific commands, including
Hermes commands, are thin adapters over this contract. Restart recovery reads the
ledger and never redispatches an accepted task.

**Claim boundary:** Steward may say that Gateway authorized an exact request,
recorded dispatch acceptance, and observed an agent-reported terminal state. It
must use terms such as `dispatch_accepted` and `agent_reported_completed`. It must
not call the work verified, successful, correct, or exactly once. An independent
acceptance check must establish the real-world effect when that matters.

**Pareto and adversarial analysis:** task lifecycle evidence offers high functional
and audit value by extending existing bounded, offline-capable mechanisms. Node
retirement offers independent security value and remains a separate priority. Hard
storage quotas offer greater shared-host isolation value, but require a nonportable
storage substrate: Docker's ordinary named-volume interface does not supply a
portable byte-and-inode enforcement boundary, and a userspace counter would be a
false security claim. The main lifecycle risk is converting a false service report
into an overstated signed claim. Fixed destinations, strict response validation,
immutable terminal evidence, task-local correlation, non-borrowing tenant
reservations, and explicit claim limits reduce that risk.

**Buy vs build:** **in-house**: extend the current standard-library implementation
and signed ledger. A workflow engine or database would introduce another durable
state authority and recovery boundary. A general policy engine would not replace
exact permit validation or receipt ordering. Full MCP Tasks or A2A support would
add broad protocol surface without supplying the required evidence semantics. A
result store would expand sensitive-data retention. Revisit these choices if a
stable, independently implementable protocol can preserve the exact request,
tenant, node, policy, replay, receipt, and offline-verification bindings without a
mandatory online service or private dependency.

## Consequences

The connector receipt format and rollback boundary advance when the first lifecycle
record is written. Readers continue to accept older receipt formats, while older
binaries cannot safely reopen a ledger containing the new format. Lifecycle
authorization reserves enough tenant-local evidence capacity for both remaining
records before dispatch; one tenant cannot borrow another tenant's reservation.

Duplicate run identifiers within one service grant are conflicts, not aliases.
Ambiguous durable writes poison the ledger until restart and reconciliation.
Revocation is checked before a terminal observation is attached. State indexes and
locks reconstruct from, and remain bounded by, retained ledger history.

The compact evidence packet proves signature validity, exact permit binding, and
task-local ordering for the records it contains. It does not prove that the source
ledger is complete, that no signed suffix was removed, that the agent's report was
truthful, or that the work was useful. Full-ledger verification plus an externally
retained head remains necessary for global-chain and suffix-retention claims.
Operator public-key distribution, Steward and Gateway process integrity, host root,
and protection of the Gateway receipt private key remain trusted.

Background polling, cancellation, signed progress streams, automatic redispatch,
fleet-wide task state, semantic result verification, transcript retention,
multi-hop delegation, shared-host persistent-storage quotas, dynamic skill
installation, node retirement, and hardware attestation are outside this decision.
They require separate threat models and must not be implied by the lifecycle API.
