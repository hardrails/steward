---
title: Build actionable diagnostics and bounded recovery on retained Steward facts
description: Why Steward reuses its existing Control and Executor projections, browser APIs, and CLI contexts instead of adding a repair service, TUI, or streaming protocol.
section: Architecture decision
---

# Build actionable diagnostics and bounded recovery on retained Steward facts

## Decision

Decision: use `in-house` for stable reason guidance and recovery eligibility,
because those decisions interpret Steward's authority, replay, evidence, and
generation fences. Reuse the existing Control attention model, Executor readiness
report, CLI contexts, React application, browser clipboard, and bounded HTTP
polling. Add no Go module, frontend dependency, repair service, or streaming
protocol.

Recovery is preview-first. Automation initially covers only a missing signed
workload that Executor reconciliation has proved safe to retire. Executor rechecks
all preconditions during apply. Other ambiguity remains blocked.

## Context

Operators already had access to the relevant facts, but they had to connect raw
attention reasons, reconciliation failures, API responses, and documentation.
Generic messages such as `reconciliation_required` correctly failed closed but did
not explain which fact caused the block or what action remained safe.

OpenShell demonstrates useful operator patterns through concise status, inspection,
and reason-bearing denial output. Steward can borrow that clarity without adopting
another runtime or weakening its customer-held authority boundary.

## Alternatives

| Option | Benefit | Why it was rejected |
| --- | --- | --- |
| Generic `recover --force` | Short apparent path out of any degraded state | Could erase an uncertain mutation, allow a stale generation, or cause a duplicate external effect. |
| Separate remediation controller | Could run richer automated playbooks | Adds another privileged service, state machine, credential, failure mode, and air-gap artifact for a narrow requirement. |
| New TUI | Rich live terminal interaction | Duplicates the embedded React console and does not improve authority semantics. |
| WebSockets or server-sent events | Faster updates | Current health data is low-volume and one bounded poll already exists; another long-lived protocol adds lifecycle and proxy behavior without changing operator safety. |
| Raw backend errors in the console | More immediate detail | Backend text can be unbounded, unstable, secret-bearing, or attacker-influenced. Stable reason guidance is safer and testable. |

## Consequences

- The CLI can summarize both Control and a local node through one selected context.
- Human output explains cause, impact, and next step; JSON keeps stable codes for
  automation.
- The console remains observation-first and only copies a validated diagnostic
  command. It does not execute recovery.
- Adding a new reason requires bounded guidance and tests.
- Recovery coverage grows only when Executor can define and prove exact monotonic
  preconditions for another state.

Revisit polling only if measured fleet size or latency makes bounded refresh
materially inadequate. Revisit a recovery case only after its external result,
replay safety, retained evidence, and generation transition can be proven without
an operator-specific guess.

