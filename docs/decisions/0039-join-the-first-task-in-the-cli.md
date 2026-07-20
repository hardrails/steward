# 0039. Join the first task in the existing CLI

- Status: Accepted
- Date: 2026-07-20
- Rung: in-house

## Context

Steward already has bounded application build, durable deployment, task signing,
Gateway dispatch, terminal observation, and recovery operations. A routine task
still requires operators to construct request JSON, name a runtime-specific
operation, and choose several output paths. That exposes protocol mechanics before
the first useful result and makes the safe recovery path easy to miss.

A generic workflow engine would duplicate Hermes and OpenClaw planning behavior and
add another trusted execution surface. A shell wrapper would be difficult to make
portable, would parse JSON indirectly, and could diverge from the command paths it
orchestrates.

## Decision

Decision: use `in-house` for a thin command join because safe first-task recovery is
part of Steward's core operator contract and the implementation can directly reuse
the existing Go command functions. Rejected: an open-source workflow engine because
the distinguishing requirement is one ordered local operation with existing
idempotency and authority semantics, not general workflow scheduling.

`agent create NAME` calls the canonical application initializer. `agent apply NAME`
calls durable deployment apply; the named-flag-only form retains direct single-node
apply for expert use. `task run NAME "prompt"` waits for authenticated task-ready
state, recognizes only the qualified Hermes or OpenClaw service, writes a bounded
exact request, signs and persists one-use authority, dispatches, observes, and saves
the terminal result.

Automatic artifacts live in a new owner-only directory. The command prints paths,
not prompt or result bytes. The explicit request, operation, key, and output flags
remain available for automation and off-node signing.

## Consequences

- The common first-task surface is three memorable commands after site authority is
  configured.
- Prompt mode cannot select an arbitrary service or operation; unknown adapters use
  the explicit task interface until separately qualified.
- A failed dispatch retains the exact bundle needed for safe recovery.
- Steward gains no workflow engine, dependency, daemon, or new network interface.

Revisit the join when a new qualified adapter needs a request shape that cannot be
represented by one bounded prompt, or when measured onboarding shows that site
authority setup—not task execution—is the remaining dominant failure point.
