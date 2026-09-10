# 0082. Link stop receipts to the original task

- Status: Accepted for implementation; qualification required before release
- Date: 2026-09-10
- Rung: native-platform

## Context

A real signed Hermes run stopped successfully, but Gateway rejected the stop
acknowledgment as `run_id_conflict`. Starting work allocates a run; stopping work
references that run. Treating both as allocation prevents a complete cancellation
lifecycle. Removing uniqueness for ordinary work would let an agent substitute
another task's output.

## Decision

Reuse the native signing, dispatch and receipt ledger. Record a stop's exact target
run and original task digest in version 8 receipts. Require the original admitted
task, matching tenant/runtime/grant/authority, and the canonical signed stop body
before dispatch. The stop references the original run without taking ownership of
it. Ledger restart and offline verification enforce the same relationship.

Only the closed Hermes stop operation selects this behavior. Other operations
retain unique run ownership. A stop acknowledgment does not prove cancellation;
the original run must still be observed to terminal state.

**Tradeoff:** One additive receipt format preserves old evidence and uses the
existing transport without a second cancellation service or signing authority.
**Rejected:** Removing the duplicate-run fence, or scoping it only by operation
name, because either permits unrelated work to claim an existing run.

## Consequences

Older readers reject version 8 rather than misinterpreting it. Historical receipts
are not rewritten. Portable single-task evidence cannot prove the parent link;
stop audit requires the full verified ledger until a bounded linked export exists.
Revisit when another qualified runtime needs a different control operation.
