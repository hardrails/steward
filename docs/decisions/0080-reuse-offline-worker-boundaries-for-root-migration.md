# 0080. Reuse offline worker boundaries for root migration

- Status: Accepted
- Date: 2026-09-09
- Rung: native-platform

## Context

Retained volumes from the earlier default root permissions cannot pass the
sandbox-group invariant. Repairing arbitrary permissions during normal replay
would conceal changes and expand the serving worker's authority.

## Decision

Use the existing lifetime lock, strict scoped records, bounded Docker client and
descriptor-pinned ZFS root checks for an explicit offline CLI migration. Native
ownership and mode operations affect only one verified root. The former
`root:root 0755`, interrupted chown state, and completed target are recognized;
other modes fail closed. No new service, dependency or metadata format is added.

**Tradeoff:** operators must quiesce Executor, other container creators and host
writers. Docker's reference query includes stopped containers but cannot prevent
another root-equivalent client from starting one afterward. The worker lock
excludes concurrent serving/migration through the same configured worker.

**Rejected:** recursive shell ownership repair lacks retained identity checks and
changes customer files. Startup auto-repair hides tampering. A general migration
daemon or journal adds permanent ownership for an idempotent two-syscall change.

## Consequences

The command preserves records, quota settings, Docker binding and snapshots.
Post-migration inspection must still pass. Real Linux acceptance verifies lock
and container refusal, successful migration/replay, and retained data on a random
fixture removed after the test. Revisit if migrations need data rewrites or
online service continuity; those require a distinct state-transition design.
