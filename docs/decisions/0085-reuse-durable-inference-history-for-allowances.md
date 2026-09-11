# 0085. Reuse durable inference history for allowances

- Status: Accepted for implementation; review and qualification required before deployment
- Date: 2026-09-11
- Rung: native-platform

## Context

Recording potentially paid inference attempts does not stop an agent from making
more calls. A limit must survive concurrent tasks, caller retries and gateway
restart, including attempts whose provider outcome is unknown. Steward already
owns the signed, exclusively locked, fsync-backed network ledger and route policy.

## Decision

Reuse that ledger's verified authorization history for an optional per-tenant,
per-grant inference attempt allowance. Check and increment under its existing
append lock before network transport. Terminal observations never refund an
attempt. Rebuild counts from the original history on open, including attempts
made before the cap was enabled. Bind the cap into route policy and preserve it
during CLI reconfiguration unless an explicit removal is requested. Retained
grants continue to fence policy changes.

**Tradeoff:** A small index adds no database, daemon, dependency, receipt format
or billing ownership. Conservatively consumed attempts can include calls that
never reached the provider; callers must not infer provider charges from counts.

**Rejected:** An in-memory rate limiter forgets allowance after restart. A new
accounting service duplicates the ledger's lock and durable history. Prompt-only
limits and counters after network dispatch cannot prevent oversubscription.

## Consequences

HTTP-boundary and race tests prove refusal before provider I/O, exact concurrent
allowance consumption, no refund after unknown outcomes or restart, failure when
bounded accounting is unavailable, and retained-grant policy fencing. CLI tests
prove omission preserves the cap and rejected options leave configuration intact.
These fixture-provider checks do not qualify a deployed consumer or dollar cap.

The limit is per grant, not per task or invoice. Independent grants have distinct
allowances; consumers must bind grant issuance to their own admission policy.
Keep monetary pricing and customer billing outside Steward. Revisit if multiple
independently budgeted jobs must share one grant, verified provider refunds become
available, or concurrent gateway writers need a shared transactional ledger.
