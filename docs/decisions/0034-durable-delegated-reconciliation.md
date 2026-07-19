# Durable delegated reconciliation

## Status

Accepted.

## Context

One-shot placement and locally signed `admit` and `start` commands stop when the
operator disconnects. They cannot converge an agent after Control restarts, and
placing a tenant command private key in Control would give a controller compromise
the key's complete authority. Requiring Kubernetes or Nomad would make an ordinary
single Linux server depend on another control plane without solving Steward's
agent-specific authority and evidence problem.

## Decision

Decision: use `in-house` for a narrow, single-writer desired-state reconciler and
`built-in` for Steward's durable store, signed command courier, Executor admission,
anti-replay fences, and terminal reports. Tradeoff: Steward owns the crash states,
generation rules, placement determinism, and migration contract, but does not own
a general scheduler or consensus system. Rejected: `open-source` Kubernetes or
Nomad as a mandatory substrate, and rejected: a tenant private key in Control.
Revisit the storage and leader-election boundary when a supported deployment needs
active control-plane failover.

Control retains bounded desired deployments in durable store format 5. Each
deployment contains a portable bundle digest, a publisher-signed capsule, and a
tenant-signed delegation. It never contains a tenant or controller private key.
The delegation fixes the controller public key, lifecycle verbs, allowed nodes,
exact instance and lineage identities, generation bounds, claim generation,
admission fields, and an expiry no longer than 24 hours.

The packaged controller has a dedicated online Ed25519 signing identity, separate
from TLS and the evidence-witness identity. It computes a deterministic
least-loaded choice among active delegated nodes that advertise
`controller-delegation-v1` and have reported within the operator's node freshness
threshold, then creates only `admit`, `start`, `stop`, or `destroy` commands. The
deployment transition and new command enter one write-ahead-log
mutation, so a crash cannot retain one without the other. Command identifiers and
per-instance sequences are deterministic and monotonic.

Executor remains the enforcement authority. It authenticates its local site
policy, verifies the tenant signature on the delegation, verifies the controller
signature, and checks the exact authorization-context digest and scope before
touching Docker. Control's inspection of a delegation is routing validation, not
trust in the tenant signature.

Known failure is safer than optimistic retry. A terminal failure or
`outcome_unknown` report makes the deployment degraded; the reconciler does not
automatically create another effect. Concurrent reconciliation cannot enqueue two
commands for the same transition, and restart after enqueue does not duplicate it.
Retryable placement and authority problems use a bounded, machine-readable reason
vocabulary. Repeating the same blocker does not append another durable mutation.
New placement resumes after a fresh authenticated node poll. An assigned instance
is not moved merely because its node becomes stale: without fencing, the controller
cannot prove the old effect stopped.

## Consequences

- Operators can apply, inspect, list, and remove durable deployments through the
  public HTTP API and short `stewardctl agent deployment` commands.
- Exact retries are idempotent. Changed desired state uses optimistic revisions
  and monotonically increasing deployment generations.
- A controller compromise can use delegated lifecycle authority until expiry, but
  cannot widen its instances, nodes, generations, resources, capabilities, or
  verbs.
- The store remains bounded, single-writer, air-gap capable, and free of external
  runtime dependencies.
- Resource reservations, fencing leases, safe replacement, progressive rollout,
  autoscaling, snapshots, and high-availability leadership remain separate roadmap
  work.
