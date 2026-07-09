# Architecture

Steward is an on-node supervisor whose only job is to track the lifecycle of
agent instances and expose that lifecycle over a small HTTP API. This document
records what it deliberately does *not* do, and why the most sensitive future
capability is kept at arm's length.

## Intentionally minimal

This version of Steward is a walking skeleton. It does exactly one thing:

- **Lifecycle tracking.** An in-memory tracker (`internal/runtime`) maps an
  opaque `runtime_ref` to an instance and its status (`PENDING`, `RUNNING`,
  `STOPPED`, `HIBERNATED`, `DESTROYED`, `FAILED`). The six operations —
  provision, start, stop, hibernate, destroy, status — are thin transitions over
  that map, guarded by a single mutex.

It explicitly does **not**:

- execute commands or run workloads,
- sandbox or isolate anything,
- perform computer-use or any other agent capability,
- persist state (a restart forgets every tracked instance),
- authenticate, terminate TLS, or emit metrics/traces.

Those are out of scope on purpose. Steward is meant to be small enough to read in
one sitting and to audit against its published contract
(`openapi/steward.v1.yaml`).

### Provisioning is idempotent by design

`Provision` keys on the caller-supplied `instance_id`. If an instance with that
id is already tracked, the existing `runtime_ref` and status are returned
unchanged rather than creating a second instance. This is the safety net for a
client that retries an ambiguous, timed-out provision call: a double-invoke
cannot create a duplicate. The concurrency test in `internal/runtime` pins this
by racing many goroutines to provision the same id and asserting exactly one
instance is created.

### `spec` is opaque

The `spec` supplied at provision time is treated as an opaque, forwards-compatible
JSON blob. The HTTP layer enforces exactly one thing about it — that it is a JSON
object (a non-object `spec` is rejected with 400, matching the published
contract) — and otherwise stores and echoes its contents verbatim without parsing
them, so the control plane can evolve the spec shape without a Steward release.
An omitted or explicit-null `spec` is accepted and stored as absent.

## Deferred decision: computer-use is a separate worker, never in-process

Steward will eventually need to offer a computer-use capability. The decision for
this repository is that computer-use will be a **separate, optional,
container-based "worker" process** that Steward provisions on demand, and that
registers itself back through the `skills` array of `GET /v1/capabilities`. The
`skills` field ships empty in v1 precisely to reserve that shape.

It will **never** be code loaded into Steward's own process or address space, for
two independent reasons:

1. **Dependency purity.** Steward is deliberately dependency-free Go and cannot —
   and must not — run Python or other agent tooling in-process. Loading such a
   capability inline would violate the zero-private-dependency and
   standard-library-only posture that makes this repository independently
   buildable and auditable.
2. **Isolation.** Computer-use is the highest-risk capability in the system. The
   highest-risk capability deserves a process/container isolation boundary, not
   an in-process one. Keeping it in a separate container means a compromise or
   crash of the worker cannot take the supervisor — or the node — down with it,
   and the blast radius stays inside the sandbox.

Until that worker exists, `GET /v1/capabilities` returns `{"skills": []}` and
Steward does nothing related to skills or computer-use.

## Layout

```
cmd/steward/        HTTP server entrypoint (flags/env, graceful shutdown)
internal/runtime/   In-memory instance tracker and lifecycle operations
internal/server/    HTTP handlers wiring the operations to REST endpoints
openapi/            Hand-written public API contract (the audit surface)
```
