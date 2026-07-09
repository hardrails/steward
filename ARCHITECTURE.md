# Architecture

Steward is an on-node supervisor whose only job is to track the lifecycle of
agent instances and expose that lifecycle over a small HTTP API. This document
records what it deliberately does *not* do, and why the most sensitive future
capability is kept at arm's length.

## Intentionally minimal

This version of Steward is a walking skeleton. It does exactly one thing:

- **Lifecycle tracking.** A tracker (`internal/runtime`) maps an opaque
  `runtime_ref` to an instance and its status (`PENDING`, `RUNNING`, `STOPPED`,
  `HIBERNATED`, `DESTROYED`, `FAILED`). The six operations — provision, start,
  stop, hibernate, destroy, status — are thin transitions over that map, guarded
  by a single mutex. State is held in memory by default; durable state across a
  restart is opt-in (see below).

It explicitly does **not**:

- execute commands or run workloads,
- sandbox or isolate anything,
- perform computer-use or any other agent capability,
- authenticate, terminate TLS, or emit metrics/traces.

By default it also does not persist state — a restart forgets every tracked
instance — unless durable state is explicitly enabled.

### Durable state is opt-in

Persistence is off unless the operator sets `-state-file` (or
`STEWARD_STATE_FILE`). When unset, behavior is exactly as above: in-memory only,
a restart forgets everything.

When a state file is configured:

- **Load on startup.** If the file exists, the tracker repopulates both its
  `byRef` and `byID` indexes from it before the HTTP server accepts a single
  request. A missing file is a first run: the tracker starts empty and the file
  is created on the first mutation. A present-but-corrupt file (unreadable,
  invalid JSON, wrong format version, or structurally inconsistent — e.g. a
  duplicate `runtime_ref`) is a **fail-closed startup error** that names the path
  and the fix, never a silent empty start.
- **Persist on every mutation.** Provision, start, stop, hibernate, and destroy
  each write the full snapshot before returning success. The write happens inside
  the tracker's existing mutex, so a mutation and its durable record are atomic
  with respect to every other operation — the file can never lag behind or race
  ahead of memory. If the write fails, the in-memory mutation is rolled back and
  the operation returns an error, so memory never claims a durability the file
  does not have.
- **Crash-safe writes.** Each snapshot is written to a temp file in the same
  directory, fsynced, then atomically renamed over the real path. A process that
  dies mid-write leaves either the intact previous file or an orphan temp file,
  never a half-written file readable as current state.
- **Format.** The file is a small versioned JSON document
  (`{"version":1,"instances":[…]}`) written with only `encoding/json` and `os` —
  no embedded database, no third-party serialization. A compact `spec` is
  round-tripped byte-for-byte; only insignificant JSON whitespace in a `spec` is
  normalized.

Persistence is transparent to the HTTP contract: it adds no endpoint, field, or
status code, and the request/response shapes in `openapi/steward.v1.yaml` are
unchanged.

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
internal/runtime/   Instance tracker and lifecycle operations (in-memory, with
                    opt-in durable state via a JSON state file)
internal/server/    HTTP handlers wiring the operations to REST endpoints
openapi/            Hand-written public API contract (the audit surface)
```
