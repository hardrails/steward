# Design: `POST /v1/instances/batch` (ordered batch lifecycle operations)

Status: **implemented; design provenance.** This document records the shape
chosen, the shapes rejected, and the idempotency analysis for the batch
endpoint. It follows the same style as [ARCHITECTURE.md](../ARCHITECTURE.md)
and [`docs/instance-generation-fencing.md`](instance-generation-fencing.md):
it explains not just *what* but *why*.

## Why this exists

A control plane driving a fleet reconciliation loop routinely needs to issue
several lifecycle operations against one Steward in one pass — for example,
destroying a stale instance and re-provisioning its `instance_id` in the same
reconciliation, or starting a batch of newly-provisioned instances. Before
this change, that meant one HTTP round trip per operation, with no ordering
guarantee a caller could rely on beyond "whatever order I happened to send
the requests in and however the OS/network reordered them." `POST
/v1/instances/batch` gives a caller one round trip and an explicit ordering
contract: operations run in exactly the order listed, so a caller can compose
`destroy` then `provision` (or any other sequence) and rely on the first
operation's effect being visible to the second.

## What stays true (invariants)

- **One tracker, one call path per verb.** The batch handler introduces no
  new tracker logic. Each operation kind calls the exact same
  `internal/runtime.Tracker` method its single-instance HTTP handler already
  calls — `Provision`, `Start`, `Stop`, `Destroy` — so there is exactly one
  place that implements "what does a provision/start/stop/destroy do,"
  regardless of whether it arrived via a single-instance route or a batch
  entry. A batched operation's request/response shape and idempotency
  behavior are therefore identical to its single-op endpoint's, by
  construction, not by parallel re-implementation that could drift.
- **Strict, live-tracker ordering.** Operations are not staged, validated as
  a group, or reordered; the handler iterates `operations` in order and
  calls straight into the tracker for each one before moving to the next.
  This is what makes "destroy `instance_id` X, then re-provision X" work
  inside one batch: by the time the second operation runs, the first has
  already executed and released the `instance_id` (see
  [Provisioning is idempotent by design](../ARCHITECTURE.md#provisioning-is-idempotent-by-design)
  and the `Destroy` doc comment in `internal/runtime/runtime.go`).
- **Not a transaction — stated, not implied.** No operation is ever rolled
  back because a later one failed, and there is no dry-run/validate-first
  pass. A batch is a convenience for sending many operations in one request
  with an ordering guarantee, not an atomic unit of work. This is a real
  design decision a caller needs to know about, so it is stated explicitly
  here, in `ARCHITECTURE.md`, in the README, and in the OpenAPI operation
  description for `batchInstanceOperations` — not left to be discovered by
  surprise.
- **Partial success is always visible, never swallowed.** Every operation's
  outcome — success or failure — is reported in its own `results[i]` entry,
  positionally aligned with `operations[i]`. A failing operation 3 of 5 does
  not prevent 1, 2, 4, and 5 from being attempted and reported. The overall
  HTTP response is `200` as long as the request body itself parsed as a
  valid `{"operations": [...]}` object; per-operation failures live in that
  operation's own `status`/`error` fields, never in the response's HTTP
  status code.

## The shape chosen

### Request: `{"operations": [{"op", "instance_id"?, "runtime_ref"?, "spec"?}, ...]}`

Each operation names its verb (`op`: `"provision"` | `"start"` | `"stop"` |
`"destroy"`) plus the identifier and body fields that verb's single-instance
endpoint already accepts — deliberately not one generic identifier field
shared by every verb:

- **`"provision"`** takes `instance_id` (required) and `spec` (optional),
  the exact shape of `ProvisionRequest`. `runtime_ref` is ignored: a
  provision has no `runtime_ref` yet.
- **`"start"` / `"stop"` / `"destroy"`** take `runtime_ref` (required),
  because that is what their single-instance routes already address an
  instance by (`POST /v1/instances/{id}/start`, etc. — `{id}` is documented
  in `openapi/steward.v1.yaml` as "the opaque `runtime_ref` returned when the
  instance was provisioned"). `instance_id` and `spec` are ignored.

This mirrors, field-for-field, what each single-instance endpoint already
accepts, rather than inventing a new shape or forcing every verb through one
loosely-typed "id" field. A caller who already knows how to call
`POST /v1/instances` and `POST /v1/instances/{id}/start` needs to learn
nothing new about field names to compose them into a batch.

### Response: `{"results": [{"op", "instance_id"?, "runtime_ref"?, "status", "instance"?, "error"?}, ...]}`

`results` is wrapped in a named object under a stable `results` key (never a
bare top-level array), matching the same object-wrapping convention
`instancesResponse` already established for `GET /v1/instances` — leaving
room for an additive sibling field later without a breaking shape change.

Each `results[i]` echoes the identifier the corresponding request operation
carried (`instance_id` for a `provision`, `runtime_ref` for the others) and
reports exactly one of:

- **`instance`** — the same `Instance` body, and the same `status` (`200` or
  `201`), the matching single-instance endpoint would have returned on
  success.
- **`error`** — the same `{"error", "message"}` body, and the same `status`
  (`400`, `404`, `503`, or `500`), the matching single-instance endpoint
  would have returned on that failure.

Echoing the request identifier in every result (not just relying on
positional index alignment) makes a result self-describing — a caller
processing `results` does not have to keep the original `operations` array
alongside it to know which instance a given entry is about.

## Idempotency analysis (the trickiest part)

The single-instance `provision` endpoint is documented as idempotent on
`instance_id`: repeating a `POST /v1/instances` call for an already-tracked
`instance_id` returns the *existing* instance (HTTP `200`) rather than
creating a duplicate (`Tracker.Provision`'s doc comment in
`internal/runtime/runtime.go`; pinned by
`TestProvisionIdempotentOnInstanceID` and the racing-goroutines
`TestConcurrentProvisionCreatesOnlyOne`). This exists specifically so a
client that retries an ambiguous, timed-out call — it does not know whether
the server finished before or after the connection dropped — cannot
double-provision.

A batch endpoint could accidentally lose that property in either of two
ways: by re-implementing provision logic that forgets the idempotency check,
or by wrapping the whole batch in something (a synthetic batch-level dedup
key, a staged-then-committed transaction) that changes *when* or *how many
times* `Tracker.Provision` is actually called on a retry. This implementation
avoids both: `batchProvision` in `internal/server/batch.go` calls
`s.tracker.Provision(op.InstanceID, 0, spec)` — the identical call
`handleProvision` makes — with no batch-specific wrapping in front of it.
Retrying an entire batch therefore has exactly the same idempotency profile
as replaying its operations one at a time:

| Operation | Retry-safe? | Why |
| --- | --- | --- |
| `provision` | **Yes.** | Calls `Tracker.Provision` directly; a repeat for the same `instance_id` returns the existing instance (`200`), not a duplicate (`TestBatchProvisionIsIdempotentAcrossRetriedBatch`). |
| `start` / `stop` | **Yes.** | `Tracker.transition` unconditionally sets the target status; repeating it converges on the same terminal state and the same `200` response either way (`TestBatchStartIsIdempotentAcrossRetriedBatch`). |
| `destroy` | **No — and this is an existing property of `Destroy`, not something batching introduces.** | `Tracker.Destroy` removes the instance and releases its `runtime_ref`/`instance_id` for reuse. Replaying a batch that already destroyed an instance gets `404 unknown_runtime_ref` on that operation the second time — the identical outcome a repeated `DELETE /v1/instances/{id}` gives today (`TestBatchDestroyIsNotIdempotentAcrossRetriedBatch`). |

The caller-facing conclusion, stated in the README, the OpenAPI operation
description, and `ARCHITECTURE.md`: a batch is safe to retry wholesale after
an ambiguous failure *unless* it contains a `destroy` — in which case a
retry either no-ops harmlessly (the destroy already happened; the retry's
destroy result is a `404`, and everything else in the batch is idempotent as
above) or, if the destroy genuinely never happened server-side, succeeds
normally. Either outcome is safe to observe and react to; what is *not* safe
to assume is that a `destroy` result of `404` on a retry means "nothing in
this batch happened" — it may mean exactly the opposite.

## Shapes rejected

1. **A single generic `id` field shared by every verb, mirroring the literal
   illustrative JSON in the original request.** Rejected because it does not
   match what the single-instance endpoints actually accept: `provision`
   addresses by `instance_id`, while `start`/`stop`/`destroy` address by
   `runtime_ref` — two different identifier spaces. Forcing both through one
   field name would either be ambiguous (which space does `id` mean for
   `provision`?) or would require the caller to already know Steward's
   internals to guess correctly. Mirroring each verb's real field names, as
   chosen, needs no new mental model beyond what calling the single-instance
   endpoints already requires.
2. **All-or-nothing transactional semantics (validate every operation
   first, or roll back on first failure).** Rejected: `internal/runtime`'s
   mutations are not designed to be staged or reversed as a group (a
   `Destroy` releases state that cannot be "un-released" without becoming a
   *new*, different `Provision`), and a caller explicitly wants ordering +
   partial-success visibility for a reconciliation loop, not atomicity. Making
   this the default would also silently change every constituent operation's
   own idempotency contract into something new and untested. Partial success,
   clearly reported, is the documented, `docs/`-recorded design decision this
   endpoint makes.
3. **A batch-level idempotency key (deduplicate an entire retried batch by a
   caller-supplied token).** Rejected as unnecessary scope: each constituent
   operation already carries its own idempotency behavior end-to-end (see the
   table above), inherited for free by calling straight into the same tracker
   methods. Adding a second, batch-level dedup mechanism on top would be a new
   piece of state to persist and reason about for a guarantee the constituent
   operations already provide (apart from the one, clearly-documented
   `destroy` exception, which a caller-supplied dedup token could not fix
   anyway — the underlying resource really is gone).

## Buy vs build

No dependency question arises: the handler is `encoding/json` decode +
`for`-loop over existing exported `Tracker` methods, using only the standard
library — the same zero-private-dependency, standard-library-only posture
every other Steward feature holds to.
