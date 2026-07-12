---
title: Ordered batch lifecycle operations
description: Ordering, partial-success, bounds, and retry behavior for POST /v1/instances/batch.
section: Design record
---

# Ordered batch lifecycle operations

Status: **implemented.** `POST /v1/instances/batch` sends several lifecycle
operations in one request while preserving their listed order.

## Why this exists

A reconciler often needs several operations on one node. Sending each as a separate
request adds round trips and gives the requests no shared ordering boundary. A batch
can, for example, destroy an old instance and provision a replacement with the same
`instance_id`, knowing that the destroy completes before the provision begins.

A batch is **not a transaction**. Steward does not stage the operations, validate
them as a group, stop at the first error, or roll back earlier work. Every operation
is attempted against the live tracker in request order. A later operation sees the
effects of every earlier operation, including failures that made no change. The
batch does not hold one lock for its full duration, so a concurrent request can run
between two entries.

## Request contract

The body is one JSON object containing a non-null `operations` array:

```json
{
  "operations": [
    {"op": "destroy", "runtime_ref": "rt_old"},
    {"op": "provision", "instance_id": "agent-1", "spec": {"model": "local"}}
  ]
}
```

The body is limited to 1 MiB and the array to 256 operations. An empty array is
valid. A missing or null array, more than 256 entries, malformed JSON, or a second
JSON value after the object returns a top-level `400 invalid_request`. A body over
1 MiB returns `413 request_too_large`. No operation runs after a top-level request
error. Normal server middleware can also reject a call before batch execution with
the JSON `405`, `429`, or `500` responses documented in
`openapi/steward.v1.yaml`.

Four operation kinds are supported:

| `op` | Required field | Optional field | Ignored fields |
| --- | --- | --- | --- |
| `provision` | `instance_id` | `spec` | `runtime_ref` |
| `start` | `runtime_ref` | none | `instance_id`, `spec` |
| `stop` | `runtime_ref` | none | `instance_id`, `spec` |
| `destroy` | `runtime_ref` | none | `instance_id`, `spec` |

These are the same identifier spaces used by the single-instance endpoints.
Provisioning starts from a caller-chosen `instance_id`; lifecycle transitions use
the opaque `runtime_ref` returned by Steward. A generic `id` field would blur those
two meanings and is deliberately not accepted.

Each operation calls the same `Tracker.Provision`, `Start`, `Stop`, or `Destroy`
method as its single-instance endpoint. Batch dispatch does not implement a second
lifecycle state machine.

## Response contract

After middleware and top-level validation, a batch returns HTTP `200` after
attempting every operation, even when some operations fail:

```json
{
  "results": [
    {
      "op": "destroy",
      "runtime_ref": "rt_old",
      "status": 200,
      "instance": {"instance_id": "agent-1", "runtime_ref": "rt_old", "status": "DESTROYED", "created_at": "2026-01-01T00:00:00Z"}
    },
    {
      "op": "provision",
      "instance_id": "agent-1",
      "status": 201,
      "instance": {"instance_id": "agent-1", "runtime_ref": "rt_new", "status": "PENDING", "created_at": "2026-01-01T00:01:00Z"}
    }
  ]
}
```

`results[i]` corresponds to `operations[i]`. Each entry contains `op`, its
applicable request identifier for a recognized operation, and the status the
matching single operation would return. It then contains exactly one of:

- `instance`, with the normal `Instance` response on success; or
- `error`, with the normal `{"error": "...", "message": "..."}` shape on
  failure.

Per-operation statuses include `200` and `201` for success, `400` for invalid input
or process intent, `404` for an unknown `runtime_ref`, `409` for a rejected state
transition, `503` for instance capacity, and `500` for an unexpected failure. An
unknown `op` receives its own `400 invalid_request` result and does not block its
siblings.

The named `results` wrapper leaves room for a future additive field. A bare
top-level array would make that extension breaking.

## Ordering and partial success

The handler loops over `operations` once and executes each entry before moving to
the next. It does not reorder provisions, even when doing so might make another
operation succeed. This rule makes replacement deterministic:

```
destroy(old runtime_ref) -> releases instance_id
provision(same instance_id) -> creates a new instance with a new runtime_ref
```

If operation 3 of 5 fails, operations 4 and 5 still run. The caller must inspect
every result; top-level `200` means the batch was processed, not that every operation
succeeded.

## Retry and idempotency

Batching preserves each tracker method's retry behavior:

| Operation | Result of repeating a successful operation |
| --- | --- |
| `provision` | Returns the existing instance with per-operation status `200`; it does not create a duplicate. |
| `start` | Without a competing transition, converges on `RUNNING` and returns `200`. |
| `stop` | Without a competing transition, converges on `STOPPED` and returns `200`. |
| `destroy` | Returns `404 unknown_runtime_ref` because the first call removed and released the reference. |

There is no batch-level idempotency key. Retrying an ambiguous batch cannot
double-provision. Without a competing concurrent transition, repeated successful
start or stop operations remain safe in effect; always treat the returned instance
as authoritative. A batch containing `destroy` is not response-idempotent: a retry can return
`404` where the first request returned `200`. That `404` can mean the earlier
destroy succeeded; it does not prove that the first batch did nothing.

Later operations still run on the retry. For a common `destroy` then `provision`
replacement, the repeated destroy returns `404` and the repeated provision returns
the already-created replacement with `200`.

## Alternatives rejected

- **One generic identifier field:** `instance_id` and `runtime_ref` have different
  meanings and lifetimes. Keeping both names matches the existing endpoints.
- **All-or-nothing execution:** `Destroy` releases identity and cannot be rolled back
  into the same instance. Transactional staging would create a new lifecycle model
  rather than compose the existing one.
- **Stop on first failure:** reconciliation needs complete, positional results and
  often benefits from later independent operations continuing.
- **A batch-level deduplication key:** it would add durable state while leaving
  `destroy`'s underlying reference release unchanged.

The implementation is a bounded JSON decode and a loop over existing tracker
methods. It uses only the standard library.

## Implementation evidence

The contract is covered by:

- `TestBatchAllSucceed`
- `TestBatchPartialFailureReportsEachResultIndependently`
- `TestBatchOrderingDestroyThenReprovision`
- `TestBatchEmptyOperationsList`
- `TestBatchRejectsTooManyOperations`
- `TestBatchProvisionMirrorsSingleEndpointProcessErrors`
- `TestBatchProvisionIsIdempotentAcrossRetriedBatch`
- `TestBatchDestroyIsNotIdempotentAcrossRetriedBatch`
- `TestBatchOversizedBodyReturns413`
- `TestBatchInvalidStateTransitionReturns409PerOperation`

`openapi/steward.v1.yaml` defines the same request, response, bounds, and
per-operation semantics under `batchInstanceOperations`.
