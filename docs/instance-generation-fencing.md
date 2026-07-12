---
title: Instance-generation fencing
description: How Steward prevents a delayed command for a destroyed instance from changing its replacement.
section: Design record
---

# Instance-generation fencing

Status: **implemented on the node.** A compatible control plane must mint and carry
the generation values described here. Steward cannot provide full fencing when the
control plane omits them.

## The race this closes

`Destroy` releases an `instance_id` for reuse. Consider this sequence:

1. `agent-1` exists at generation 1.
2. The control plane sends `stop(agent-1)`, but delivery is delayed.
3. `agent-1` is destroyed and provisioned again at generation 2.
4. The old `stop` arrives.

Without a lineage identifier, `RefForInstance("agent-1")` resolves the delayed
command to the new instance. The old command can then stop or destroy the wrong
workload. Neither the control-plane reference
`uplink:<len>:<node_id>:<instance_id>` nor Steward's `rt_<hex>` reference identifies
the instance's lineage across reuse.

An **instance generation** is a monotonically increasing fencing token for one
`(tenant_id, node_id, instance_id)` lineage. Steward records the current generation
and drops a command whose generation is older. In the example, generation 1 is
strictly older than the tracked generation 2, so the delayed `stop` cannot reach a
tracker mutator.

This token has a different purpose from `claim_generation`:

- `claim_generation` prevents a stale execution from reporting after its command
  claim has been superseded. The node echoes it in the report.
- `instance_generation` prevents a command for an old instance lineage from acting
  on a replacement. The node consumes it but does not echo it.

## Persisted state

The generation is stored on the tracked `runtime.Instance`:

```go
Generation int64 `json:"generation,omitempty"`
```

This keeps the runtime reference, lifecycle state, and generation in one source of
truth. It also uses the existing `-state-file` snapshot and atomic persistence path;
there is no second map or state file to keep synchronized.

The state-file format remains `version: 1`. A missing `generation` field decodes to
zero, which means “no fencing baseline.” A snapshot written without the field
therefore remains readable. The loader rejects a negative persisted generation as
corrupt.

There is one rollback caveat. A generation-unaware Steward binary can read an
additive field, but when it later rewrites an instance it omits that field. The
instance then returns to generation zero and loses its local fence until a later
generation-aware provision restores it. This is a loss of protection, not silent
state-file corruption. Avoid running an older writer against state that depends on
generation fencing.

## Wire contract

Each command in `POST /uplink/poll` can carry `instance_generation` alongside
`claim_generation`:

```json
{
  "commands": [
    {
      "command_id": "…",
      "node_id": "node-7",
      "runtime_ref": "uplink:6:node-7:agent-1",
      "kind": "provision",
      "payload": { },
      "claim_generation": 3,
      "instance_generation": 2
    }
  ]
}
```

An absent field decodes to zero. A negative wire value is invalid, but Steward
normalizes it to zero before checking or storing it. Absent, zero, and negative
values therefore preserve the unfenced compatibility behavior.

`POST /uplink/report` is unchanged:

```json
{
  "command_id": "…",
  "status": "done",
  "reported_status": "running",
  "claim_generation": 3,
  "result": { }
}
```

The optional `generation` value is also visible on an `Instance` returned by the
inbound API when it is nonzero. It is the node's current lineage baseline, not a
command sequence number.

## Fence rule

The dispatcher checks one rule before its command-kind switch:

```
generation := cmd.InstanceGeneration
if generation < 0 {
    generation = 0
}
trackedGen, known := GenerationForInstance(instanceID)
if known && generation != 0 && generation < trackedGen {
    // A newer lineage has superseded this command.
    // Execute nothing and send no report.
}
```

The cases are intentional:

- **Unknown instance:** there is no local baseline, so the command is not fenced.
- **Generation zero:** the sender did not provide a usable token, so the command is
  not fenced.
- **Command generation below the baseline:** the command is stale and is dropped.
- **Command generation equal to or above the baseline:** the command proceeds.
  Only `provision` can adopt a higher generation; a newer lifecycle command does not
  change the baseline.

The check is in `dispatcher.execute`, before every command-specific path. This makes
it a single enforcement point for `provision`, `start`, `stop`, `hibernate`, and
`destroy`. `GenerationForInstance` is a locked read of the tracker's existing
indexes. A later lookup of `runtime_ref` uses a second locked read, but the gap is
safe: tracked generations only increase, so a stale command cannot become current
during the gap.

## What happens to a fenced command

A fenced command:

- calls no tracker method;
- is logged at `INFO`;
- is not included in the one-pass `start` retry; and
- produces no report.

Reporting `failed` would turn normal at-least-once delivery into an operator-visible
failure and could trigger incorrect reconciliation. Reporting `done` is more
dangerous: the control plane could apply a `stopped` result from generation 1 to the
generation-2 instance. Sending no report avoids both forms of state corruption.

No report means the control plane may reclaim and redeliver the command after its
claim lease expires. Steward will fence it again, so safety does not depend on timely
cleanup. Efficiency does: a compatible control plane must retire commands whose
`instance_generation` is older than the current lineage. Until it does, the command
causes bounded poll and log churn.

## Generation adoption is atomic

`Tracker.Provision` accepts the generation:

```go
func (t *Tracker) Provision(instanceID string, generation int64, spec json.RawMessage) (inst *Instance, created bool, err error)
```

Under the tracker's existing mutex:

- a new instance stores `generation`; and
- an existing instance stores `max(existing, generation)`.

Provisioning never lowers the baseline. Adoption happens inside the same locked
operation that creates or returns the instance. A separate `SetGeneration` call
would leave a window in which a stale lifecycle command could observe a newly
provisioned instance before its generation was recorded.

The inbound REST handler passes `0`. That preserves direct-REST behavior and cannot
lower a nonzero baseline. Keeping one `Provision` method, instead of adding a
parallel generation-aware method, also keeps every caller on the same idempotency and
persistence path.

## First-seen behavior

A node cannot identify a stale command before it has a local baseline. For an
`instance_id` that `GenerationForInstance` does not know:

- `provision` creates the instance and adopts the carried generation;
- `start` gets its existing one-pass retry, then reports `failed` if no provision
  made the instance known;
- `stop` and `hibernate` report `failed` immediately; and
- `destroy` reports `done` because the instance is already absent.

This is the unfenced compatibility baseline. Refusing every first command until a
separate baseline arrived would make recovery impossible for a fresh node. Once a
provision establishes a generation, older commands are fenced.

## Compatibility

| Steward | Control plane | Result |
| --- | --- | --- |
| Generation-unaware | Omits the field | Unfenced behavior. |
| Generation-unaware | Sends the field | Unfenced behavior; the unknown JSON field is ignored. |
| Generation-aware | Omits the field or sends `0` | Fence remains dormant. |
| Generation-aware | Sends generations `>= 1` | Full node-side lineage fencing. |

The following control-plane requirements are outside this repository and must be
verified for each integration:

- Mint generations at `1` or higher and increase them on every fresh provision.
- Key the generation by `(tenant_id, node_id, instance_id)`.
- Retire commands older than the current generation to prevent repeated redelivery.
- Continue to fence reports with `claim_generation`; do not require the node to echo
  `instance_generation`.

If a control plane can mint a live generation of zero, that command is deliberately
treated as unfenced. Safety then degrades to compatibility behavior for that command;
Steward does not invent a generation on the control plane's behalf.

## Alternatives rejected

- **A separate generation map or file:** it could drift from the instance and would
  require another persistence lifecycle.
- **Adoption after `Provision`:** a second call creates the stale-command race the
  fence is meant to close.
- **Lowering the tracked generation on idempotent provision:** an old provision could
  reopen a superseded lineage.
- **Reporting fenced commands as `failed` or `done`:** either creates false failures
  or can write stale status onto the replacement instance.
- **Requiring a baseline before any command:** it would strand a new or recovered
  node that missed the original provision.
- **Treating generation as batch order:** a lineage token says which instance a
  command belongs to, not the causal order of commands in one poll.

The implementation uses `int64`, comparisons, the existing tracker mutex, and
`encoding/json`. It adds no dependency.

## Implementation evidence

The persistence and monotonicity rules are covered by:

- `TestGenerationRoundTripsThroughPersistence`
- `TestOldFormatFileWithNoGenerationKeyLoadsAsZero`
- `TestProvisionGenerationSetForNewInstance`
- `TestProvisionGenerationNeverLowered`
- `TestProvisionGenerationZeroLeavesExistingUntouched`
- `TestGenerationForInstanceResolvesTrackedInstance`

The dispatcher and batch behavior are covered by:

- `TestDispatchFenceDropsStaleCommandForEveryKind`
- `TestDispatchFenceAllowsCommandAtOrAboveTrackedGeneration`
- `TestDispatchFenceIgnoresZeroInstanceGeneration`
- `TestDispatchFenceNeverSeenInstanceNotFenced`
- `TestDispatchProvisionAdoptsGeneration`
- `TestDispatchProvisionClampsNegativeGenerationToZero`
- `TestDispatchNegativeGenerationDoesNotFenceAlreadyTrackedInstance`
- `TestExecuteBatchFencedCommandProducesNoReport`
- `TestExecuteBatchDeferredStartFencedAfterSiblingProvisionBumpsGeneration`

Run the tracker and uplink suites with the race detector after changing this path:

```console
go test -race ./internal/runtime ./internal/uplink
```

## Scope limits

Generation fencing does not provide causal ordering within one poll, mint or retire
generations for a control plane, rotate credentials, or provide control-plane
failover. The uplink's no-reorder and one-pass `start` retry rules handle its current
batch behavior separately. See [Outbound uplink client]({{ '/uplink-client/' | relative_url }}).
