---
title: Instance-generation fencing
description: Design record for closing delayed-command destroy and reprovision races with durable instance-generation and command-sequence fences.
section: Design record
---

# Design: instance-generation fencing (closing the destroy/re-provision race)

Status: **implemented node-side; design provenance.** This document records the
shape chosen, the shapes rejected, the invariants the design must hold, and the
exact task list that was implemented. It follows the same style as
[ARCHITECTURE.md](https://github.com/hardrails/steward/blob/main/ARCHITECTURE.md) and [`docs/uplink-client.md`]({{ '/uplink-client/' | relative_url }}):
it explains not just *what* but *why*, and it names the failure mode each decision
closes.

This is the **node-side (load-bearing) half** of a two-repo change. The framework
side adds a wire-carried
`instance_generation: int` field to `NodeCommand`, minted per
`(tenant_id, node_id, instance_id)` lineage and bumped on every fresh `provision`,
mirroring the existing `claim_generation` fencing token exactly. That field is
purely additive on the poll response — an old Steward that ignores it behaves
exactly as today. **A wire field the node ignores closes nothing; this design is
the half that makes the node actually enforce it.**

## Why this exists

[`docs/uplink-client.md`]({{ '/uplink-client/' | relative_url }}#deliberately-deferred) names a
deliberately-deferred race precisely: if the **same** `instance_id` on the **same**
node is destroyed and then re-provisioned *before* a **stale, already-in-flight**
lifecycle command from the OLD instance's lineage is finally delivered (a long
partition, a redelivery after the claim lease expires), the client's
`RefForInstance(instanceID)` resolves to the **new** instance — so a stale `stop` /
`hibernate` / `destroy` can mutate or remove the wrong (newly-provisioned)
instance. The accepted v1 mitigation was procedural: "never reuse a destroyed
`instance_id`."

The root cause is that `runtime_ref` (both the control plane's
`uplink:<len>:<node_id>:<instance_id>` and Steward's own `rt_<hex>`) carries **no
generation component**, and `Destroy` deliberately releases the `instance_id` for
reuse (see the `Destroy` doc comment in `internal/runtime/runtime.go`). Two
different instances that share an `instance_id` across a destroy boundary are
therefore indistinguishable by ref alone.

A fencing token fixes exactly this: tag every command and every locally-tracked
instance with the **generation** of the lineage it belongs to, and refuse to act
on a command whose generation is older than the one the node currently tracks for
that `instance_id`. A stale gen-1 `stop` redelivered after the node has adopted
gen-2 is then dropped, instead of stopping the gen-2 instance. This is the same
shape as the `claim_generation` fencing the report path already relies on — a
monotonic token that lets a receiver discard a superseded message — applied one
level up, to the **instance lineage** instead of the **command claim**.

## What stays true (invariants)

- **Additive and dormant until the server sends it.** The feature is off in every
  deployment where the control plane does not send a non-zero `instance_generation`.
  A command with an absent or zero generation is never fenced, so a new Steward
  against an old control plane behaves *exactly* as today — the current accepted
  risk, never worse. This mirrors how the uplink itself, and `-state-file` before
  it, added capability without changing any existing behavior.
- **One source of truth for the generation.** The per-`instance_id` generation
  lives **inside the tracker's `Instance`**, riding the existing `-state-file`
  persistence, not in a second file or a client-side map. The client already refused
  to keep its own `instance_id → rt_<hex>` map (it reconstructs nothing on restart —
  see uplink-client.md); the generation follows the same rule. There is no second
  place a generation can drift from.
- **The fence is one chokepoint the lazy caller cannot skip.** Every lifecycle
  command flows through `dispatcher.execute`; the fence check lives there, before the
  per-kind dispatch, so no command kind can reach a tracker mutator around it. And the
  tracker's `Provision` refuses to *lower* a generation regardless of caller, so even
  a future caller that forgets the fence cannot regress a lineage. The guarantee is
  structural, not a comment asking the next caller to be careful.
- **The report wire is unchanged.** `instance_generation` is an **inbound-only** wire
  field: the node reads it on a poll to decide whether to act. The report still echoes
  `command_id` + `claim_generation` and nothing more — `claim_generation` remains the
  fencing token for the *report* path, `instance_generation` is the fencing token for
  the *command-execution* path, and the two do not mix.
- **Zero new dependencies.** A generation is an `int64`, a comparison, and a field on
  a struct that already round-trips through `encoding/json`. Nothing here needs a
  library. The zero-private-dependency invariant ([AGENTS.md](https://github.com/hardrails/steward/blob/main/AGENTS.md)) is
  untouched.
- **Scope is one race.** This closes the `instance_id`-reuse race and nothing else.
  It is not credential rotation, not TLS, not multi-control-plane failover, and — see
  [What this deliberately does not solve](#what-this-deliberately-does-not-solve) — not
  the separate batch-ordering follow-up.

## The shape chosen

### Where the generation lives: on the tracked `Instance`, persisted

Extend `runtime.Instance` with one field, adopting the wire type of the existing
`ClaimGeneration` (`int64`) exactly so no lossy conversion or second numeric type is
introduced:

```go
type Instance struct {
	InstanceID string          `json:"instance_id"`
	RuntimeRef string          `json:"runtime_ref"`
	Status     Status          `json:"status"`
	Generation int64           `json:"generation,omitempty"` // NEW
	Spec       json.RawMessage `json:"spec,omitempty"`
}
```

This is the **reuse-before-build** choice the task calls for: the tracker already
persists every `Instance` on every mutation and reloads it on startup (`persist.go`),
so the generation survives a restart *for free*, exactly the way the durable state it
rides already does. No separate file, no separate load/save machinery, no second
persistence lifetime to reason about.

Decisions for the persisted field:

- **`omitempty`, and the state-file format version stays `1`.** The field's zero
  value (`0`) is a safe, meaningful default — "no lineage baseline / no fencing" (see
  the compatibility matrix below) — so it needs no format-version bump. `omitempty`
  keeps a generation-0 instance byte-identical to what today's Steward writes, and an
  old state file (no `generation` key) loads as generation 0. This is the same
  additive discipline `Spec omitempty` already uses; bumping `stateVersion` would
  gratuitously break a mixed-version rolling restart that shares one state file — a
  configuration the uplink design explicitly contemplates ("one durable file that both
  callers share").
- **Downgrade caveat, named not hidden.** If an operator *downgrades* to a
  pre-generation Steward, its `Instance` struct has no `Generation` field, so the next
  mutation rewrites the file without it and the generation baseline is lost (resets to
  0) for any re-persisted instance. This deactivates fencing on downgrade — i.e. it
  returns to today's accepted-risk baseline, **never worse**, and never corrupts the
  file. A downgrade losing a forward-compatible feature is the expected cost, worth one
  sentence here so it is a choice, not a surprise.
- **Load-time hardening (minor).** `load()` already rejects a structurally corrupt or
  hand-edited state file field by field; add one clause rejecting a **negative**
  generation (`inst.Generation < 0`) as corrupt, since a generation is a monotonic
  non-negative counter and a negative value can only be a damaged or tampered file.
  Uniform with the existing `!inst.Status.valid()` and non-object-`spec` clauses.

### The wire field: inbound-only, zero as the "unset" sentinel

The poll-response `command` gains one field, mirroring `ClaimGeneration`'s shape:

```go
type command struct {
	CommandID          string          `json:"command_id"`
	NodeID             string          `json:"node_id"`
	RuntimeRef         string          `json:"runtime_ref"`
	Kind               string          `json:"kind"`
	Payload            json.RawMessage `json:"payload"`
	ClaimGeneration    int64           `json:"claim_generation"`
	InstanceGeneration int64           `json:"instance_generation"` // NEW, inbound-only
}
```

An absent field decodes to `int64(0)` naturally, so **zero is the "unset"
sentinel**: an old control plane that never sends the field, and a new one that
sends `0`, are treated identically as "no fencing for this command." This depends on
minted generations being **≥ 1** (a fresh `provision` bumps from an initial mint, so
`0` is never a live generation) — a cross-repo assumption listed in the
[reconciliation checklist](#the-wire-contract) to confirm against the framework side,
exactly as uplink-client.md reconciled its field semantics rather than guessing. Even
if a real generation could ever be `0`, treating `0` as no-fencing degrades that one
command to today's behavior — never worse — so the sentinel choice fails safe.

The **report is not touched.** The server fences a *report* on `claim_generation`
(the report path's token); it does not need the node to echo `instance_generation`
back to fence a *command*. Keeping the report shape stable is deliberate: it is the
node's own local decision whether to act, not something the server re-derives from
the report.

### The fence check: one guard in `execute`, before the kind switch

The check lives in `dispatcher.execute`, immediately after the existing
unparseable-ref and foreign-`node_id` guards and **before** the `switch cmd.Kind`.
It reads the tracker's currently-tracked generation for the command's `instance_id`
through one new read accessor — the sibling of `RefForInstance`:

```go
// GenerationForInstance returns the generation currently tracked for instanceID,
// or (0, false) when no live instance has that instance_id. A locked read of the
// existing byID/byRef indexes, no lifecycle logic — the fence-check analog of
// RefForInstance.
func (t *Tracker) GenerationForInstance(instanceID string) (generation int64, ok bool)
```

The fence rule, applied uniformly to every command kind:

```
trackedGen, known := GenerationForInstance(instanceID)
if known && cmd.InstanceGeneration != 0 && cmd.InstanceGeneration < trackedGen {
    // stale: a newer generation of this instance_id has superseded the command.
    → drop it (see "Fenced-stale semantics" below)
}
// otherwise: fall through to the existing per-kind dispatch unchanged.
```

Each clause earns its place:

- **`known` false → do not fence.** No local baseline means nothing to compare
  against; this is the fresh-node / never-seen bootstrap (see
  [First-seen](#first-seen-a-nodes-view-before-any-provision)). The existing behavior
  applies (a `start` defers then fails-unknown; `stop`/`hibernate` fail-unknown; a
  `destroy` is idempotently done) — the fence adds nothing because there is nothing to
  fence against.
- **`cmd.InstanceGeneration == 0` → do not fence.** Backward compatibility with an old
  control plane (see [rollout matrix](#the-wire-contract)).
- **`cmd.InstanceGeneration < trackedGen` → fence.** Strictly-older only. A command at
  or above the tracked generation is *not* stale and must proceed: dropping a
  legitimately-current `stop` would be a worse failure (a real intent silently
  ignored) than the rare edge a stricter rule would catch, and the primary race this
  closes — a superseded OLD command hitting a re-provisioned instance — is fully
  covered by strict `<`. A command *newer* than tracked (`>` — the node missed the
  provision that bumped the lineage) is deliberately allowed through and reconciled by
  the control plane; only `provision` adopts a new generation (below), keeping
  generation-adoption in exactly one place.

Choosing a **dedicated `GenerationForInstance`** over folding the generation into
`RefForInstance`'s return is deliberate: the fence needs only the generation and runs
*before* the per-kind handlers resolve the ref, so a dedicated read keeps
`RefForInstance` and its existing test untouched. The one extra locked read (the fence
in `execute`, then the ref resolve in `transition`/`destroy`) is a trivial in-memory
map lookup, and the window between them is benign — a tracked generation only ever
*increases*, so a stale command stays stale.

### Fenced-stale semantics: silently drop, do not report `failed`

A fenced-stale command reports **no** result and executes **nothing** — the node
logs it at INFO and moves on. `execute` gains a third outcome distinct from its
current `(report, retry)` pair: **fenced** (send no report, do not defer). It does
**not** report `failed`, and it does **not** fabricate a `done`.

The reasoning, strongest first:

1. **A `failed` report would corrupt the operator's failure signal.** A fenced command
   is not a failure — it is the *expected* consequence of at-least-once delivery plus
   `instance_id` reuse. Reporting `failed` would light up a genuine, operator-visible
   failure channel for a command that was correctly and deliberately ignored, and could
   trigger reconciliation that re-drives a command that should stay dead. This is the
   analog of the server's own `report_command_result`, which treats a mismatched
   `claim_generation` as a **silent `applied: false` no-op**, never a `4xx` — a
   superseded message is a no-op, not an error, on *both* sides of the wire.
2. **A fabricated `done` report could corrupt the live instance's control-plane
   state.** The stale command (say `stop(agent-1, gen 1)`) is a legitimately-*current*
   claim, so its `claim_generation` matches and the server would **apply** a report for
   it — and if the server writes `reported_status` keyed by `(node, instance_id)`
   without generation-awareness, a `done`+`stopped` report for gen-1's stop would stamp
   the **gen-2** instance's row as stopped. The fence prevents the local mutation; a
   fabricated report would leak the same corruption through the report path. So the node
   must not send one.
3. **Silent drop reuses the system's existing self-healing path exactly.** The uplink is
   already designed around "no report → the server redelivers via its claim lease" (a
   lost report is self-healing; see uplink-client.md). A fenced command that sends no
   report looks to the server precisely like a lost report, and the server does what it
   always does. The **only** difference is that a fenced command will be fenced again on
   every redelivery (the tracked generation only rises), so it never *succeeds* — which
   means something on the server must eventually **retire** it rather than redeliver it
   forever.

That last point is the one **cross-repo coordination** this design depends on: the
companion framework change, which already mints and bumps `instance_generation`, must
also **retire a superseded-generation command** (refuse to redeliver a command whose
`instance_generation` is older than the lineage's current generation) rather than
redelivering it on lease expiry indefinitely. Until it does, a fenced command incurs
bounded redelivery churn — a cheap re-fence each poll, never a corruption — which is
strictly better than the two reporting alternatives above. This is listed in the
reconciliation checklist. The node side is correct and safe regardless of *when* the
server ships that retirement; it simply stops churning once the server does.

### Provision adoption: atomically inside `Tracker.Provision`

A fresh `provision` carries the new (post-destroy, post-reprovision) generation, and
Steward must **adopt** it as the new local baseline. The adoption happens **inside**
`Tracker.Provision`, atomically under the tracker's existing single mutex — the answer
to the task's "before, after, or atomically with the tracker's `Provision` call" is
**atomically with**. `Provision` gains the generation as a parameter:

```go
func (t *Tracker) Provision(instanceID string, generation int64, spec json.RawMessage) (inst *Instance, created bool, err error)
```

- **New instance:** `Generation = generation`.
- **Existing instance (the idempotent re-provision path):** `Generation = max(existing, generation)` — provision **never lowers** a generation.

Atomicity is load-bearing and closes a reintroduced-race trap: if adoption were a
*separate* `SetGeneration` call after `Provision` returned, a stale lifecycle command
arriving in the window between the two locked calls would read the not-yet-adopted
(old/zero) generation and act on the fresh instance — exactly the race this feature
exists to close, reopened by a two-step update. Folding adoption into `Provision`
closes the window under the mutex that already serializes every mutator.

The `max()` (never-lower) rule makes `Provision` **self-protecting** regardless of
caller — the careless-caller discipline in structural form. The fence guard already
ensures only `generation >= trackedGen` provisions reach `Provision` (older ones are
dropped), so `max()` is belt-and-suspenders on the dispatch path; but it also protects
a *direct* tracker caller and the missed-destroy convergence case (a re-provision whose
higher generation is adopted onto an instance the node never saw destroyed, after
which the old lineage's commands fence correctly — self-healing).

The **REST handler passes `0`.** `internal/server`'s `handleProvision` calls
`s.tracker.Provision(req.InstanceID, spec)`; it becomes
`s.tracker.Provision(req.InstanceID, 0, spec)`. The direct-REST / direct-dial path has
no `instance_generation` concept, and `0` is the coherent "no fencing" value: it never
lowers an existing generation (`max` protects it) and a new REST-provisioned instance
simply starts at generation 0 (unfenced), which is precisely today's behavior for the
inbound path. Extending the **one** shared `Provision` signature (and its `uplink.Tracker`
interface entry) — rather than adding a second `ProvisionWithGeneration` method — is
deliberate: two provision paths would be the exact "two callers silently enforce
different contracts" divergence the uplink design already fought when it insisted the
uplink reuse `IsJSONObject` instead of re-implementing the spec check.

### First-seen: a node's view before any `provision`

For an `instance_id` the tracker has **never** seen
(`GenerationForInstance → ok=false`), there is no prior lineage to compare against, so
**the fence does not trigger and the first command is accepted at whatever generation
it carries; the node enforces monotonically from there.** This is the standard
fencing-token bootstrap — trust the first token you see, then require monotonic
increase — and it is an edge case worth naming, not glossing.

Concretely, for a fresh node, or one that missed the original `provision` during
downtime:

- **First command is `provision`:** the instance is created and **adopts** the carried
  generation as its baseline (above). Every later older-generation command for that
  `instance_id` is then fenced. This is the common recovery path: a node that was down
  never reported the provision `done`, so the server's claim lease **redelivers the
  provision**, and the node adopts the generation from it before any dependent command.
- **First command is `start` for a never-seen `instance_id`:** `ok=false`, not fenced;
  the existing behavior applies — the batch runner defers one retry (a sibling
  `provision` may be later in the same poll), then reports `failed`. The control plane
  reconciles and re-drives (re-sends the provision). Self-corrects.
- **First command is `stop`/`hibernate` for a never-seen `instance_id`:** `ok=false`,
  not fenced; reports `failed` immediately (you cannot stop what was never provisioned).
  Unchanged.
- **First command is `destroy` for a never-seen `instance_id`:** `ok=false`, not fenced;
  reported idempotently `done` ("the goal is already met — it is gone"). Unchanged.

The residual risk — a fresh node whose very *first* command for an `instance_id`
happens to be a stale one it cannot recognize as stale — is **not made worse** than
today (today has no fencing at all) and is closed for every *subsequent* command once a
baseline exists. Refusing all commands until some out-of-band baseline arrived would
brick a legitimately-fresh node; accept-then-enforce-monotonically is the safe choice.

### The rollout compatibility matrix

Because a control plane and Steward can ship on independent schedules, the
deployment-ordering question is real. Every cell degrades to today's accepted behavior
or better — **no synchronized upgrade is required**, and the fix activates only when
both sides are new:

| Steward | control plane | `instance_generation` on the wire | behavior |
| ------- | ------------- | --------------------------------- | -------- |
| old     | old           | absent                            | today's behavior (the accepted race). |
| old     | new           | present, ignored                  | today's behavior — old Steward ignores the unknown JSON field (Go drops unknown fields); the framework field is additive. Never worse. |
| **new** | old           | absent → decodes to `0`           | fence dormant (`cmd.InstanceGeneration == 0` → not fenced; provisions adopt `0`). **Today's behavior — the safe default this design owes.** A Steward upgrade needs no control-plane upgrade. |
| **new** | new           | present, `≥ 1`                    | **full fencing — the race is closed.** |

## The wire contract

The only wire change is one additive field on each element of the existing
`POST /uplink/poll` response, carried alongside `claim_generation`:

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

`POST /uplink/report` is **unchanged** (it still carries `command_id`, `status`,
`reported_status`, `claim_generation`, `result`). Steward's own published inbound
contract (`openapi/steward.v1.yaml`) is **unchanged** — this is an outbound-client
behavior, not an inbound endpoint, exactly as uplink-client.md established.

### Reconciliation checklist — confirm against the framework side

Mirrors uplink-client.md's device: these are the cross-repo assumptions to confirm by
reading the companion change, not to guess.

- [ ] `NodeCommand.instance_generation` is minted **≥ 1** and bumped on every fresh
      `provision`, so `0` is an unambiguous "unset" sentinel (see the zero-sentinel
      rationale). If the framework can ever mint `0` as a live generation, the sentinel
      still fails safe (that one command degrades to no-fencing), but confirm the
      intended floor.
- [ ] `instance_generation` mirrors `claim_generation`'s lineage key exactly —
      `(tenant_id, node_id, instance_id)` — so the node's per-`instance_id` tracking is
      the correct granularity.
- [ ] The server **retires a superseded-generation command** (refuses to redeliver a
      command whose `instance_generation` is older than the lineage's current
      generation) rather than redelivering indefinitely — the coordination the node's
      silent-drop semantics depend on to avoid redelivery churn (see
      [Fenced-stale semantics](#fenced-stale-semantics-silently-drop-do-not-report-failed)).
- [ ] The report path stays fenced on `claim_generation` only; the server does **not**
      expect the node to echo `instance_generation` back on a report.

## Buy vs build

**Decision: build. Add no dependency.** A generation is an `int64`, an `<` comparison,
a `max`, and one struct field that already serializes through `encoding/json`. There is
nothing here a library would do, and adding one would forfeit the zero-private-dependency
invariant that is the whole reason Steward is a separate public repo
([AGENTS.md](https://github.com/hardrails/steward/blob/main/AGENTS.md)). As with uplink-client.md, this decision is recorded inline
as prose rather than as a `docs/adr/NNNN-*.md` file **on purpose**: this repo records
architectural decisions as prose sections, and an ADR directory tree would be the kind
of over-building this design resists.

## Task list (ordered, each with its acceptance check)

Layer tags use Steward's own layout: `runtime` (tracker), `uplink` (the outbound
client), `server` (inbound REST — one call-site update only), `cmd` (wiring), `docs`.

1. **`runtime`: add `Instance.Generation` + persist it.** Add the `int64
   json:"generation,omitempty"` field; ensure `clone()` copies it (it is a value field,
   so the existing `c := *i` already does — confirm, do not add machinery); add the
   `inst.Generation < 0` corrupt-file clause to `load()`. No format-version bump.
   *Check:* a unit test provisions with a generation, saves and reloads via a
   `-state-file`, and asserts the generation round-trips; an old-format file with no
   `generation` key loads as generation 0; a negative generation is a fail-closed load
   error naming the path. Gate: `go test -race ./internal/runtime`.

2. **`runtime`: generation-aware `Provision` + `GenerationForInstance`.** Add the
   `generation int64` parameter to `Provision` with the new-instance-set /
   existing-instance-`max` (never-lower) rule, atomically under the existing mutex; add
   the `GenerationForInstance` read accessor over `byID`/`byRef`. Depends on 1.
   *Check:* provisioning a new id sets its generation; re-provisioning the same id with a
   *lower* generation does not lower it, with a *higher* one raises it; provisioning with
   `0` leaves an existing generation untouched; `GenerationForInstance` returns
   `(gen, true)` for a live id and `(0, false)` for an unknown one. Run with `-race`.
   Gate: `go test -race ./internal/runtime`.

3. **`server`: pass `0` from the REST handler.** Update the single call site
   (`handleProvision`, `internal/server/server.go`) to `Provision(req.InstanceID, 0,
   spec)`. No behavior change on the inbound path.
   *Check:* the existing `internal/server` tests still pass unchanged; a REST-provisioned
   instance reports generation 0 via the tracker. Gate: `go test ./internal/server`.

4. **`uplink`: carry `instance_generation` + fence in `execute`.** Add the
   `InstanceGeneration int64 json:"instance_generation"` field to `command`; add the
   fence guard in `execute` before the kind switch (the `known && != 0 && <` rule) and
   the **fenced** third outcome (no report, no retry); pass `cmd.InstanceGeneration`
   through the `provision` dispatch to the generation-aware `Provision`; update the
   `uplink.Tracker` interface to the new `Provision` signature and add
   `GenerationForInstance`. Depends on 2.
   *Check:* table tests drive `execute` against an in-memory tracker: a command with
   `instance_generation` **older** than the tracked generation is dropped — no report is
   sent, the tracker mutator is never called, and it is logged INFO not ERROR (assert via
   a spy tracker that records calls); a command at or above the tracked generation
   proceeds; a command with `instance_generation == 0` is never fenced (old-server
   compatibility); a never-seen `instance_id` is not fenced (first-seen bootstrap); a
   `provision` adopts its generation. Gate: `go test -race ./internal/uplink`.

5. **`uplink`: the fenced outcome through `executeBatch`.** Ensure a fenced command
   sends no report and is not deferred to the start-retry pass, and that fencing composes
   correctly with the existing batch rules (a `destroy(x)` → `provision(x)` replace and
   the start-defer pass both still behave as before). Depends on 4.
   *Check:* an `httptest.Server`-driven test with a batch containing a stale command
   asserts exactly the non-stale commands are reported and the stale one produces no
   report POST; a replace batch still recreates `x`; a deferred `start` still retries
   once. Gate: `go test -race ./internal/uplink`.

6. **`docs`: document the mode.** Add the new "Uplink commands are generation-fenced"
   subsection to ARCHITECTURE.md (in the existing style, beside "Outbound uplink is
   opt-in"), and a one-line note that the persisted instance record gained an additive
   `generation` field with no format-version bump. `openapi/steward.v1.yaml` is
   **unchanged** (outbound-client behavior, no inbound-contract change) — state this so a
   reader does not go looking for it in the spec.
   *Check:* `spectral lint` still passes on the unchanged spec; prose review against this
   design. Gate: the `openapi lint` CI job + review.

The full battery for the change is the three required CI jobs: `go build ./...`,
`go vet ./...`, `go test -race ./...` (`build / vet / test`), `golangci-lint`, and
`spectral lint`.

## What this deliberately does not solve

Named explicitly so they are choices, not oversights.

- **Batch ordering within a single poll.** `instance_generation` is a *fencing* token
  ("is this command for the current lineage?"), **not** an *ordering* token ("in what
  order do the commands in this one poll apply?"). The batch-ordering concern — the
  claim query has no `ORDER BY`, and a `destroy(x)` → `provision(x)` replace must not be
  reordered — is handled by the existing no-reorder + one-pass start-retry mechanism in
  `executeBatch`, and the sound long-term fix (a causal sequence on `runtime_ref`)
  remains the **separate** cross-repo follow-up uplink-client.md already tracks. This
  design does not close, replace, or depend on it.
- **The server-side minting, bumping, and retirement of `instance_generation`.** That is
  the companion framework change (the `hardrails` repo). This document is the node half;
  the reconciliation checklist names what the node assumes of the server half.
- **Everything uplink-client.md already deferred stays deferred** — TLS / mTLS,
  node-side credential rotation, multi-control-plane failover, disabling the inbound
  listener, a durable outbound report queue, report batching. This change pulls none of
  them in.
</content>
</invoke>
