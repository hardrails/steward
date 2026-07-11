---
title: Outbound uplink client
description: Design provenance and wire contract for Steward's implemented NAT-friendly outbound command and reporting channel.
section: Design record
---

# Design: the outbound uplink client (NAT-friendly control channel)

Status: **implemented; design provenance and wire contract.** This document records the shape chosen, the shapes
rejected, the invariants the design must hold, and the exact task list. It follows
the same style as [ARCHITECTURE.md](https://github.com/hardrails/steward/blob/main/ARCHITECTURE.md): it explains not just *what*
but *why*, and it names the failure mode each decision closes.

[The wire contract](#the-wire-contract) records the implemented public endpoint
paths, field names, and status vocabulary used between Steward and any compatible
control plane.

## Why this exists

Steward originally served only an **inbound** REST API. That assumed whoever ran the
control plane could dial *into* the node—true only when the node was directly
reachable (same network, public IP, VPN). In
the target sovereign/enterprise deployment the node sits behind NAT or a corporate
firewall that blocks inbound connections entirely, so the control plane can never
open a socket to it.

The fix is to **invert who dials whom.** Instead of the control plane connecting to
the node, the node makes an **outbound-only** HTTP connection *out* to the control
plane, asks "do you have any commands for me?", executes whatever comes back against
its existing local tracker, and reports the result. NAT and stateful firewalls
allow outbound connections by default, so this channel works from exactly the
places the inbound API cannot reach. The control plane *queues* commands; the node
*polls* for them.

This is the **client** half—the code that runs inside Steward. A compatible control
plane owns the server half: poll/report endpoints, node enrollment, command claims,
and credential issuance. Both sides use the public wire vocabulary documented below.

## What stays true (invariants)

- **Additive, opt-in, and off by default.** A node with no uplink configured behaves
  *exactly* as today: inbound REST only. Enabling the uplink adds a background
  goroutine and changes nothing about the existing endpoints, status codes, or the
  published `openapi/steward.v1.yaml` contract. This mirrors how `-state-file`
  turns durable state on without changing any request/response shape.
- **One tracker, one source of truth.** The poll loop is a **second caller of the
  same `internal/runtime` tracker methods** the REST handlers already call —
  `Provision` / `Start` / `Stop` / `Hibernate` / `Destroy` / `Status`. It is *not*
  a parallel lifecycle implementation. The tracker's single mutex already serializes
  every mutator, so a node running *both* channels at once is safe for free: there
  is no new concurrency surface, no second copy of the state machine, and (when
  `-state-file` is set) one durable file that both callers share.
- **Zero new dependencies.** `net/http`, `encoding/json`, `time`, `context`,
  `log/slog`, `math/rand/v2`, `os` — standard library only. No third-party HTTP
  client, retry library, or backoff library. The bounded-backoff loop is small
  enough to write by hand, and hand-writing it is the whole point of the repo (see
  [Buy vs build](#buy-vs-build)).
- **Fail closed on startup.** If the uplink is enabled but its credential is
  missing or corrupt, Steward refuses to start with an error that names the path
  and the fix — the exact discipline `runtime.LoadTracker` already applies to a
  corrupt `-state-file`. There is no "uplink silently disabled because the
  credential didn't load" path.
- **Single-tenant by construction.** A node's credential binds exactly one tenant.
  The client only ever presents its own credential and only ever acts on commands
  addressed to its own `node_id`. It has no way to name, read, or mutate another
  tenant's or another node's work.

## The shape chosen

### Configuration surface

Every setting is a flag with a matching `STEWARD_`-prefixed env var (flag wins),
following the existing `-addr` / `-state-file` convention exactly.

| Flag                        | Env var                            | Default | Purpose                                                                     |
| --------------------------- | ---------------------------------- | ------- | -------------------------------------------------------------------------- |
| `-uplink-url`               | `STEWARD_UPLINK_URL`               | (unset) | Control-plane base URL. **Its presence is the opt-in switch**: unset ⇒ uplink disabled (current behavior). |
| `-uplink-credential-file`   | `STEWARD_UPLINK_CREDENTIAL_FILE`   | (unset) | Path to the local credential JSON. **Required** when `-uplink-url` is set; fail-closed if missing/corrupt. |
| `-uplink-poll-interval`     | `STEWARD_UPLINK_POLL_INTERVAL`     | `10s`   | Base poll cadence (a Go duration string). Jitter is applied on top.        |

The uplink is enabled **iff `-uplink-url` is non-empty**, mirroring how the presence
of `-state-file` enables durable state. When enabled, `-uplink-credential-file` must
resolve to a valid credential file or Steward exits non-zero at startup.

`node_id` is **not** a flag: it lives in the credential file (below), because it is
minted by the control plane at enrollment, not chosen by the operator at launch.

### Node identity / credential storage

The node needs a bearer credential — `(tenant, node, secret)`, minted by the control
plane operator at enrollment — persisted locally so it survives a restart. It is
stored the same way `internal/runtime/persist.go` stores durable state: a small,
**versioned**, atomically-written JSON file, using only `encoding/json` and `os`.

The file the operator drops on the node (the output of enrollment) is:

```json
{
  "version": 1,
  "tenant_id": "acme",
  "node_id": "node-7",
  "credential": "<opaque bearer token minted at enrollment>"
}
```

Design decisions for this file:

- **The `credential` is stored as one opaque string** and sent verbatim in the auth
  header. Steward does **not** parse it, and therefore does **not** reimplement the
  control-plane length-prefixed credential codec
  (`format_node_credential`/`parse_node_credential`). That keeps Steward decoupled
  from a private encoding: the token is minted server-side and the node only echoes
  it. This is why `tenant_id` and `node_id` are stored as **separate explicit
  fields** rather than extracted from the token — the client needs `node_id` locally
  (to verify each command is addressed to *this* node, and for logging) but must not
  depend on the token's internal format to get it.
- **Loaded fail-closed at startup**, before the poll loop starts, exactly like
  `LoadTracker`: a missing file (when uplink is enabled), unreadable file, invalid
  JSON, wrong `version`, or an empty `tenant_id`/`node_id`/`credential` is a fatal
  startup error whose message names the path and the remedy (re-enroll this node and
  write the credential to `<path>`), never a silent disable.
- **Read-only after load.** v1 never rewrites this file — there is no credential
  rotation on the node side (see [Deliberately deferred](#deliberately-deferred)).
  So it needs none of `persist.go`'s temp-file/fsync/rename write machinery; it only
  needs the *load-and-validate* half. It is a separate small file from the
  `-state-file` snapshot: different lifetime (operator-provisioned secret vs.
  runtime state), different sensitivity.

### The poll loop

A single background goroutine, started from `cmd/steward/main.go` only when the
uplink is enabled, driven by the same `context.Context` that already carries
`SIGINT`/`SIGTERM` via `signal.NotifyContext`. Its cycle:

```
loop:
  wait( next interval, or ctx.Done() → return )   // time.Timer selected against ctx
  commands, err := poll(ctx)                       // outbound POST, credential in header
  classify(err / HTTP status):
    ok        → reset backoff; execute & report each command (below)
    transient → increment backoff; log WARN; continue
    fatal     → log ERROR naming the remedy
                → CredentialPath set (the normal case): pause and watch the
                  credential file (see "Node-side credential hot-reload" below),
                  then resume with the new credential once it changes
                → CredentialPath unset: return (stop the loop) — pre-hot-reload
                  fallback, only reachable from a caller that built a Poller
                  without a credential path
```

- **Jitter (thundering-herd avoidance).** The steady-state wait is
  `interval ± up to 20%`, randomized per cycle with `math/rand/v2`. If many nodes
  restart together (a control-plane redeploy, a datacenter power event), their polls
  decorrelate instead of arriving in a synchronized wave.
- **Cancellation.** The inter-poll wait is a `time.Timer` in a `select` against
  `ctx.Done()`, and every outbound request is built with
  `http.NewRequestWithContext(ctx, …)`, so a shutdown signal cancels both the sleep
  and any in-flight request immediately. `main` waits for the loop's `done` channel
  (bounded by the existing shutdown timeout) before exiting, mirroring the current
  `srv.Shutdown` graceful-shutdown block.
- **HTTP client.** One shared `*http.Client` with an explicit `Timeout` (so a black-
  holed control plane cannot wedge a poll forever). No global `http.DefaultClient`.

### Executing a command against the tracker

Each `NodeCommand` carries a control-plane-minted, self-describing `runtime_ref`
(`uplink:<len>:<node_id>:<instance_id>`), a `kind`, an opaque `payload`, a
`command_id`, and a `claim_generation` fencing token. The five `CommandKind`s map
**1:1** onto the existing tracker methods:

| `CommandKind` | tracker call                          | resulting `Status` | `reported_status` (wire) |
| ------------- | ------------------------------------- | ------------------ | ------------------------ |
| `provision`   | `Provision(instance_id, payload)`     | `PENDING`          | `provisioning`           |
| `start`       | `Start(ref)`                          | `RUNNING`          | `running`                |
| `stop`        | `Stop(ref)`                           | `STOPPED`          | `stopped`                |
| `hibernate`   | `Hibernate(ref)`                      | `HIBERNATED`       | `hibernated`             |
| `destroy`     | `Destroy(ref)`                        | (removed)          | see note                 |

**The addressing-namespace reconciliation (the one subtle part).** The control plane
addresses instances by the `uplink:…` ref it minted. Steward's tracker mints its
*own* opaque ref (`rt_<hex>`) at provision time and keys everything else on that ref.
These are two different namespaces for the same instance. The client bridges them
without a second source of truth:

1. Parse the command's `runtime_ref` into `(node_id, instance_id)`. **Reject** (log
   ERROR, report `failed`) any command whose `node_id` is not *this* node — the
   client-side analog of the server adapter's `_verify_issued` check. The server
   should only ever queue commands for this node, so this is a version-skew / bug
   tripwire, not an expected path.
2. `provision` calls `Provision(instance_id, payload)` — the tracker mints its
   `rt_<hex>` and the client learns it from the return value. **The client must apply
   the same object-shape validation the inbound REST handler already applies**
   (`internal/server`'s `isJSONObject`, called from `handleProvision`): a non-object
   `payload` (a bare scalar or array) is rejected — reported `failed` with a message
   naming the shape problem, never passed to `Tracker.Provision` — before the tracker
   ever sees it. Without this, the uplink path would create tracker state the
   published REST contract would have rejected as `400 invalid_request`, so the two
   lifecycle callers would silently enforce different instance-spec contracts (a real
   finding from this doc's own review — see the task-list acceptance check below).
   Reuse `isJSONObject` directly (export it, or move it beside the tracker) rather
   than re-implementing the check a second time.
3. `start` / `stop` / `hibernate` / `destroy` need the tracker's `rt_<hex>` ref. The
   client resolves `instance_id → rt_<hex>` through the tracker's own `byID` index
   via **one new read-only method** (below), then calls the existing transition
   method with that ref.

The `instance_id ↔ rt_<hex>` mapping already lives inside the tracker (its `byID`
map) and is already persisted by `-state-file`. So the client stores **no** mapping
of its own and reconstructs nothing on restart — the tracker remains the single
source of truth. The only new surface on `internal/runtime` is a read accessor:

```go
// RefForInstance returns the runtime_ref currently tracked for instanceID, if any.
// It is a locked read of the existing byID index — no lifecycle logic — so the
// uplink caller can address an instance the control plane names by instance_id.
func (t *Tracker) RefForInstance(instanceID string) (runtimeRef string, ok bool)
```

This is a read accessor, not a parallel lifecycle path: it exposes an existing index
so the *same* tracker methods can be driven by an instance-id-addressed caller. A
resolve-then-act across two locked calls is safe — if the instance is destroyed
between resolve and act, the second call returns `ErrNotFound`, which is exactly the
"report `failed`" outcome we want, not a race.

**Idempotency and redelivery are safe by construction.** The server may redeliver a
command (its claim lease treats a slow node as a crashed one and reclaims the
command to a second execution). Re-executing against the tracker is safe because the
tracker's operations are idempotent in *effect*:

- `provision` is idempotent on `instance_id` (a repeat returns the existing instance).
- `start` / `stop` / `hibernate` are idempotent transitions (setting `RUNNING` twice
  lands on `RUNNING`).
- `destroy` maps `ErrNotFound` → **`DONE`, not `failed`**: the command's desired end
  state is "this instance is gone," so an already-absent instance means the goal is
  already met. This is the one place the client must *not* treat `ErrNotFound` as a
  failure, or a redelivered `destroy` (after a lost report) would falsely report a
  failure for an instance that was in fact destroyed.

For `start` / `stop` / `hibernate`, `ErrNotFound` **is** a genuine failure (you
cannot start an instance the node has never provisioned) → report `failed`; the
control plane reconciles and re-drives.

**Batch ordering.** A single poll can return several commands for the same
instance, and the wire contract does not guarantee that a returned batch is causal or
chronological. The client therefore processes a batch in the **server's own
returned order, reordering nothing**, then makes exactly **one bounded retry
pass** over **`start` only**: a `start` that fails only because its instance is
not yet known (the `RefForInstance` miss) is deferred, not reported failed; after
the first pass runs to completion, each deferred `start` is retried exactly once
(a sibling `provision` earlier *or later* in the same batch has now had its chance
to run); a `start` still naming an unknown instance then reports `failed` for real.
This is bounded (one retry pass, never an unbounded loop), needs no server-side
wire change, and — because `destroy` is already idempotent on a missing instance,
`provision` depends on no sibling, and `stop`/`hibernate` are deliberately excluded
(see below) — only `start` ever defers.

> **Retraction (closed review finding).** An earlier version of this design moved
> every `provision` to the front of the batch ("provisions always first"),
> reasoning that a `start` should not hit an unknown instance ahead of its own
> provision. A hosted review found that blanket reordering **inverts a REPLACE**:
> when a single poll carries `destroy(x)` then `provision(x)` (the control plane
> replacing an instance), hoisting the provision ahead of the destroy runs
> `provision` (an idempotent no-op — `x` still exists) and *then* `destroy`, ending
> with `x` **gone** instead of recreated. The corrected approach above reorders
> nothing, so the `destroy → provision` replace runs in the intended order, while
> the one retry pass still closes the original `start`-before-its-own-provision
> case. A wire-level ordering guarantee — an epoch/generation or a causal sequence
> on `runtime_ref` is the sound long-term fix and belongs in the public protocol,
> not in this client-only change.

> **Narrowing (second, more precise hosted review finding).** The fix above first
> shipped with the deferred retry applying to **any** of `start` / `stop` /
> `hibernate` on an unknown instance, on the theory that a sibling `provision`
> anywhere in the batch might create the instance in time for all three. A second
> hosted review found that reasoning only holds for `start`: `stop`/`hibernate` on
> a missing instance has no equivalent legitimate case, and deferring them
> introduces a **new** ordering inversion — a batch carrying `stop(agent-1)` then
> `provision(agent-1)` would defer the stop, let the provision create the instance,
> and then the retry pass would **stop the instance the provision just created**,
> which is very likely wrong (the stop probably targeted an old/different lineage,
> or the control plane's intent does not include stopping something it is
> provisioning in the same batch). This is the same class of bug the first
> retraction above already closed for `destroy`/`provision`, resurfacing for
> `stop`/`hibernate`. The retry-eligibility signal is now scoped to `start` only:
> `stop`/`hibernate` on a missing instance report `failed` immediately on the first
> pass, exactly as they did before the batch-ordering fix was introduced.

### Reporting a result

After executing each command, the client POSTs a report echoing the command's
`command_id` **and `claim_generation` verbatim**, its terminal `CommandStatus`
(`done`/`failed`), the `reported_status` (the mapped agent-instance lifecycle state),
and an opaque `result`.

Echoing `claim_generation` verbatim is **load-bearing** and non-negotiable: it is
the fencing token the server uses to discard a stale report from a superseded (slow,
lease-reclaimed) execution. A client that dropped or regenerated it would defeat the
server's duplicate-dispatch defense. The client never mints its own `command_id` or
`claim_generation`; it only carries the ones the command arrived with.

**A lost report is self-healing** and needs no durable outbound queue on the node.
If the report POST fails (network blip), the command stays `CLAIMED` server-side; its
lease expires; the server redelivers it with a bumped `claim_generation`; the client
re-executes (idempotent) and re-reports. So report-POST failures are logged at WARN
and *not* retried in an inner loop — the server's existing lease + fencing machinery
is the retry mechanism, and reusing it keeps the node stateless.

### Status vocabulary mapping

Steward's own `Status` values are UPPERCASE and **must not be renamed**
(`internal/runtime` says so, and the direct-REST contract depends on them). The wire's
`reported_status` uses the wire's lowercase lifecycle vocabulary. The
uplink client owns a small translation table so neither side's vocabulary leaks into
the other:

| Steward `Status` | wire `reported_status` | note                                                              |
| ---------------- | ---------------------- | ----------------------------------------------------------------- |
| `PENDING`        | `provisioning`         | Steward's "provisioned, not yet started." Confirmed correct.      |
| `RUNNING`        | `running`              |                                                                   |
| `STOPPED`        | `stopped`              |                                                                   |
| `HIBERNATED`     | `hibernated`           |                                                                   |
| `FAILED`         | `failed`               |                                                                   |
| `DESTROYED`      | `stopped`              | No `destroyed` member exists in the wire vocabulary. See note.   |

Two mappings deserve explicit explanation:

- `PENDING → provisioning`: `provision` and `start` are distinct wire commands, so a
  compatible control plane sends a separate `start` later to drive to `running`,
  exactly mirroring Steward's own two-step `Provision` then `Start` model. No bridge
  is needed beyond the table above.
- `DESTROYED → stopped`: a successful destroy removes the tracked instance, so no
  caller should poll its status afterward. `stopped` is the closest available wire
  value for "no longer running."

### Failure taxonomy (transient vs. fatal)

Mirrors this repo's structured `log/slog` conventions (`logger.Warn`/`logger.Error`
with key/value fields). The 3am test applies to every message: it must say what to do
next.

| Condition                                  | Class      | Behavior                                                                                       |
| ------------------------------------------ | ---------- | ---------------------------------------------------------------------------------------------- |
| `2xx`                                      | ok         | Process commands; reset backoff to base.                                                        |
| network error / timeout / `5xx` / `429`    | transient  | `WARN`; exponential backoff (base × 2^failures, capped at 5m) with the same ±20% jitter; retry. |
| `401` / `403` (bad/revoked credential)     | **fatal**  | `ERROR` naming the remedy; **pause the poll loop and watch the credential file for a fix** (see [below](#node-side-credential-hot-reload)) instead of stopping outright. |
| other `4xx` (e.g. `400`/`404`)             | transient  | `ERROR` naming it as a probable version-skew/bug; back off at the cap and keep retrying.         |

The transient/fatal split is the crux of requirement 3. A rejected bearer credential
does **not** become valid by retrying it against the SAME secret; retrying floods the
control plane's auth path and the node's logs. So `401`/`403` is fatal to the current
credential: the loop logs one loud, actionable `ERROR`
(`"uplink credential rejected; pausing the poll loop and waiting for a new credential
at <path>"`) and pauses — see
[Node-side credential hot-reload](#node-side-credential-hot-reload) for how it resumes
without a restart. The rest of Steward keeps running throughout — an inbound REST
listener, if bound, is unaffected — so "uplink went dark" is visible without taking
the process down. Other `4xx` codes are treated as transient-at-max-backoff so a
control plane mid-deploy (a momentary `404`) does not permanently dark the node over a
blip, while still logging loudly.

### Node-side credential hot-reload

A fatal `401`/`403` used to stop `Poller.Run` outright — recovering after a revoked
node or a rotated secret required a full process restart, even with a corrected
credential file already in place (see
[Deliberately deferred](#deliberately-deferred), where this was originally scoped
out). It is now closed: `Run` pauses instead of returning, and
`waitForCredentialChange` watches the credential file until it changes to a new,
valid credential for this node, then resumes polling with it — no restart, no
operator intervention beyond dropping the new file.

- **Configuration.** `uplink.Config.CredentialPath` is the file `Credential` was
  loaded from; `cmd/steward` always sets it to `-uplink-credential-file`'s value, so
  this is the default behavior for the real binary. It is optional at the `Poller`
  API level — a caller that omits it gets the pre-hot-reload behavior (`Run` stops
  outright on a fatal rejection), since there is then no file to watch.
- **Poll on a bounded interval, never busy-loop.** The wait loop re-reads the file
  every `Config.CredentialWatchInterval` (default `DefaultCredentialWatchInterval`,
  5s), using the same `ctx`-aware `time.Timer` pattern as the ordinary inter-poll
  wait — cancellation (a shutdown) returns promptly instead of blocking until the
  next tick. It issues **no** `/uplink/poll` request while paused: only a local file
  read per tick, so a permanently-wrong credential costs a small stat/read every few
  seconds, never a hot loop and never repeated control-plane traffic.
- **Compare by content, not mtime.** Each tick re-parses the file with
  `LoadCredential` and compares the decoded secret against the one just rejected. An
  mtime-only rewrite (an editor's save, a permissions-preserving copy) must not
  trigger a doomed resume attempt with the same already-rejected secret — mtime alone
  is not trustworthy evidence of a real rotation.
- **Tolerate a torn write.** A non-atomic external rotation tool can leave the file
  transiently absent, truncated, or syntactically invalid mid-write.
  `LoadCredential`'s fail-closed error in that case is logged at `DEBUG` (the
  expected steady state while waiting) and retried on the next tick — never treated
  as a crash or a valid-but-unchanged credential.
- **Refuse a foreign `node_id`.** A reloaded file naming a different `node_id` than
  this process was configured with is refused (logged at `ERROR`, wait continues):
  silently adopting it would re-identify this process as a different node rather than
  rotate its secret, a control-plane trust violation the loop must not paper over.
  Rotating a node's own secret in place, and re-enrolling it as an unrelated node
  identity, are different operations; only the former is hot-reloaded.
- **If the new credential is ALSO rejected,** `Run` pauses and watches again — the
  same `classFatal` → pause → watch → resume cycle, indefinitely, never a crash and
  never a busy loop.

See `internal/uplink/poller_test.go`'s
`TestPollerEntersWatchModeAndResumesOnCredentialFileChange` and its siblings
(`...IgnoresUnchangedOrUnreadableCredentialFile`, `...RefusesCredentialWithDifferentNodeID`,
`...RespectsContextCancellation`) for the behavior pinned as tests, and
`cmd/steward/main_test.go`'s
`TestDisableInboundListenerRecoversFromFatalPollRejectionViaCredentialHotReload` for
the end-to-end proof against the real binary.

### Command backpressure and deduplication

The original design executed a poll's commands **inline**: `poll` returned a batch and
`executeBatch` ran every command before the next poll. That is correct for a
steady-state fleet, but it has no bound on the work one poll commits the node to, and
no guard against re-executing a command the control plane redelivers across poll cycles
(a report lost in transit, a claim-lease reclaim). This is now closed with a **bounded,
in-memory command queue** (`internal/uplink.commandQueue`) between "commands received
from a poll" and "commands executed": the poll loop is the producer, and a single
background consumer drains and executes the queue.

- **Bounded, with a redelivery-safe overflow.** `-uplink-command-queue-depth`
  (env `STEWARD_UPLINK_COMMAND_QUEUE_DEPTH`, default `256`) caps the
  queued-plus-in-flight command count. A poll cycle whose commands would exceed the cap
  has its **excess rejected**, not silently dropped — logged at `WARN` under the
  grep-able `uplink command queue full:` prefix (matching `reload.go`'s `sighup reload:`
  convention), naming each rejected command's `command_id` and `runtime_ref`. Because a
  rejected command is never reported, the server's existing claim-lease machinery
  redelivers it next cycle once the backlog drains — the same "a lost report is
  self-healing" property [Reporting a result](#reporting-a-result) already relies on,
  reused for a rejected command. Rejecting-and-redelivering, rather than blocking the
  poll loop or growing memory without bound, is the whole point: the node accepts only
  what it can hold. The value is validated positive at startup and under
  `-check-config`, unconditionally (not gated on `-uplink-url`), so the `-config`
  schema's `exclusiveMinimum: 0` for `uplink_command_queue_depth` stays a faithful
  mirror of the real validator.
- **Deduplicated across poll cycles by `command_id`.** A command whose `command_id` is
  already queued or in-flight is skipped rather than queued a second time. `command_id`
  is the protocol's own unique command identity, and
  it is exactly what survives a redelivery — the claim lease bumps `claim_generation`,
  never `command_id` — so it is the correct dedup key, not one this client invents.
  `(runtime_ref, kind)` was considered and rejected as the key: two genuinely distinct
  commands can share a `(runtime_ref, kind)` (the control plane legitimately queuing a
  second `start`, or a differing payload), and collapsing them would drop real work.
  The dedup entry lives from enqueue through the **end of execution** (drained but not
  yet completed still counts), which is precisely the window a redelivery must be caught
  in; once a command completes, a genuinely new later delivery of the same id is
  admitted again. This is a work-saving guard, not a correctness fix — the tracker is
  already idempotent in effect (`provision` returns the existing instance, `destroy`
  after destroy reports done), so the win is avoiding redundant tracker mutations and,
  with `-state-file`, redundant disk writes. An empty `command_id` (out-of-contract) is
  never deduplicated, so distinct empty-id commands are not collapsed onto one key.
- **Whole-queue drain preserves batch ordering.** The consumer drains the entire queue
  as one batch and runs it through the existing `executeBatch`, so a poll batch's own
  ordering — and the replace (`destroy`→`provision`) and one-pass start-retry semantics
  `executeBatch` depends on (see [Batch ordering](#the-shape-chosen)) — is preserved,
  while the depth cap still bounds the batch's size. Merging across cycles can only help
  a deferred start (a sibling `provision` from a later cycle now has a chance to run
  first); it never reorders a replace, because the queue is FIFO.
- **A persistently-full queue drains the node from readiness.** A queue full for
  `queueBackpressureThreshold` consecutive poll cycles reports `GET /v1/readiness`
  not-ready (naming the backlog) — a gate checked *before* the poll-success gate, so it
  can drain a node reaching its control plane fine but not executing fast enough. A
  single momentary over-full poll never flips readiness; the node returns to ready on
  its first clean cycle. On a `-disable-inbound-listener` node the signal is instead the
  `steward_uplink_command_queue_depth` and `steward_uplink_commands_rejected_total`
  metrics.

Concurrency and shutdown: the consumer runs under a child context cancelled the moment
the producer loop returns, so a fatal `401`/`403` with no credential-hot-reload path
(`CredentialPath` unset) stops both goroutines without deadlock, and a real shutdown
(parent ctx cancelled) returns both promptly — `Run` joins the consumer before
returning, so `cmd/steward`'s graceful-shutdown wait covers it. See
`internal/uplink/queue_test.go` for the queue's unit proofs and
`internal/uplink/backpressure_test.go` for the end-to-end proofs against an
`httptest` control plane (burst rejection with logged identities, in-flight
deduplication, and both readiness paths).

### Coexistence with the inbound REST API

Three configurations are coherent, and all three are just different callers of the
same tracker:

- **Inbound REST only** — current behavior, unchanged (no `-uplink-url`).
- **Uplink only** — `-uplink-url` set; the node reaches the control plane outbound.
  Note v1 still starts the HTTP listener (it binds `127.0.0.1:8080` by default),
  because a loopback listener is free and useful for local liveness/monitoring
  (`GET /v1/healthz`) even on a NAT'd node. "Uplink only" therefore means "uplink
  enabled, inbound bound to loopback," not "no listener." Fully disabling the inbound
  listener is [deferred](#deliberately-deferred).
- **Both** — allowed and coherent (useful during a migration from direct-dial to
  uplink). Because both channels are just callers of the one mutex-guarded,
  idempotent tracker, there is **no conflict to resolve**: two callers driving the
  same idempotent state machine is exactly the safety the tracker already provides.
  A `provision` racing between the two channels resolves by the tracker's existing
  idempotency-on-`instance_id`; a lifecycle transition racing resolves by the mutex.

## The wire contract

The endpoint paths, JSON field names, and header format below are Steward's public
outbound control-plane contract. The uplink routes carry no `/v1` prefix.

**Poll.** `POST {uplink-url}/uplink/poll` (no `/v1` prefix), empty (or `{}`) body. The
server derives the node from the credential (no `node_id` in the path/body). Response:

```json
{
  "commands": [
    {
      "command_id": "…",
      "node_id": "node-7",
      "runtime_ref": "uplink:6:node-7:agent-1",
      "kind": "provision",
      "payload": { },
      "claim_generation": 3
    }
  ]
}
```

An empty poll returns `{"commands": []}` with `200`, not `204` — poll is `POST`, not
`GET`, because a claim mutates `pending` → `claimed` server-side.

**Report.** `POST {uplink-url}/uplink/report`:

```json
{
  "command_id": "…",
  "status": "done",
  "reported_status": "running",
  "claim_generation": 3,
  "result": { }
}
```

Response: `{"applied": bool}` — `false` on any fenced/stale/duplicate report (a
mismatched or already-superseded `claim_generation`, or an already-terminal command).
The server returns `200` with `applied: false` for all of these, **never** a `4xx` —
so the client must not treat `applied: false` as an error to retry; it is the
"someone else already handled this" no-op signal, not a failure.

`claim_generation` is carried on the wire report even though `core.CommandReport`
models it as a separate `report_command_result` argument — the node must send it, and
it is **required** (no server-side default), matching the "the fencing token must
never be silently dropped at the HTTP boundary" risk both plans flagged independently.

**Auth.** `Authorization: Bearer <credential>` on every poll and report — confirmed,
not just the client's preferred guess; the server-side plan settled on the same
header. `POST /uplink/nodes` (operator enrollment, NOT called by this client — an
operator calls it once out of band and pastes the returned credential into this
node's credential file) runs under the normal tenant-header operator scope instead.

**Content type.** `application/json` both directions.

### Reconciliation checklist — all items resolved

- [x] Endpoint paths and methods: `POST /uplink/poll`, `POST /uplink/report` (no
      `/v1` prefix — corrected from this doc's earlier guess).
- [x] Auth header: `Authorization: Bearer <credential>` — confirmed both sides agree.
- [x] Poll returns `{"commands": [...]}`; each element carries `command_id`,
      `node_id`, `runtime_ref`, `kind`, `payload`, `claim_generation` (the `node_id`
      field was added to this doc's shape above — earlier drafts omitted it).
- [x] Poll body is empty/`{}` — no heartbeat or last-known-status payload in v1.
- [x] `PENDING → provisioning` is not a bridge to build — `provision` and `start` are
      always two separate commands. See the resolved status-vocabulary section above.
- [x] `destroy`'s `reported_status` is `stopped` — confirmed, not a placeholder. See
      the resolved status-vocabulary section above.
- [x] Poll and report stay two separate endpoints (not folded into one round-trip).

## Buy vs build

**Decision: build the poll/backoff loop by hand on the standard library. Add no
dependency.**

- **Options considered.** (a) A third-party HTTP client (`resty`, `req`); (b) a retry/
  backoff library (`cenkalti/backoff`, `avast/retry-go`); (c) standard library only.
- **Chosen: (c).** The loop is a `time.Timer` `select`, an `http.Client` with a
  timeout, a `switch` on the HTTP status, and a handful of arithmetic lines for
  capped exponential backoff with jitter. That is well under what a dependency would
  cost to justify.
- **Cost accepted.** We hand-maintain ~a screen of backoff/jitter arithmetic and its
  tests. That is a deliberate, bounded cost.
- **Why the cost is worth it.** Steward's entire value proposition is that a
  sovereign operator with zero trust in any vendor can clone *this repository alone*
  and build it (`go list -m all` lists only this module — see
  [AGENTS.md](https://github.com/hardrails/steward/blob/main/AGENTS.md)). A single third-party dependency, however small,
  breaks that guarantee irreversibly. The convenience a backoff library buys is not
  remotely worth forfeiting the one invariant the repo exists to hold.

This decision is recorded here inline rather than as a separate `docs/adr/NNNN-*.md`
file **on purpose**: this repo records its architectural decisions as prose sections
(see ARCHITECTURE.md's "Deferred decision: computer-use is a separate worker"), and
introducing an ADR directory tree into a deliberately zero-ceremony repo would be the
kind of over-building this very design is meant to resist.

## Task list (ordered, each with its acceptance check)

Layer tags use Steward's own layout: `cmd` (entrypoint/wiring), `runtime` (tracker),
`uplink` (the new client package), `server` (inbound REST), `docs`, `openapi`.

1. **`runtime`: add `RefForInstance`.** A locked read accessor over the existing
   `byID` index. No lifecycle logic, no new state.
   *Check:* a unit test provisions an instance and asserts
   `RefForInstance(id)` returns its `rt_<hex>` ref; an unknown id returns `("", false)`.
   Run with `-race`. Gate: `go test -race ./internal/runtime`.

2. **`uplink`: credential file load.** New `internal/uplink/credential.go` — a
   versioned JSON struct plus a fail-closed loader mirroring `persist.go`'s
   load-and-validate half (missing when enabled, unreadable, bad JSON, wrong
   `version`, empty field ⇒ error naming the path and remedy).
   *Check:* table test covering each corruption mode asserts the error message names
   the path; a valid file loads `(tenant_id, node_id, credential)`. Gate: `go test`.

3. **`uplink`: status mapping + command dispatch.** The `Status → reported_status`
   table and the `CommandKind → tracker method` dispatch, including the `destroy`
   `ErrNotFound → done` rule, the wrong-`node_id` rejection, and a `provision`
   payload's object-shape validation (reusing `isJSONObject`, matching the inbound
   REST handler exactly — see [the resolved review finding](#executing-a-command-against-the-tracker)).
   Depends on 1.
   *Check:* table tests drive each `CommandKind` against an in-memory tracker and
   assert the resulting `reported_status`; a redelivered `destroy` after destroy
   reports `done`; a `start` on an unknown instance reports `failed`; a command for
   a foreign `node_id` is rejected; a `provision` command with a non-object payload
   (a bare scalar or array) is rejected as `failed` and never reaches
   `Tracker.Provision` — proving the uplink path enforces the same instance-spec
   contract the REST handler does. Gate: `go test -race ./internal/uplink`.

4. **`uplink`: the poll loop, backoff, and HTTP.** The `Poller` struct, the
   `time.Timer`/`ctx` select, jitter, the transient/fatal classification, and the
   poll/report round-trips against `*http.Client`. Depends on 2 and 3.
   *Check:* tests use `httptest.Server` to assert: a queued command is executed and
   reported (echoing `command_id` + `claim_generation` verbatim); a `5xx` backs off
   and retries; a `403` logs once and stops the loop; `ctx` cancellation returns
   promptly. Gate: `go test -race ./internal/uplink`.

5. **`cmd`: wire it in.** Parse the three flags/env in `main.go`; when `-uplink-url`
   is set, load the credential fail-closed (exit non-zero on error, like
   `LoadTracker`), start the poll goroutine bound to the existing `signal.NotifyContext`
   `ctx`, and add its `done` channel to the graceful-shutdown block.
   *Check:* `envOr`-style flag/env tests; a manual/integration check that a bad
   credential path exits non-zero with a message naming the path. Gate:
   `go build ./... && go vet ./... && go test -race ./...`.

6. **`docs` + `openapi`: document the mode.** Update ARCHITECTURE.md's "Intentionally
   minimal" section (a new "Outbound uplink is opt-in" subsection in the existing
   style) and the README run/settings table. The inbound `openapi/steward.v1.yaml`
   is **unchanged** — the uplink is an *outbound client*, not a new inbound endpoint,
   so it adds nothing to Steward's published inbound contract (call this out
   explicitly so a reader does not go looking for uplink endpoints in the spec).
   *Check:* `npx @stoplight/spectral-cli lint` still passes (unchanged spec); prose
   review. Gate: `openapi lint` job.

The full battery for the change: `go build ./...`, `go vet ./...`,
`go test -race ./...`, `golangci-lint`, `spectral lint` — the three required CI jobs
in `.github/workflows/ci.yml`.

## Deliberately deferred

In ARCHITECTURE.md's "deferred decision" spirit — named explicitly so they are choices,
not oversights. None of these was designed or built in v1. Two have since been closed
(marked below) as real follow-up work landed; the rest remain deferred.

- **TLS client-certificate auth.** v1 is bearer-credential only. mTLS is a larger
  enrollment/PKI story on both sides.
- **Node-side credential rotation — closed.** v1 read the credential file once at
  startup; rotating a secret required re-enroll + rewrite + restart, and a `403`
  stopped the loop outright with no recovery short of a restart. This is now
  designed and implemented: a fatal `401`/`403` pauses `Run` and watches the
  credential file (content comparison, bounded interval, no busy-loop) until it
  changes to a new, valid credential for this node, then resumes — no restart. See
  [Node-side credential hot-reload](#node-side-credential-hot-reload) above.
- **Multi-control-plane failover.** One `-uplink-url`. No list, no health-based
  failover between control planes.
- **Disabling the inbound listener entirely — closed.** v1 always started the HTTP
  listener (loopback by default) even in "uplink-only" deployments, for local health
  checks. This is now designed and implemented: `-disable-inbound-listener` (env
  `STEWARD_DISABLE_INBOUND_LISTENER`) lets a uplink-only node bind nothing inbound,
  with a fail-closed startup guard refusing the combination without `-uplink-url`.
  See [`docs/disable-inbound-listener.md`]({{ '/disable-inbound-listener/' | relative_url }}) for the full
  design and [ARCHITECTURE.md](https://github.com/hardrails/steward/blob/main/ARCHITECTURE.md#the-inbound-listener-is-opt-out-uplink-only-nodes-bind-nothing-inbound)
  for the summary.
- **A durable outbound report queue.** Not needed: a lost report is recovered by the
  server's claim-lease redelivery + fencing (see [Reporting a result](#reporting-a-result)),
  so the node stays stateless about outbound reports on purpose.
- **Batching reports onto the next poll.** v1 reports each command immediately after
  executing it; folding reports into the next poll's round-trip is an optimization,
  not v1.
- **`instance_id` reuse across a destroy/re-provision cycle is a known, accepted race,
  not silently ignored.** A hosted review of the implementation found it precisely: if
  the SAME `instance_id` on the SAME node is destroyed and then re-provisioned before a
  STALE, already-in-flight lifecycle command from the OLD instance's lineage is finally
  delivered (a long network partition, a redelivery after the claim lease expires), the
  client's `RefForInstance(instanceID)` resolves to the NEW instance — a stale `stop` /
  `hibernate` / `destroy` can mutate or remove the wrong (newly-provisioned) instance.
  **This is a deeper root cause than a client-side bug**: `format_runtime_ref` (the
  control-plane side) is a pure function of
  `(node_id, instance_id)` with no epoch/generation component, and
  control plane may release the `instance_id` for reuse—so the exact same ambiguity
  can exist in its command queue, not just in this client's local lookup. A sound
  fix needs an epoch/generation added to `runtime_ref` itself (or a tombstone on destroy
  that the control plane refuses to re-provision over), which is a protocol change
  out of scope for a client-only v1 patch—a client-side patch alone would give
  false confidence without closing the hole. **Accepted mitigation for v1**: this
  requires (a) a stale command surviving redelivery across (b) an operator or automation
  reusing the exact same `instance_id` after destroying it, on (c) the same node, within
  a narrow timing window — a real but low-probability compound race, not a routine
  path. Operators who want to eliminate it entirely today can simply never reuse a
  destroyed `instance_id` (mint a fresh one per provision). **Follow-up**: add an
  epoch/generation to `runtime_ref` (or an equivalent tombstone-on-destroy) in the
  public protocol.
