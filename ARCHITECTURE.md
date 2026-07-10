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

Persistence is a server-side deployment concern. The only place the HTTP contract
reflects it is the boolean `durable_state` field of `GET /v1/capabilities`, which
reports *whether* persistence is enabled — never the file path. It otherwise adds
no endpoint and leaves every instance request/response shape and status code in
`openapi/steward.v1.yaml` unchanged.

### `max_instances` hot-reloads on `SIGHUP`, and lowering it never evicts

The `max_instances` cap can be retuned on a running node without a restart:
`SIGHUP` re-reads the `-config` file and applies a new `max_instances` in place.
Two design decisions define what that reload does — and, more importantly, what it
deliberately does *not* do.

- **Lowering the cap does not evict.** A `SIGHUP` that lowers `max_instances` below
  the current instance count stops the tracker growing further; it does **not**
  stop, destroy, or otherwise touch any already-tracked instance. This is the exact
  same posture the state-file loader already takes when it reads a file holding more
  instances than its cap: *"`maxInstances` is a DoS circuit-breaker on growth, not
  on reload … honored in full rather than silently truncated, and new provisions
  stay blocked until the count drops back under the cap"* (`internal/runtime/persist.go`).
  The cap is enforced in exactly one place — `Provision`'s
  `len(byRef) >= maxInstances` check, which only fires when creating a *new*
  instance — so a lowered cap naturally blocks new provisions (`503`) and lets the
  count drain back under the ceiling through ordinary `Destroy` attrition. There is
  no eviction path anywhere in the package, by design: a capacity re-tune is an
  operator tuning a knob, and it must never silently turn into an outage by
  reaching in and killing live instances. Applying the new house rule to a new
  mechanism, not inventing a second, harsher one for the live path.
- **Only `max_instances` reloads — scope is the safety boundary.** `SIGHUP`
  reloads `max_instances` and nothing else. Every other setting is a much larger,
  riskier live-reconfiguration surface: rebinding `-addr` means tearing down and
  rebuilding the listener under in-flight requests; changing `-uplink-url` or the
  credential means re-dialing a control plane mid-poll; swapping `-state-file` means
  moving durable state out from under active mutations. `max_instances` is uniquely
  safe to reload because it is a single in-memory integer — it is not even part of
  the persisted state snapshot — so applying it touches no listener, no socket, and
  no file. The narrow scope is the point, not a limitation: it keeps a live reload
  to the one setting that can change with zero blast radius. Broader live
  reconfiguration, if ever wanted, is a separate, deliberate decision, not a default
  smuggled in behind a signal handler.

Like every other Steward setting, the reload obeys the startup precedence model
(flag > env > file): a `max_instances` pinned by `-max-instances` or
`STEWARD_MAX_INSTANCES` at startup still wins over the file on the live path too,
rather than the reload inventing a different rule. `SIGHUP` never triggers
shutdown (only `SIGINT`/`SIGTERM` do), a missing `-config` file makes it a
documented no-op, and an unreadable or invalid file leaves the live cap unchanged —
every outcome is logged, never silent. It adds no endpoint or contract change:
`GET /v1/capabilities` already reads `max_instances` live, so it simply reflects
the updated value after a reload.

### Outbound uplink is opt-in

By default Steward is reachable only through its inbound REST API, which assumes the
control plane can dial *into* the node. That fails when the node sits behind NAT or a
firewall that blocks inbound connections. The opt-in **outbound uplink** inverts who
dials whom: instead of being dialed, the node makes an outbound-only HTTP connection
*out* to the control plane, polls for queued lifecycle commands, executes them, and
reports the results back. Outbound connections are what NAT and stateful firewalls
allow by default, so this channel reaches the node from exactly the places the
inbound API cannot.

The uplink is off unless the operator sets `-uplink-url` (or `STEWARD_UPLINK_URL`);
its presence is the opt-in switch, exactly as `-state-file`'s presence enables
durable state. When it is set:

- **It is a second caller of the same tracker, not a second lifecycle engine.** The
  poll loop drives the same `internal/runtime` operations — provision, start, stop,
  hibernate, destroy — that the inbound handlers call, behind the same single mutex.
  A node may run inbound-REST-only, uplink-only, or both at once; "both" needs no
  conflict resolution because both are just callers of one idempotent, mutex-guarded
  state machine, sharing one durable file when `-state-file` is set.
- **It authenticates the node *to* the control plane, outbound — it does not add
  inbound authentication.** The node presents a bearer credential (tenant, node,
  secret), minted by the control-plane operator at enrollment and persisted locally
  as a small, versioned JSON file, using only `encoding/json` and `os` — the same
  standard-library-only posture as durable state, and no new dependency. When the
  uplink is enabled the credential is loaded **fail-closed** at startup: a missing or
  corrupt credential file is a startup error naming the path and the fix, never a
  silent disable — the same discipline `LoadTracker` applies to a corrupt state file.
  The inbound REST API remains unauthenticated by design, as above.
- **It adds nothing to the published inbound contract.** The uplink is an outbound
  *client*, so it introduces no new endpoint, request/response shape, or status code;
  `openapi/steward.v1.yaml` is unchanged. A poll failure is classified transient
  (network blip, `5xx` — bounded backoff, keep retrying) or fatal (`401`/`403`, a
  bad or revoked credential — a loud, actionable log), with no third-party retry or
  backoff library: the bounded-backoff loop is hand-written on the standard library.
  A fatal rejection no longer stops the loop outright: it pauses and watches the
  credential file (content comparison, bounded interval, never a busy loop) until an
  operator drops a valid new credential, then resumes with no process restart —
  node-side credential hot-reload, detailed in
  [`docs/uplink-client.md`](docs/uplink-client.md#node-side-credential-hot-reload).

The design provenance — the shape chosen, the shapes rejected, the invariants, and
the (provisional) wire contract still being reconciled with the control-plane side —
lives in [`docs/uplink-client.md`](docs/uplink-client.md).

### The inbound listener is opt-out (uplink-only nodes bind nothing inbound)

A node with the uplink enabled has two independent front doors onto one tracker: the
inbound REST listener (dialed *into*) and the outbound uplink (dialing *out*). A node
whose reason for using the uplink is that inbound connections are impossible — behind
NAT or a firewall — has no use for the inbound listener at all, yet by default it
still binds one (loopback). `-disable-inbound-listener` (env
`STEWARD_DISABLE_INBOUND_LISTENER`) lets such a node **bind nothing inbound**: the
`http.Server` is not built, and all fleet operations flow through the uplink poll
loop only. This is safe because the uplink is already a second *in-process* caller of
the tracker, not an HTTP client of the local listener — removing the inbound door
does not touch the outbound one.

- **It is opt-out, so today's behavior is the default.** With the flag unset the
  listener binds `-addr` exactly as before, whether or not the uplink is also on. Only
  an explicit `-disable-inbound-listener` removes it. This mirrors how every other
  Steward setting defaults to today's behavior.
- **A node is never left unreachable.** Disabling the listener *without* an uplink
  would leave a node that can neither be dialed nor dial out — a dark, useless
  process. That combination is a **fail-closed startup error** naming the
  contradiction and both fixes, never a silent launch — the same discipline the uplink
  credential and `-uplink-poll-interval` checks already apply. The startup rule reduces
  to one line: a node must open at least one door (inbound, outbound, or both); only
  "neither" is refused.
- **It changes nothing on the published contract.** The flag adds no endpoint,
  request/response shape, or status code, so `openapi/steward.v1.yaml` is unchanged;
  which front doors a node opens is a deployment-mode concern, exactly as durable state
  is. A uplink-only node has no local `GET /v1/healthz`; its liveness signal is the
  process being up and its uplink poll logs advancing (a fatal `401`/`403` pauses and
  watches the credential file loudly, rather than exiting — see credential
  hot-reload above), which is the model a co-located supervisor already uses —
  nothing external can reach a loopback probe on a NAT'd node anyway. An operator
  who wants a local HTTP health probe simply leaves the listener on (the default).

The design provenance — the flag-vs-`-addr` decision, the interaction rules, the
health/readiness answer, and the task list — lives in
[`docs/disable-inbound-listener.md`](docs/disable-inbound-listener.md).

### Uplink commands are generation-fenced

Because `Destroy` releases an `instance_id` for reuse, two different instances can
share one `instance_id` across a destroy boundary — so a stale, redelivered
lifecycle command from a destroyed instance's lineage could act on the *wrong*,
newly re-provisioned instance. Steward closes that race by **fencing on a generation
token**: each tracked instance records the `generation` of the lineage it belongs to,
the control plane stamps every queued command with the `instance_generation` it is
addressed to, and the uplink **drops any command whose generation is older than the
one the node currently tracks** for that `instance_id`. A fresh `provision` carries —
and the tracker adopts, atomically with the provision — the new generation, so
everything from the superseded lineage is fenced thereafter.

- **It rides the existing durable state, not a new file.** The generation is one
  additive `generation` field on the persisted instance record, so it survives a
  restart through `-state-file` exactly as the rest of the tracked state does; the
  state-file format version is unchanged (the field's zero value is the safe "no
  fencing" default).
- **A fenced command is a no-op, not a failure.** Steward drops it silently — it logs
  the drop but sends no report — because a superseded command is an expected
  consequence of at-least-once delivery, not an operator-visible failure, and a
  fabricated success report could corrupt the live instance's control-plane state.
- **It is additive and dormant until the control plane sends it.** A command with an
  absent or zero `instance_generation` is never fenced, so this changes nothing about
  the inbound REST path, the published `openapi/steward.v1.yaml` contract (unchanged —
  this is outbound-client behavior), or a Steward talking to a control plane that does
  not yet send the field. It requires no synchronized upgrade.

The design provenance — the persistence choice, the fence rule, the silent-drop
semantics, the first-seen bootstrap, and the rollout compatibility matrix — lives in
[`docs/instance-generation-fencing.md`](docs/instance-generation-fencing.md).

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

Until that worker exists, the `skills` array of `GET /v1/capabilities` stays
empty and Steward does nothing related to skills or computer-use. That endpoint
does additionally report read-only operational state for a control plane's
dashboard — `version`, the current `instance_count`, the configured
`max_instances` cap, and a `durable_state` boolean — but that is pure
introspection over the tracker's existing state, not a new capability or any
step toward in-process computer-use.

## Layout

```
cmd/steward/        HTTP server entrypoint (flags/env, graceful shutdown)
internal/runtime/   Instance tracker and lifecycle operations (in-memory, with
                    opt-in durable state via a JSON state file)
internal/server/    HTTP handlers wiring the operations to REST endpoints
openapi/            Hand-written public API contract (the audit surface)
```
