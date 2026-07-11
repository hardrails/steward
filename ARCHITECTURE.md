# Architecture

Steward is an on-node supervisor for the lifecycle of agent instances, exposed
over a small HTTP API. This document records the core it always provides,
which capabilities are opt-in versus on by default, what it deliberately does
*not* do, and why the most sensitive future capability is kept at arm's length.

## Separation of concerns

Steward is an independently buildable, control-plane-neutral application. An
independently operated control plane may depend on Steward's public HTTP and
uplink contracts; the dependency never points back the other way. Steward contains
no tenant database, user identity system, approval workflow, rollout scheduler,
private client SDK, or vendor-specific API.

Three runtime boundaries keep higher-risk responsibilities separated:

1. The **control plane** owns enterprise identity, tenant authorization, desired
   state, artifact and skill approval, fleet rollout, and evidence aggregation.
2. The included open-source **Steward Executor** sibling process owns the Docker
   socket and admits untrusted OCI images and workload configuration under Docker
   plus gVisor. It ships from this repository as `steward-executor` but is never
   linked into or hosted inside the `steward` daemon process.
3. An operator-managed **OpenAI-compatible inference gateway** owns model routing
   and inference policy. Steward treats it as outside the lifecycle contract.

The built-in `os/exec` supervisor is therefore a trusted-operator facility, not the
untrusted tenant workload path. Root and non-loopback startup acknowledgements are
defense-in-depth against accidental exposure; neither provides sandboxing. Any
untrusted workload belongs at the separate Executor process boundary.

## A minimal core, with opt-in capabilities layered on top

Every version of Steward provides one always-on core:

- **Lifecycle tracking.** A tracker (`internal/runtime`) maps an opaque
  `runtime_ref` to an instance and its status (`PENDING`, `RUNNING`, `STOPPED`,
  `HIBERNATED`, `DESTROYED`, `FAILED`). The six operations — provision, start,
  stop, hibernate, destroy, status — are transitions over that map, guarded by
  a single mutex. State is held in memory by default; durable state across a
  restart is opt-in (see below).

Layered on that core, several capabilities are available but off by default,
so a minimal deployment stays minimal until an operator deliberately turns
each one on: real process execution (`-enable-process-exec` — see [Process
supervision is opt-in](#process-supervision-is-opt-in)), durable state (`-state-file`), Prometheus
metrics (`-enable-metrics`), a command audit log (`-audit-log-file`), and the
outbound uplink (`-uplink-url`) with its TLS/credential hardening. This
document's "does not do" list below is about permanent, structural boundaries
— things no flag turns on — not about these opt-in capabilities.

The sibling `steward-executor` binary is documented separately in
[`docs/executor.md`](docs/executor.md). It is part of the Steward distribution but
not a capability flag in this daemon: enabling Executor means starting a second
service unit with its own identity, state, listener/uplink, and Docker-socket mount.

The Linux release archive packages those two service identities as a disconnected
node appliance. Versioned binaries live separately from durable state and credentials;
activation swaps only binary symlinks after both target binaries pass non-serving
configuration validation. The installer never owns Docker/gVisor installation,
control-plane deployment, tenant policy, approved OCI images, or inference. See
[`docs/node-appliance.md`](docs/node-appliance.md).

It explicitly does **not**, by default:

- execute commands or run workloads — real process supervision is **opt-in**
  (`-enable-process-exec`, off by default; see below). With it off, every
  lifecycle operation is a pure status transition, exactly as it always was.
- sandbox or isolate anything (this holds even with process execution on — see
  the process-supervision section's stated limits),
- perform computer-use or any other agent capability (a separate, still-deferred
  concept — see the deferred-decision section, and do not conflate it with the
  process supervision below),
- authenticate, terminate TLS, or emit distributed traces,
- emit metrics or a command audit log — both are opt-in (see below); nothing is
  exposed or written until an operator deliberately turns it on.

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
  Because the credential is a bearer secret, its file must additionally be owner-only
  (`0600` or stricter): a file readable or writable by group or others is refused
  fail-closed — at startup, under `-check-config`, and on the credential hot-reload
  watch — with a message naming the path and the `chmod 600` fix. The check is on the
  mode bits, so it holds even when Steward runs as root. The inbound REST API remains
  unauthenticated by design, as above.
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
- **Its outbound transport is hardened the same fail-closed, standard-library-only
  way.** The HTTP client's TLS is operator-configurable (`-uplink-tls-ca-file` for a
  custom/private control-plane CA, `-uplink-tls-client-cert`/`-uplink-tls-client-key`
  for mTLS, and the insecure, loudly-warned `-uplink-tls-skip-verify` escape hatch),
  built with only `crypto/tls` — no new dependency — and validated fail-closed at
  startup and under `-check-config`, so a bad CA/cert/key is a startup error, never a
  silent fall back to system defaults. The client private key gets the same
  owner-only (`0600`) permission gate the credential does, since it is an equivalent
  node-authenticating secret. Every poll/report body the client reads or
  writes is bounded at the same 1 MiB the inbound REST API caps a request body to: a
  poll response over the cap is a clean, logged rejection (this cycle is dropped and
  retried next, never an unbounded read), and a report body over the cap is refused
  before it is sent (the server redelivers via its claim lease). The outbound channel
  gets the same request-size and validation discipline the inbound one already has.

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

### Uplink commands are bounded and deduplicated (backpressure)

The uplink poll loop does not execute a poll's commands inline. It puts a **bounded,
in-memory queue** (`internal/uplink.commandQueue`) between "commands received from a
poll" and "commands executed": the poll loop is the producer, and a single background
consumer drains and executes the queue. This decoupling is what makes two properties
possible that an execute-every-command-inline loop cannot give — and both close a real
gap for a node whose control plane can queue work faster than the node executes it.

- **Bounded in-flight work, with a redelivery-safe overflow.** At most
  `-uplink-command-queue-depth` commands are ever queued-plus-in-flight (default
  `256`, validated positive at startup and under `-check-config`). A poll cycle whose
  commands would exceed the cap has its **excess rejected, never silently dropped**:
  each rejected command is logged at `WARN` under the grep-able
  `uplink command queue full:` prefix (the same operator convention as
  `sighup reload:`), named by `command_id` and `runtime_ref`. A rejected command is
  never reported, so the server's existing poll/report claim-lease machinery
  redelivers it on a later cycle once the backlog drains — the node commits to no more
  than it can hold, and loses nothing. This is the same "circuit breaker on growth,
  not an outage" posture `maxInstances` takes for the inbound path, applied to the
  outbound command stream. The consumer draining the whole queue at once preserves each
  poll batch's own ordering — the replace/retry semantics `executeBatch` depends on —
  while the cap still bounds the batch's size.
- **Deduplication across poll cycles.** A command whose `command_id` is already queued
  or in-flight is skipped rather than executed a second time, so a command redelivered
  while its first copy is still pending (a report lost in transit, a claim-lease
  reclaim) is not re-executed. `command_id` is the protocol's own unique command
  identity, and it is exactly what the server preserves across a redelivery (the claim
  lease bumps `claim_generation`, not `command_id`), so it is the correct dedup key —
  not a new one this client invents. Because the tracker's operations are already
  idempotent in effect (a redelivered `provision` returns the existing instance, a
  redelivered `destroy` after destroy reports done), this dedup is a **work-saving
  guard**, not a correctness fix: it avoids redundant tracker mutations and, when
  `-state-file` is set, redundant disk writes. An empty `command_id` (out-of-contract)
  is never deduplicated, so distinct empty-id commands are not collapsed onto one key.
- **A persistently-full queue factors into readiness.** A node that keeps rejecting a
  backlog for several consecutive poll cycles is, by definition, not keeping up — so
  the `GET /v1/readiness` gate reports it not-ready (naming the backlog), and a load
  balancer or orchestrator stops routing it new work until it catches up. This is a
  distinct gate checked *before* the poll-success gate, so it can drain a node that is
  reaching its control plane fine but cannot execute fast enough. A single momentary
  over-full poll never flips readiness (no flapping); the node returns to ready on its
  first clean poll cycle. On a `-disable-inbound-listener` (uplink-only) node there is
  no `/v1/readiness` endpoint, so the signal there is the same advancing poll logs plus
  the `steward_uplink_command_queue_depth` / `steward_uplink_commands_rejected_total`
  metrics.

Like the generation fence and the credential hot-reload, this is additive
outbound-client behavior: it adds no inbound endpoint, request/response shape, or status
code, so `openapi/steward.v1.yaml` is unchanged except for the (opt-in) `/metrics`
prose that enumerates the new series. The design provenance lives in
[`docs/uplink-client.md`](docs/uplink-client.md#command-backpressure-and-deduplication).

Those are out of scope on purpose. Steward is meant to be small enough to read in
one sitting and to audit against its published contract
(`openapi/steward.v1.yaml`).

### Metrics and the command audit log are opt-in

Two observability surfaces exist, both off unless an operator turns them on, and
both built with only the standard library — neither pulls in
`prometheus/client_golang` or any other dependency, per the zero-dependency
invariant above.

- **`GET /metrics`** (`-enable-metrics` / `STEWARD_ENABLE_METRICS`, default off)
  renders the tracker's live instance counts (by status) and capacity cap, plus —
  when the outbound uplink is also enabled — its poll latency (min/max/last),
  poll count, command success/failure counters, and current backoff, in the
  [Prometheus text exposition
  format](https://github.com/prometheus/docs/blob/main/content/docs/instrumenting/exposition_formats.md)
  (`# HELP`/`# TYPE` comments and `metric_name{labels} value` lines — simple
  enough that a handful of `fmt.Fprintf` calls suffice). It is registered on the
  **same** `http.ServeMux` and reachable only through the **same** inbound
  listener every other endpoint uses (see `internal/server.Server.Handler`): there
  is no second listener, so it automatically inherits `-disable-inbound-listener`
  (no listener bound at all means no `/metrics`, the same as every other route)
  and the per-source rate limiter. Disabled (the default), the route is never
  registered and the path 404s exactly like any other unrouted path.
- **`-audit-log-file`** (env `STEWARD_AUDIT_LOG_FILE`, unset by default) appends
  one JSON-lines record — timestamp, `command_id`, `instance_id`, `kind`,
  `status` (`"success"`/`"failure"`), and an `error` detail on failure — for
  every **uplink** command Steward executes to a terminal (reported) outcome.
  It covers the outbound uplink dispatcher specifically (`internal/uplink`),
  which is where a queued lifecycle command is a first-class object with its own
  `command_id`; the direct inbound REST API has no such identifier to record. The
  file is opened once (created if missing) and appended to for the process's
  life: each record is one `os.File.Write` call under a mutex — POSIX guarantees
  a single `O_APPEND` write is atomic against any other writer to the same file
  — which gives the same "never a torn/corrupt record" property `-state-file`'s
  temp-file-then-rename gives a rewritten-in-full snapshot, via a mechanism suited
  to a log that only ever grows by appending. Opening the file fails closed at
  startup (a bad path names the fix, the same discipline every other file this
  project opens uses); a write failure at runtime is logged at `WARN` and
  otherwise ignored, since the audit log is a best-effort trail, never a source
  of truth a command's real outcome depends on.

### Failure classes are named, not generic

Every error response carries a stable `error` code drawn from one small, closed
taxonomy defined in exactly one place (`internal/server`'s error-code constants)
and projected into the `Error.error` enum of `openapi/steward.v1.yaml` — the two
halves of one contract, kept from drifting. The codes name distinct real failure
classes: `invalid_request` (a malformed request envelope or missing field),
`invalid_spec` (a present but non-object instance `spec` — the malformed-config
class, split out from the generic request error), `unknown_runtime_ref`,
`invalid_state_transition` (see below), `capacity_exceeded`, `request_too_large`,
`rate_limited`, `not_found`, `method_not_allowed`, and `internal_error`. Each
code travels with a fixed HTTP status; a consumer branches on the status (or the
code), never on the human-facing `message`. The set is additive over the prior
generic codes — the one behavior change is that a non-object `spec`, formerly
`invalid_request`, is now the more specific `invalid_spec` (still a `400`, so a
status-based client is unaffected).

### Readiness is distinct from liveness

`GET /v1/healthz` answers "is the process up?"; the separate `GET /v1/readiness`
answers "should traffic go to this instance *right now*?" — the question a
rolling deploy or load balancer must ask. It returns `200` only when three gates
pass, and `503` naming the first failing one otherwise: the instance tracker is
initialized; the outbound uplink (when enabled) has completed at least one
successful poll **or** is not in a persistent-failure state (a rejected
credential, or sustained polling failure with no success yet — a brief blip does
not flip readiness, and one success keeps a node ready across a later blip); and
durable state (when enabled) is writable. That last gate is the deliberate
inversion of `healthz`'s posture: liveness refuses to touch the state file (a hot
path, and a redundant guarantee), but readiness *does* probe writability, because
a state directory gone read-only or full is exactly the degraded-but-alive
condition a readiness gate exists to drain. The probe creates and removes a
uniquely-prefixed temp file, so it never races the atomic-rename persistence
writes. Like `healthz` it lives only on the inbound listener; an uplink-only node
signals readiness through its advancing poll logs, the same way it signals
liveness.

### Provisioning is idempotent by design, and transitions are validated

`Provision` keys on the caller-supplied `instance_id`. If an instance with that
id is already tracked, the existing `runtime_ref` and status are returned
unchanged rather than creating a second instance.

The three lifecycle transitions (`start`/`stop`/`hibernate`) are validated
against the instance's current status by a small allowed-transitions table,
rather than mutating unconditionally. Two rules define it. First, a
self-transition is always an idempotent no-op success — starting an
already-`RUNNING` instance returns it unchanged — because that is the property a
redelivered (report-lost) uplink command and a retried batch both depend on: the
double-invoke covenant would break if the second call reported a spurious
failure. Second, `stop`/`hibernate` are refused from `PENDING` (a `409
invalid_state_transition`, instance left unchanged) — a never-started instance
has nothing to stop or hibernate, so silently recording `STOPPED`/`HIBERNATED`
would be a nonsensical state, not a transition. Every other move among the live
statuses stays valid: Steward mirrors the control plane's state machine, it does
not impose a stricter one. `destroy` is always allowed on a live instance and is
not routed through the table. This is the safety net for a
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

### Listing supports filtering, and instances carry `created_at`

`GET /v1/instances` accepts three optional query-string filters —
`status`, `instance_id_prefix`, and `created_since` — that compose via AND
when combined. This rides `runtime.Tracker.ListFiltered`, a filtered sibling
of the existing `List()` (which is unchanged and still backs the no-filter
case, so omitting all three query params is byte-for-byte the same response
this endpoint always returned). `created_since` filters on a new
`created_at` field on every tracked `Instance`, set once by `Provision` when
a *new* instance is created and never changed again — including across an
idempotent re-provision of the same still-live `instance_id`, which returns
the original `created_at` unchanged. `created_at` therefore now appears on
every `Instance` in every response (it has no `omitempty`, because
`encoding/json`'s `omitempty` never omits a struct-typed field regardless of
value — unlike `Generation`'s `int64`, a zero `time.Time` is not "empty" to
the encoder). An instance loaded from a state file written before this field
existed simply has no `created_at` key and decodes to the zero time, which
never matches a real (non-zero) `created_since` filter — the same
additive, no-format-version-bump discipline `Generation` established (see
[`docs/instance-generation-fencing.md`](docs/instance-generation-fencing.md)),
adapted to a field whose zero value can't be made to disappear from the wire.

### Batch operations execute sequentially, are not a transaction, and reuse existing idempotency

`POST /v1/instances/batch` executes an ordered list of `provision`/`start`/
`stop`/`destroy` operations against the tracker, one at a time, in exactly
the order given, and reports one result per operation. Each operation is
dispatched through the *exact same* tracker call its single-instance
endpoint already uses (`Tracker.Provision`, `.Start`, `.Stop`, `.Destroy`) —
the batch handler adds no parallel logic of its own, so a batched operation
keeps precisely the request/response shape and idempotency behavior its
single-op endpoint already has, rather than a second, possibly-diverging
implementation.

It is deliberately **not** a transaction: operations are not rolled back on
a later failure, and because they run strictly in request order against the
live tracker (never pre-validated or executed out of order), a later
operation observes an earlier one's effect within the same batch — for
example, destroying an `instance_id` and re-provisioning it in one batch
works, because the destroy has already released the `instance_id` by the
time the provision runs. A failure on one operation never blocks its
siblings: the response's `results` array reports every operation's own
outcome at its own index, so partial success (operation 3 of 5 failing while
1, 2, 4, and 5 succeed) is always visible per-operation, never silently
swallowed and never an all-or-nothing rollback.

Retrying a whole batch (the case a client-side timeout leaves genuinely
ambiguous — did the server finish before or after the connection dropped?)
is safe exactly to the extent each constituent operation's own single-op
endpoint already is: `provision` stays idempotent on `instance_id` because it
calls the same `Tracker.Provision` the single-instance endpoint does, and
`start`/`stop` converge on the same terminal status either way. `destroy` is
the one exception, and it is an existing property of `Tracker.Destroy`, not
something batching makes worse: destroying releases the `runtime_ref`
(see [Provisioning is idempotent by design](#provisioning-is-idempotent-by-design)
and the `Destroy` doc comment in `internal/runtime/runtime.go`), so replaying
a batch that already destroyed an instance gets a `404 unknown_runtime_ref`
on that operation the second time — the same outcome a repeated
`DELETE /v1/instances/{id}` retry would give.

The design provenance — the request/response shape decisions, the
transaction-vs-not tradeoff, and the idempotency analysis per operation kind
— lives in [`docs/batch-instance-operations.md`](docs/batch-instance-operations.md).

## Process supervision is opt-in

By default Steward tracks lifecycle *status* and spawns nothing. With
`-enable-process-exec` (or `STEWARD_ENABLE_PROCESS_EXEC`, or `enable_process_exec`
in the config file) turned on, it becomes a real, `os/exec`-level process
supervisor for instances whose `spec` carries a `command` — in the same class as
systemd or supervisord, and deliberately *not* the sandboxed computer-use worker
below.

### The opt-in gate is two conditions, and it is backward-compatible by design

`spec` has always been an opaque, forwards-compatible blob that existing callers
fill with arbitrary config (`{"owner":"a"}`) never meant to be a process spec.
Making execution mandatory would break all of them, so real execution requires
**both**:

1. Steward started with `-enable-process-exec` (default **off**), and
2. the per-instance `spec` containing a `command` field (a JSON string).

The **presence of `command`** is the trigger. When execution is off, provisioning a
`command`-bearing spec is **rejected** with `400 process_exec_disabled` — a
caller's real intent to run a process is failed loudly, never silently stored and
ignored. When execution is on but `command` is absent, behavior is byte-for-byte
what it always was: a pure status transition, no process. So an existing opaque
caller is unaffected in either mode, and only a spec that explicitly asks for a
process ever gets one.

The interpreted spec fields (every other key stays ignored, `additionalProperties`
holds): `command` (string, the executable — its presence is the trigger), `args`
(string array), `env` (a name→value object), and `working_dir` (string). `env` is
a map rather than a `KEY=VALUE` list because that is the natural JSON shape and
frees callers from pre-formatting; Steward converts it to the `[]string` `exec.Cmd`
wants. A malformed process spec (a non-string/empty `command`, a wrong-typed
`args`/`env`/`working_dir`) is rejected with `400 invalid_spec` at provision time —
failing early, not at first start.

### Security posture

Deliberate choices, not afterthoughts — plus one caveat an operator **must** act on:

- **The child runs with Steward's own user and privileges.** A spawned process
  inherits Steward's UID, GID, and privileges; Steward drops **no** privileges (no
  `setuid`/`setgid`, no `SysProcAttr` credential change) and applies no sandbox. **If
  Steward runs as root, spawned commands run as root.** Run Steward as an unprivileged,
  dedicated user — never root — so an operator-configured command cannot act with more
  authority than intended. This is also why the identity-verified reattachment above is
  a safety property and not merely a correctness one: a root Steward that mis-reattached
  a reused pid would SIGKILL an arbitrary root-owned host process, and the start-time
  witness closes exactly that door.
- **No shell, ever.** Steward runs `exec.Command(command, args...)` directly. There
  is no `sh -c`, so shell metacharacters in a caller-supplied arg cannot cause
  injection.
- **No environment inheritance.** The child does **not** inherit Steward's own
  environment, which may hold the uplink credential, TLS key paths, and other
  secrets. Its environment is a minimal base of only `PATH` (copied from Steward so
  the child and its subprocesses can still find executables) plus exactly the
  variables in `spec.env`, which take precedence. The child's env is always an
  explicit, non-nil set, so `exec.Cmd` never silently falls back to inheriting the
  parent environment.
- **Everything is logged.** Every start, stop, hibernate, resume, unexpected exit,
  and restart reattachment is a structured log line on Steward's own JSON logger
  (the same stream an operator already captures), with a distinct message and
  fields (`runtime_ref`, `instance_id`, `pid`, `exit_code`, `reason`). An unexpected
  exit is logged at WARN with an explicit "UNEXPECTEDLY" marker so a crash is
  distinguishable from a requested stop even though both land on `STOPPED`. We
  deliberately did **not** add a separate process-audit-log *file*: the existing
  `-audit-log-file` is uplink-command-specific and lives in a package `internal/
  runtime` cannot import without a cycle, and process events already flow through the
  same structured logger — a second sink would duplicate that trail for marginal
  benefit. A dedicated file is an easy, non-breaking follow-up if an operator wants
  one.

### Lifecycle semantics (only when execution is on and `command` is present)

- **Provision** is unchanged: it stores the spec, `PENDING`, no process yet.
- **Start** from `PENDING`/`STOPPED` spawns a fresh process and a monitor goroutine
  that `Wait()`s on it. If the spawn itself fails (executable not found, permission
  denied, missing `working_dir`) the call returns `400 process_start_failed` and the
  instance is left in its prior status — never a false `RUNNING`.
- **Start** on an already-`RUNNING` instance with a live tracked process is an
  idempotent no-op — it does **not** spawn a duplicate (the same redelivery-safety
  guarantee the status state machine already makes).
- **Start** from `HIBERNATED` sends **SIGCONT** to resume the *existing* suspended
  process, preserving its in-memory state, rather than spawning anew. If the handle
  was lost (a restart could not reattach), it falls back to a fresh spawn and logs
  the discontinuity.
- **Stop** sends SIGTERM, waits up to `-process-stop-grace-period` (default 10s),
  then escalates to SIGKILL if still alive, and transitions to `STOPPED` once the
  process is confirmed dead. The grace wait runs **without** the tracker lock, so
  stopping one instance never freezes the whole tracker.
- **Hibernate** sends **SIGSTOP** to suspend (not kill) the process, so Start can
  later resume it.
- **Destroy** terminates any tracked process (SIGTERM→SIGKILL) and removes tracking,
  regardless of status.
- **Unexpected exit.** When the monitor sees a process exit that Steward did not
  request, the instance transitions to **`STOPPED`, never `FAILED`** — Steward must
  never emit `FAILED` (that status is reserved for the control plane, which sets it
  when it cannot reach Steward at all). Because `STOPPED` cannot itself distinguish a
  crash from a requested stop, the additive `last_exit_code`/`last_exit_reason`
  fields on the instance record it: `crashed` for an unexpected exit, `stopped`/
  `killed` for a graceful/forced stop, `supervision_lost` for a process gone across a
  restart.

### Restart reattachment is best-effort, identity-verified, and honestly limited

An OS process handle — its `*os.Process`, its monitor goroutine, its stdout/stderr
pipes — **cannot** be persisted or truly reattached across a Steward restart. We do
not pretend otherwise. The child's `pid` is persisted together with a **start-time
identity witness** (`proc_start_token`) captured immediately after spawn (both
additive, non-breaking state-file fields, like `created_at`/`generation` before them).
On reload with execution enabled, for each instance recorded `RUNNING`/`HIBERNATED`
with a `command` spec, Steward first probes the stored pid's liveness (`signal 0`) and
then re-verifies its **identity** — because a live pid alone is **not** proof the
original child is still there:

- **pid gone** → the process did not survive; the instance is transitioned to
  `STOPPED` with `last_exit_reason = supervision_lost`, logged clearly.
- **pid alive but not provably ours** → the OS reuses pids, so an unrelated process (a
  cron job, a database, `sshd`) may now hold that exact pid. Steward re-reads the pid's
  current start time and compares it to the recorded witness; if they differ — or the
  witness is missing or unreadable — it **fails closed**: the instance is transitioned
  to `STOPPED` (`supervision_lost`) and Steward **never signals that pid**. This is
  precisely what stops a later Stop/Destroy/Hibernate from sending
  SIGTERM/SIGKILL/SIGSTOP to a stranger's reused pid.
- **pid alive and identity confirmed** (the child was reparented to init when Steward
  exited, and its start time still matches the witness) → Steward **reattaches in a
  deliberately degraded, liveness-only mode**: it regains the ability to
  stop/hibernate/resume the process by pid, but it has **not** regained the process's
  stdout/stderr (those file descriptors are gone forever) and cannot `Wait()`/reap it
  or proactively detect a future crash. A reattached instance keeps its status and is
  logged loudly as `DEGRADED`. This is a real, permanent limitation of process
  reattachment, stated plainly rather than glossed over.

The witness is the process start time, read via `ps -o lstart=` — one portable path
across Steward's Linux and macOS targets, with no dependency. Its granularity is one
second (coarser than the kernel's boot-tick resolution), but the check only ever fails
**closed**: a coarse witness can cause a conservative `supervision_lost`, never a false
reattach onto the wrong process.

### Known gap: no resource limits or sandboxing

This pass is `os/exec`-level process supervision only. There are **no** resource
limits (cgroups/ulimits), **no** sandboxing, and **no** isolation of a child's
grandchildren — matching what a systemd/supervisord-style tool does at its base
layer, and matching the existing documented deferrals for durable state and
computer-use. Resource limits and sandboxing are an explicit, named future decision,
not a silent omission. Neither `command` nor `working_dir` is validated against an
allowlist: `command` is any executable, and `working_dir` may point anywhere the
Steward process's user can access — both are trusted, operator-configured inputs (the
same posture as a systemd unit's `ExecStart` and `WorkingDirectory`), which is the
other reason to run Steward as an unprivileged, dedicated user. Platform note: process
supervision uses Unix signals and is
supported on Linux and macOS (Steward's CI and deployment targets); a Windows build
of the supervisor is out of scope.

## Deferred decision: computer-use is a separate worker, never in-process

Steward will eventually need to offer a computer-use capability. This is **distinct
from the `os/exec` process supervision above** — that runs an arbitrary
operator-configured command with no sandbox; computer-use is the specific,
highest-risk agent capability and gets a stronger isolation boundary. The decision
for this repository is that computer-use will be a **separate, optional,
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
                    opt-in durable state via a JSON state file); exec.go adds the
                    opt-in real process supervision (spawn/signal/monitor)
internal/server/    HTTP handlers wiring the operations to REST endpoints,
                    plus the opt-in /metrics endpoint
internal/uplink/    Outbound uplink poll loop, command dispatch, and the
                    opt-in command audit log
openapi/            Hand-written public API contract (the audit surface)
```
