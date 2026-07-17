# Architecture

Steward is open-source software for coordinating and running isolated agent
instances. The optional `steward-control` service coordinates a fleet. Independently
installable node services enforce lifecycle, untrusted-container, and restricted
network boundaries. This document defines those boundaries, the features that
require explicit configuration, and the risks that remain outside Steward's
control.

## Separation of concerns

Steward is independently buildable and ships a replaceable open-source control
plane. Nodes use only Steward's public HTTP and uplink contracts; they never call a
private API or import a private package. The bundled controller contains a bounded
tenant registry, node enrollment, inventory, and signed-command delivery state. It
does not contain an enterprise identity system, approval workflow, rollout
scheduler, private client SDK, or vendor-specific API.

Five runtime boundaries separate authority:

1. The optional **Steward Control** service owns tenant records, scoped operator
   and node transport credentials, one-time enrollment, bounded inventory, opaque
   signed-command retention, delivery leases, and reported outcomes. It has no
   Docker socket, tenant private signing key, shell runner, or agent runtime. An
   embedded React console projects read-only summary, attention, node, command,
   and credential metadata through the same operator-authenticated API. It adds no
   mutation, approval, secret-retrieval, or signing path. An
   organization may place enterprise identity, approvals, desired state, artifact
   and skill approval, scheduling, rollout, and evidence aggregation above its
   public API.
2. The **Steward supervisor** owns the generic lifecycle and status contract, plus
   its control-plane uplink. It has no Docker authority.
3. The open-source **Steward Executor** is a separate process that owns the Docker
   socket. It admits untrusted Open Container Initiative (OCI) images and workload
   configuration into Docker under gVisor. gVisor is an application-kernel sandbox
   that adds a boundary between the container and the host kernel. Executor ships
   as `steward-executor`; it is never linked into or hosted by `steward`.
4. **Steward Gateway and the per-instance relay** enforce finite inference,
   service, exact credential-brokered connector, and named HTTP(S) egress grants.
   They do not give an agent a raw host or Internet route. Gateway has its own
   service identity and no Docker authority. In Authorized Effects mode, signed
   tenant policy pins off-node action keys and an approval threshold to selected
   connectors, generic egress is unavailable, and Gateway accepts only a complete
   version-2 or multi-party version-3 permit for one exact request. It durably spends the permit before DNS while the upstream credential
   remains outside the workload. A separate service-scoped
   tenant task authority can sign one exact agent-service request. Current service
   tasks record task-local authorization, dispatch, and terminal lifecycle evidence.
   Gateway can read credentials that OpenBao Agent or another trusted materializer
   places in owner-only files; agents receive only the mediated capability, never
   the materialization directory or reusable value.
5. An operator-managed **OpenAI-compatible inference system** owns model routing
   and inference policy. It is outside Steward's lifecycle contract.

Two additional binaries are operator interfaces, not long-running service
boundaries. Most `stewardctl` operations are offline: they manage Ed25519 keys,
signed profile capsules, site policies, exact-request action permits, OCI archives,
and receipt chains.
`sudo stewardctl image import` is the deliberate exception; after verification and
sanitization, that one-shot command connects directly to Docker to load the image.
`steward-mcp` is a stdio adapter over the bounded Steward Control API, the
host-local Executor API, or both. When explicitly configured, it also exposes the
loopback Gateway task-lifecycle API. It has no Docker authority. Its task tools
accept only pre-signed exact requests and write verified terminal bytes to a fixed
owner-only result store rather than MCP output.

The built-in `os/exec` supervisor is for trusted, operator-authored processes. Root
and non-loopback startup acknowledgements reduce accidental exposure, but they do
not provide isolation. Run untrusted workloads through Executor.

### Embedded operator console

`steward-control` embeds its committed `/console/` distribution and serves it on
the existing control listener. Static console assets introduce no second web
server or authentication database. Data requests use the same Bearer operator
identity and tenant projection as the operations API. The React source issues only
same-origin reads for summary, derived attention, nodes, command metadata, and
credential metadata. Controller mutations and private signing remain CLI, API, or
offline operator workflows.

The browser credential exists only in a JavaScript memory reference. Explicit
lock, `pagehide`, 15 minutes of inactivity, or an eight-hour absolute interval
aborts the session and clears application state. These browser timers do not
expire or revoke the server-side bearer. Browser extensions remain trusted enough
to read the page or memory, so the intended operator endpoint is a dedicated
hardened profile without unapproved extensions.

The control server derives its exact Host gate without an additional setting. A
literal-loopback HTTP listener accepts only its actual bound IP and port. A TLS
listener accepts exact non-wildcard DNS or IP Subject Alternative Names from the
loaded leaf certificate at the bound port; only port `443` may be omitted. A
malformed or mismatched Host fails before API or console dispatch.

The production HTML, JavaScript, CSS, and icon files are committed and embedded
with `go:embed`. They load no CDN or telemetry service, and the running controller
has no Node.js dependency. React and Vite are lockfile-pinned inputs to a separate
maintainer rebuild. CI uses Node.js 24 LTS, installs with lifecycle scripts
disabled, audits and tests the source, rebuilds the distribution, and rejects any
diff from the committed assets. A normal or air-gapped Go build consumes those
assets directly and does not invoke npm.

## Runtime layers

### Supervisor core and opt-in features

The supervisor always provides lifecycle tracking. `internal/runtime` maps an
opaque `runtime_ref` to an instance and one of these statuses: `PENDING`, `RUNNING`,
`STOPPED`, `HIBERNATED`, `DESTROYED`, or `FAILED`. Provision, start, stop,
hibernate, destroy, and status operations use one mutex-guarded state machine.
State is in memory unless durable state is enabled.

The following supervisor features are off by default:

- process execution: `-enable-process-exec`;
- durable state: `-state-file`;
- Prometheus metrics: `-enable-metrics`;
- the uplink command audit log: `-audit-log-file`; and
- the outbound control-plane uplink: `-uplink-url`.

Bundled-controller node enrollment enables only Executor's signed uplink. It keeps
the generic supervisor on literal loopback with durable local state and process
execution disabled. A separately compatible controller can supply the optional
generic supervisor credential and uplink.

Without process execution, lifecycle operations only change tracked status. The
supervisor does not sandbox workloads, perform computer-use, authenticate inbound
requests, terminate TLS, emit distributed traces, expose metrics, write an audit
log, or persist state by default.

Executor and Gateway are separate services, not supervisor feature flags. Enabling
Executor means starting another service with its own identity, durable state,
listener or uplink, and Docker-socket access. Gateway has a third identity and its
own configuration. `steward-relay` runs only inside an admitted workload's private
network as a fixed-destination companion.

Linux release artifacts contain seven binaries:
`steward-control`, `steward`, `steward-executor`, `steward-gateway`,
`steward-relay`, `stewardctl`, and `steward-mcp`. Each release contains those
binaries, helper scripts, configuration templates, and a manifest that binds every
binary and host-integration asset by SHA-256. A node installation creates three
service identities for supervisor, Executor, and Gateway. The separate controller
installer creates a fourth identity only on a controller host; the node package
never installs or enables a controller service.
Installation stages the complete release without changing active files. Activation
validates the target, then selects its binaries and host integration together
through `/opt/steward/current`. When Gateway and relay support is configured,
activation also verifies a relay image built from the target release and selects its
binding. A release transition requires a drained node and stops and restarts only
services that were active. Durable state and credentials remain outside the release
directory. The installer does not install Docker. It installs verified gVisor
artifacts only with explicit operator approval. Controller placement, tenant
signing keys and policy, approved OCI images, and inference remain operator
responsibilities. See
[`docs/node-appliance.md`](docs/node-appliance.md).

### Signed Executor admission

Signed admission is opt-in. Executor admits only the intersection of three inputs:

- a publisher-signed reusable profile capsule, which sets an artifact and profile
  ceiling but does not schedule a tenant;
- a site-root-signed policy, which narrows publishers, repositories or exact
  digests, profiles, tenants, and resource ceilings; and
- an authenticated instance intent, bound to a tenant, node, instance, lineage,
  and generation.

For a multi-tenant Executor uplink, the bearer credential identifies the node's
transport. It does not authorize a tenant. Each command is a bounded DSSE (Dead
Simple Signing Envelope) statement signed by a tenant command key or a restricted
site cleanup key from the site policy. The signature binds the tenant, node,
instance, runtime reference, claim and instance generations, command sequence,
validity window, operation, and payload. Durable command state is keyed by
`(tenant_id, instance_id)`, so two tenants may reuse an instance ID without sharing
a replay fence.

Before changing Docker, Executor fsyncs (flushes to durable storage) a fixed-format
operation journal and appends a signed pre-effect receipt. It then creates and
inspects the fixed gVisor workload, appends a signed commit receipt, advances the
policy and generation fence, and marks the journal entry committed. A generation fence is a durable
high-water mark that rejects older authority. A corrupt receipt chain, changed
receipt key, or rollback stops startup. A valid unresolved journal entry starts
Executor in degraded mode: readiness is 503, normal mutations remain blocked, and
only an authenticated stop may narrow existing authority.

Executor lifecycle receipts use exact binary framing, Ed25519 signatures, and hash
links; they do not depend on JSON canonicalization. Gateway connector receipts use
a separate Gateway key and one signed DSSE JSON record per newline. Permit-backed
records bind the action-authority key ID, exact permit digest, and exact request
digest beside the stable task-based call digest. Current lifecycle service tasks use
receipt format 4 and add a task-local sequence and hash link across authorization,
dispatch, and terminal records. Authorized connector events use receipt format 5
and add the explicit effect mode plus the exact operation-policy digest. A stable
pre-effect `action_permit_denied` condition may create at most one denial marker
per retained grant; it binds the request digest without claiming a verified permit
or authority key. This first-observed sample is attacker-selectable and does not
enumerate later denials. Gateway state format 5 preserves the authorized mode and
signed-policy-derived connector/key scopes across restart. Both receipt systems are
node-local enforcement evidence, not proof against a hostile host. Host root, the
host kernel, Docker, gVisor, and node-key protection remain trusted. Receipts
exclude prompts, model responses, agent logs, semantic tool actions, and agent
explanations. Executor and Gateway each hold their own receipt key in-process.
Moving signing to separate service identities or processes could reduce that
authority in the future.

Capsules can set bounded `state`, `inference`, `service`, `connector`, and `egress` ceilings.
State requires a Steward-owned volume and the explicit dedicated-host-only mode for
volumes without enforced byte or inode quotas. Inference, service, connector, and egress
require the complete Gateway/relay path. Executor grants a capability only when its
required enforcement path is configured and verified. A signed field alone never
grants a capability.

### Authorized Effects enforcement path

Stored or indirect prompt injection is attacker-controlled content that reaches an
agent through a calendar invitation, email, web page, document, tool response, or
memory and is interpreted as instructions. Steward does not ask that same agent or
model to establish whether the content is safe. For this boundary it assumes the
workload is fully compromised.

Authorized Effects is an explicit intersection:

1. the site-root-signed tenant rule contains `authorized_effects`, selects
   `optional` or `required`, assigns each action public key to exact connector IDs,
   and sets the number of distinct approvals required;
2. authenticated instance intent explicitly selects `effect_mode`; required policy
   rejects `standard`, while authorized mode rejects generic egress;
3. Executor projects only the selected, policy-pinned connector/key scopes through
   immutable runtime state to Gateway;
4. Gateway requires those scopes to exactly match its validated connector keys and
   operations; and
5. every effect needs a complete canonical version-2 or version-3 DSSE permit over
   the exact request, which Gateway records as spent before resolution or
   connection.

Action private keys stay off-node and outside the workload. Gateway keeps the
upstream credential in an owner-only file and injects it only at the fixed
connector operation. The signed connector chain lets an offline auditor correlate
the exact permit, request digest, operation policy, authorization, and terminal
observation.

This is complete mediation only for Steward connectors. Unmanaged credentials or
channels, inference confidentiality, local filesystem changes, computer use, host
root, signing-key compromise, approver misunderstanding, and upstream exactly-once
semantics remain outside the claim. See
[`docs/guides/authorized-effects.md`](docs/guides/authorized-effects.md).

Detailed Executor behavior is in [`docs/executor.md`](docs/executor.md).

### Operator-side fleet rollout

`stewardctl rollout` is a bounded operator-side coordinator, not a controller
resource or scheduler. Its unsigned plan fixes one release, tenant, explicit target
order, first-node canary, and deterministic later batches. Before any controller
request, one tenant command key authorized for `admit`, `start`, and
`activation-canary` signs the exact plan. Before entering each later batch, the
same key signs a chained promotion that binds the preceding batch's passed target
state, activation proofs, controller captures, and the next boundary. Every
rollout command signs the applicable plan-authorization or promotion-envelope
digest as `authorization_context_digest`; protocol-4 nodes advertise
`rollout-authorization-context-v1` when they accept that field.

The owner-only rollout workspace publishes generated artifacts without replacement
through same-directory hard-link transactions and reconciles only bounded staging
states after interruption. It requires same-filesystem POSIX hard links, reliable
file and directory `fsync`, reliable `flock`, and stable Unix ownership and link
counts. It fails closed instead of using a weaker fallback.

The aggregate proof remains unsigned. Its `plan_authorization_digest` and ordered
`batch_promotion_digests` bind the signed envelopes, so its digest commits the
complete promotion chain. Each target entry also binds the exact signed outer
command envelopes through `admit_command_digest`, `start_command_digest`, and
`canary_command_digest`. The aggregate digest therefore commits the exact retained
plan, promotion, and outer-command authorization envelopes without becoming a
signature. This is a signer-attested
authorization sequence, not an independent wall-clock or host attestation and not
a record of the human reasoning or external approval behind promotion. The exact
workflow and limits are in
[`docs/guides/fleet-rollout.md`](docs/guides/fleet-rollout.md).

## Supervisor state and control

### Durable state

Durable state is disabled unless `-state-file` or `STEWARD_STATE_FILE` is set.
Without it, a restart forgets every tracked instance.

With a state file:

- **Startup:** Steward rebuilds its `byRef` and `byID` indexes before serving. A
  missing file means a first run; Steward creates it on the first mutation. An
  unreadable file, invalid JSON, unsupported format version, duplicate
  `runtime_ref`, or other structural inconsistency stops startup with the path and
  a corrective action.
- **Mutation:** Provision, start, stop, hibernate, and destroy persist the full
  snapshot before returning success. The write occurs under the tracker's mutex.
  Ordinary reversible mutations restore the prior in-memory state when persistence
  fails. A process-backed stop or unexpected exit cannot resurrect a process that
  has already ended; in those paths memory remains `STOPPED` and the state file may
  lag until a later successful mutation or restart reconciliation.
- **Process-crash safety:** Steward writes a temporary file in the same directory,
  flushes the file with `fsync`, and atomically renames it over the current file. A
  process crash leaves the previous complete snapshot, the new complete snapshot,
  or an orphan temporary file, not a partially written current file. Steward does
  not `fsync` the parent directory after the rename, so durability across a host
  power loss depends on the filesystem and storage configuration.
- **Format:** The versioned JSON shape is
  `{"version":1,"instances":[…]}`. Steward uses only `encoding/json` and `os`.
  An already compact `spec` round-trips byte-for-byte. Only insignificant
  whitespace in a noncompact `spec` is normalized.

`GET /v1/capabilities` reports whether persistence is enabled in `durable_state`;
it never exposes the path. Persistence adds no endpoint and does not change the
instance request or response shapes in `openapi/steward.v1.yaml`.

### Capacity reload

`SIGHUP` rereads `-config` and can change only `max_instances` without a restart.
Lowering the cap below the current count does not stop or destroy an instance. It
blocks new provisions with `503` until normal destroys bring the count below the
new cap. Likewise, a state file containing more instances than the configured cap
loads in full; the cap limits growth, not recovery.

The narrow reload scope avoids rebinding a listener, redialing an uplink, or moving
durable state while requests are active. `max_instances` is an in-memory integer
and is not stored in the state snapshot. Other configuration changes require a
restart.

Startup precedence also applies to reloads: flag > environment > file. A value set
by `-max-instances` or `STEWARD_MAX_INSTANCES` continues to override the file.
`SIGHUP` never shuts down the process; only `SIGINT` and `SIGTERM` do. If no
`-config` file is set, reload is a documented no-op. An unreadable or invalid file
leaves the live cap unchanged. Every outcome is logged. `GET /v1/capabilities`
reads the current cap and reflects a successful reload.

### Outbound uplink

`-uplink-url` or `STEWARD_UPLINK_URL` enables a node-initiated command channel for
sites where network address translation (NAT) or a firewall prevents inbound
control-plane connections. The node
polls for lifecycle commands, applies them through the same tracker used by the
REST handlers, and reports results. REST and uplink calls therefore share the same
mutex, idempotency rules, and durable file.

The node authenticates to the control plane with a versioned bearer credential
containing its tenant, node, and secret. This outbound identity does not add
authentication to the inbound REST API. A missing, malformed, or unsafe credential
stops startup when the uplink is enabled. The credential must be a regular file
with mode `0600` or stricter, including when Steward runs as root. Startup,
`-check-config`, and credential reload all enforce this rule.

The uplink adds no inbound HTTP route. Network errors and `5xx` responses use
bounded retry backoff. A `401` or `403` pauses polling and marks readiness degraded
while Steward watches the credential file. A valid replacement for the same node
resumes polling without a restart. If no credential path is available to watch,
recovery requires a restart.

TLS uses the Go standard library. Operators can provide a private CA with
`-uplink-tls-ca-file` and mutual TLS (mTLS) credentials with
`-uplink-tls-client-cert` and `-uplink-tls-client-key`. An explicit CA replaces
the system root set for that connection. The private key must be owner-only.
Invalid TLS inputs stop startup and `-check-config`; Steward never silently falls
back. `-uplink-tls-skip-verify` is an explicit, logged compatibility exception.

Poll and report bodies are limited to 1 MiB. An oversized poll response is rejected
and retried in a later cycle. An oversized report is rejected before transmission,
allowing the control plane's claim lease to redeliver the command. See
[`docs/uplink-client.md`](docs/uplink-client.md).

### Inbound listener

The inbound listener remains enabled unless `-disable-inbound-listener` or
`STEWARD_DISABLE_INBOUND_LISTENER` is set. With the flag, Steward creates no
`http.Server`; the in-process uplink still calls the tracker directly.

Disabling the listener without an uplink would make the node unreachable, so that
combination stops startup with both remedies. The flag changes no API shape or
status code. An uplink-only node has no local `GET /v1/healthz`,
`GET /v1/readiness`, or `GET /metrics`. Systemd, or another external service
manager, can report process state and expose startup, failure, recovery, and
command logs. Quiet successful polls are not logged on every cycle, so
listener-free mode provides no local positive readiness signal. Leave the
listener enabled when a local HTTP probe, positive poll-health signal, or metrics
scrape is required. See
[`docs/disable-inbound-listener.md`](docs/disable-inbound-listener.md).

### Replay fencing and backpressure

Destroy releases an `instance_id` for reuse. To prevent an old uplink command from
acting on a replacement instance, each instance records its lineage `generation`.
A command with an older `instance_generation` is logged and dropped without a
report. A new provision stores its generation atomically with the instance. The
field is part of the existing state snapshot, so the fence survives a restart.

An absent, zero, or negative command generation is treated as zero and is not
fenced. This preserves compatibility with control planes that do not send the
field. Request shapes are unchanged. Responses may include the optional
`Instance.generation` field when uplink fencing is in use; the OpenAPI schema
documents it. See
[`docs/instance-generation-fencing.md`](docs/instance-generation-fencing.md).

The uplink uses a bounded in-memory queue between polling and execution. The
`-uplink-command-queue-depth` default is `256` and must be positive. A single
consumer preserves each poll batch's order.

When a poll would exceed the cap, Steward rejects the excess, logs each rejection
with the prefix `uplink command queue full:`, and sends no report. The control plane
can redeliver those commands after the backlog drains. A `command_id` already queued
or in flight is skipped to avoid duplicate work. An empty, out-of-contract
`command_id` is not deduplicated. Tracker idempotency remains the correctness
boundary; queue deduplication only saves work and durable writes.

Several consecutive full-queue polls make `GET /v1/readiness` return not ready. A
single burst does not. The first poll with queue headroom restores readiness. An
uplink-only node exposes the condition through advancing logs. When the listener
and metrics are enabled, `steward_uplink_command_queue_depth` and
`steward_uplink_commands_rejected_total` expose it directly.

## Supervisor API and observability

### Metrics and audit log

Both surfaces are opt-in and use only the Go standard library.

- `GET /metrics` is registered only with `-enable-metrics` or
  `STEWARD_ENABLE_METRICS`. It reports instance counts by status and the capacity
  cap. With an uplink, it also reports poll latency (minimum, maximum, and latest),
  poll count, command success and failure counters, current backoff, queue depth,
  and rejected commands in Prometheus text format. It uses the main listener and
  its per-source rate limiter. With metrics disabled, the path returns 404.
- `-audit-log-file` or `STEWARD_AUDIT_LOG_FILE` appends one JSON Lines record for
  each uplink command that reaches a terminal reported outcome. Records contain a
  timestamp, `command_id`, `instance_id`, `kind`, `status`, and an `error` detail
  on failure. Direct REST requests have no `command_id` and are not included. The
  file opens once and each mutex-protected record is one `O_APPEND` write, so
  concurrent writers cannot interleave a record. An open failure stops startup. A
  later write failure is logged at `WARN`; the audit log is best-effort and does
  not determine the command result.

### Errors and health

Every API error has `{"error":"...","message":"..."}` and a stable code.
Supervisor codes are
`invalid_request`, `invalid_spec`, `process_exec_disabled`,
`process_start_failed`, `unknown_runtime_ref`, `invalid_state_transition`,
`capacity_exceeded`, `request_too_large`, `rate_limited`, `not_found`,
`method_not_allowed`, and `internal_error`. Each code has a fixed HTTP status and
appears in the `Error.error` enum in
`openapi/steward.v1.yaml`. Clients should branch on the status or code, not the
human-readable `message`.

`GET /v1/healthz` reports process liveness. `GET /v1/readiness` reports whether the
node should receive traffic. Readiness returns `200` only when the tracker is
initialized; an enabled uplink is not in persistent first-contact failure or
sustained backpressure; and an enabled state directory is writable. A failed gate
returns `503` and names the first failure. One transient uplink error does not
change readiness, and one successful poll keeps the node ready across later brief
errors.

The state-writability probe creates and removes a uniquely named temporary file.
It does not race the snapshot's atomic rename. The liveness path does no file I/O.
Both endpoints exist only when the inbound listener is enabled.

### Instance semantics

`Provision` is idempotent on the caller's `instance_id` for the lifetime of the
instance. A repeat returns the existing `runtime_ref` and status. After `Destroy`,
the ID may be reused and the new instance receives a new `runtime_ref`. Concurrent
provisions for one ID still create one instance because the lookup and mutation
share the tracker's mutex.

Lifecycle transitions use an allowed-transition table. A self-transition is an
idempotent success. `stop` and `hibernate` from `PENDING` return
`409 invalid_state_transition` and leave the instance unchanged. Other transitions
among live statuses are allowed. `destroy` is always allowed for a live instance.

At provision time, `spec` must be a JSON object, `null`, or omitted. Steward
otherwise treats it as an opaque, forward-compatible value and stores and returns
it without interpreting its contents. Process execution is the one opt-in exception
described below.

`GET /v1/instances` supports `status`, `instance_id_prefix`, and `created_since`;
combined filters use AND. Each new instance gets an immutable `created_at`, and an
idempotent provision preserves it. Older state files without the field load a zero
time. That value remains visible in responses and does not match a real nonzero
`created_since` filter.

`POST /v1/instances/batch` applies an ordered list of `provision`, `start`, `stop`,
and `destroy` operations sequentially through the same tracker methods as the
single-instance endpoints. It is not a transaction. A later failure does not roll
back earlier effects or block later operations; each result stays at its input
index. A later operation sees earlier effects in the same batch.

Retry safety matches the individual operations. Provision remains idempotent.
Without a competing concurrent transition, repeated start and stop calls converge
on their terminal status. When transitions overlap, the returned instance is
authoritative; for example, a concurrent start may supersede a process stop before
the stop response is returned. Destroy releases the
`runtime_ref`, so replaying an already completed destroy returns
`404 unknown_runtime_ref`. See
[`docs/batch-instance-operations.md`](docs/batch-instance-operations.md).

## Process supervision is opt-in

The supervisor spawns nothing by default. Process execution requires both:

1. `-enable-process-exec`, `STEWARD_ENABLE_PROCESS_EXEC`, or
   `enable_process_exec` in the config file; and
2. a string `command` field in the instance `spec`.

A `command` with execution disabled returns `400 process_exec_disabled`. With
execution enabled and no `command`, Steward preserves status-only behavior.
Recognized process fields are `command` (non-empty string), `args` (string array),
`env` (name-to-value object), and `working_dir` (string). Other fields remain
opaque. Invalid types return `400 invalid_spec` during provision.

### Process security boundary

The child inherits Steward's UID, GID, and privileges. Steward does not call
`setuid`, `setgid`, or apply a sandbox. A root Steward therefore starts root
children. Startup refuses that posture unless `-allow-root-process-exec` is also
set. It likewise requires `-allow-nonloopback-process-exec` when the listener is
reachable beyond loopback. These flags acknowledge risk; they do not add
isolation. Run process supervision under a dedicated unprivileged user.

Steward calls `exec.Command(command, args...)` directly; it never invokes `sh -c`.
The child does not inherit Steward's environment. It receives only Steward's
`PATH` plus the exact variables in `spec.env`, with `spec.env` taking precedence.
This prevents accidental inheritance of uplink or TLS secrets.

Start, stop, hibernate, resume, unexpected exit, and restart reattachment produce
structured JSON logs with `runtime_ref`, `instance_id`, `pid`, `exit_code`, and
`reason` where applicable. Unexpected exit uses WARN and an `UNEXPECTEDLY` marker.
There is no separate process audit file; `-audit-log-file` covers uplink commands.

### Process lifecycle

- **Provision:** stores the spec as `PENDING` without starting a process.
- **Start from `PENDING` or `STOPPED`:** starts a new process and monitor
  goroutine. A missing executable, permission error, or invalid `working_dir`
  returns `400 process_start_failed` and preserves the previous status.
- **Start from `RUNNING`:** returns success without starting a duplicate.
- **Start from `HIBERNATED`:** sends SIGCONT to the existing process. If Steward
  lost the handle and cannot reattach, it starts a replacement and logs the loss
  of continuity.
- **Stop:** sends SIGTERM, waits up to `-process-stop-grace-period` (10 seconds by
  default), then sends SIGKILL if needed. The wait does not hold the tracker mutex.
- **Hibernate:** sends SIGSTOP without killing the process.
- **Destroy:** applies the stop sequence and removes tracking from any live status.
- **Unexpected exit:** records `STOPPED`, never `FAILED`. `FAILED` is reserved for
  the control plane when it cannot reach Steward. `last_exit_code` and
  `last_exit_reason` distinguish `crashed`, `stopped`, `killed`, and
  `supervision_lost` outcomes.

### Restart reattachment

An `*os.Process`, monitor goroutine, and stdout/stderr pipes cannot be persisted.
Steward stores the child's `pid` and a `proc_start_token` captured immediately
after spawn. On restart, each process-backed instance recorded as `RUNNING` or
`HIBERNATED` follows one of three paths:

- If the PID is gone, Steward records `STOPPED` with
  `last_exit_reason = supervision_lost`.
- If the PID exists but its start-time witness is missing, unreadable, or
  different, Steward records `supervision_lost` and never signals that PID. This
  prevents a reused PID from targeting an unrelated host process.
- If the PID and witness match, Steward restores only signal-based lifecycle
  control. It cannot recover stdout/stderr, wait for or reap the process, or detect
  a later exit. The instance keeps its status and is logged as `DEGRADED`.

The witness comes from `ps -o lstart=` on Linux and macOS and has one-second
precision. A missing or different witness causes a conservative
`supervision_lost`. A reused PID whose new process has the same one-second start
value cannot be distinguished, so reattachment is best-effort identity checking,
not cryptographic process identity.

Process supervision has no cgroup or ulimit resource controls, sandbox, or special
containment for child processes. `command` is not allowlisted, and `working_dir`
may name any path the Steward user can access. Treat both as trusted operator
configuration. This feature uses Unix signals and supports Linux and macOS; Windows
is outside its scope.

## Deferred decision: computer-use is a separate worker, never in-process

Computer-use is distinct from trusted `os/exec` supervision. If added, it will run
as a separate optional container-based worker and register through the `skills`
array in `GET /v1/capabilities`. It will not load into Steward's process.

This boundary preserves two invariants:

1. **Dependency purity:** Steward remains dependency-free Go and does not load
   Python or private agent tooling.
2. **Isolation:** a compromise or crash in the highest-risk agent capability stays
   outside the lifecycle supervisor's address space.

Until that worker exists, `skills` remains empty and Steward performs no skill or
computer-use action. `GET /v1/capabilities` may still report `version`,
`instance_count`, `max_instances`, and `durable_state`; these are read-only runtime
facts, not agent capabilities.

## Supervisor layout

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
