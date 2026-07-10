# Steward

Steward is a minimal, always-running **lifecycle supervisor for agent instances**
that runs on a node. It tracks the lifecycle of agent instances — provision,
start, stop, hibernate, destroy, and status — behind a small HTTP API, and does
nothing else. It is designed to be managed remotely over HTTP by a separate
control plane.

Steward is deliberately a *walking skeleton*: lifecycle tracking only, no command
execution, no sandboxing. State is in memory by default (a restart forgets every
instance); durable state across a restart is opt-in via `-state-file`. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the design boundaries and the deferred
decisions (notably how a future computer-use capability is kept out of Steward's
own process).

## The public contract

[`openapi/steward.v1.yaml`](openapi/steward.v1.yaml) is the authoritative,
hand-written public contract for the HTTP API. It is the audit surface: if the
server and that document disagree, the document is the spec. CI lints it on every
change.

## Zero private dependencies

Steward has **zero dependency, at build time or runtime, on any private package,
API, or tool.** It uses only the Go standard library and the public Go module
ecosystem. This is the entire point of the repository being public: a
sovereign or regulated operator can clone *this repository alone* and build and
run Steward, without access to — or trust in — any vendor-private code.

This claim is mechanically checkable. The module currently depends on nothing but
the standard library, so:

```console
$ go list -m all
github.com/hardrails/steward
```

lists only this module. Any private dependency would appear here (and in
`go.mod`/`go.sum`), so the guarantee cannot silently rot.

## Requirements

- Go 1.24 or newer.

## Contributing

Read [AGENTS.md](AGENTS.md) first — it names the invariants a change must not
regress (zero private dependencies, request-size/instance-count bounds,
concurrency safety in `internal/runtime`) and the local guard:
`git config core.hooksPath .githooks` once per clone, run before every commit,
mirrored by required status checks on `main`.

## Build and test

```console
go build ./...
go vet ./...
go test ./...
```

## Run

```console
# Defaults to 127.0.0.1:8080.
go run ./cmd/steward

# Override the listen address via flag or env var.
go run ./cmd/steward -addr 127.0.0.1:9090
STEWARD_ADDR=0.0.0.0:8080 go run ./cmd/steward
```

Every setting is a flag with a matching `STEWARD_`-prefixed env var, and can also
be supplied in a JSON [config file](#config-file). Precedence is
**flag > env var > config file** (a flag beats an env var, which beats the config
file, which beats the built-in default):

| Flag              | Env var                  | Default          | Purpose                                                                 |
| ----------------- | ------------------------ | ---------------- | ----------------------------------------------------------------------- |
| `-addr`                    | `STEWARD_ADDR`                    | `127.0.0.1:8080` | host:port to listen on                                                  |
| `-log-level`               | `STEWARD_LOG_LEVEL`               | `info`           | log verbosity: one of `debug`, `info`, `warn`, `error` (case-insensitive); a garbage value fails closed at startup |
| `-max-instances`           | `STEWARD_MAX_INSTANCES`           | `1024`           | maximum tracked instances before Provision returns 503; must be a positive integer (a non-positive value fails closed at startup) |
| `-max-requests-per-second` | `STEWARD_MAX_REQUESTS_PER_SECOND` | `20`             | max inbound requests/second per source IP before returning 429 (burst is 2x this); `0` or negative disables the per-source limiter |
| `-state-file`              | `STEWARD_STATE_FILE`              | (unset)          | path to a JSON file for durable state; unset means in-memory only       |
| `-uplink-url`              | `STEWARD_UPLINK_URL`              | (unset)          | control-plane base URL for the outbound uplink; unset disables it       |
| `-uplink-credential-file`  | `STEWARD_UPLINK_CREDENTIAL_FILE`  | (unset)          | path to the node's uplink credential JSON; required when `-uplink-url` is set. Must be `0600` or stricter (owner-only); a group- or other-accessible file fails closed at startup — see [Uplink transport security](#uplink-transport-security) |
| `-uplink-tls-ca-file`      | `STEWARD_UPLINK_TLS_CA_FILE`      | (unset)          | PEM CA bundle used to verify the control plane's TLS certificate; unset verifies against the host's system root CAs |
| `-uplink-tls-client-cert`  | `STEWARD_UPLINK_TLS_CLIENT_CERT`  | (unset)          | PEM client certificate presented for mutual TLS (mTLS); requires `-uplink-tls-client-key` |
| `-uplink-tls-client-key`   | `STEWARD_UPLINK_TLS_CLIENT_KEY`   | (unset)          | PEM private key for `-uplink-tls-client-cert`; requires `-uplink-tls-client-cert` |
| `-uplink-tls-skip-verify`  | `STEWARD_UPLINK_TLS_SKIP_VERIFY`  | `false`          | **INSECURE**: skip verification of the control plane's TLS certificate. Defeats TLS authentication; logged loudly when on. Temporary diagnostics only |
| `-uplink-poll-interval`    | `STEWARD_UPLINK_POLL_INTERVAL`    | `10s`            | base cadence for uplink polling; jitter is applied on top; clamped to a 5-minute ceiling (the failed-poll backoff cap) |
| `-disable-inbound-listener` | `STEWARD_DISABLE_INBOUND_LISTENER` | `false`          | do not bind an inbound listener; requires `-uplink-url`                |
| `-enable-metrics`          | `STEWARD_ENABLE_METRICS`          | `false`          | expose `GET /metrics` (Prometheus text format) on the inbound listener; see [Metrics](#metrics) |
| `-audit-log-file`          | `STEWARD_AUDIT_LOG_FILE`          | (unset)          | path to a JSON-lines file recording every executed uplink command; unset disables it; see [Command audit log](#command-audit-log) |
| `-enable-process-exec`     | `STEWARD_ENABLE_PROCESS_EXEC`     | `false`          | run real OS processes for `command`-bearing specs; off by default (pure status tracking). See [Process supervision](#process-supervision) |
| `-process-stop-grace-period` | `STEWARD_PROCESS_STOP_GRACE_PERIOD` | `10s`         | how long a stop waits after SIGTERM before escalating to SIGKILL; must be positive; only used when process execution is enabled |
| `-config`                  | `STEWARD_CONFIG`                  | (unset)          | path to a JSON [config file](#config-file) supplying any of the settings above; a flag or env var overrides it |

`-version`, `-check-config`, and `-schema` are action flags rather than settings
(they have no env var):

- `-version` prints the build/version string and exits 0 without binding a port or
  starting the uplink loop. The string is the VCS revision the Go toolchain stamps
  into the binary (`go build`/`go install`), falling back to a compiled-in constant
  when no build metadata is available (for example under `go run`). It is the same
  value `GET /v1/capabilities` advertises.
- `-check-config` runs every fail-closed startup check against the fully resolved
  configuration (flags, env vars, and any `-config` file) and then exits 0 (valid)
  or non-zero with the same actionable message a real startup would give —
  **without binding a port, keeping state for real use, or starting the uplink
  loop**. It answers "will this configuration work?" before a rollout. It validates
  a `-config` file too:

  ```console
  # Validate the flags, env, and config file this node would boot with.
  go run ./cmd/steward -check-config -config /etc/steward/config.json
  # -> prints "configuration valid" and exits 0, or names the first problem and exits non-zero.
  ```

- `-schema` prints the JSON Schema (draft 2020-12) for the [config file](#config-file)
  to stdout and exits 0, without binding a port or starting the uplink loop. It
  describes the config file's *shape* — every key, its type, and the constraints a
  real boot enforces (`additionalProperties: false`, a positive `max_instances`,
  the `uplink_url` ⇒ `uplink_credential_file` pairing, `disable_inbound_listener:
  true` ⇒ `uplink_url`) — so fleet tooling can validate a candidate config against a
  real schema *before* ever invoking `-check-config`. The schema is generated by
  reflecting over the config struct, so it cannot drift from what a boot accepts:

  ```console
  # Emit the schema your fleet tooling validates candidate configs against.
  go run ./cmd/steward -schema > steward.config.schema.json
  ```

By default Steward keeps state in memory and a restart forgets every tracked
instance. Set `-state-file` to persist state across restarts:

```console
# Durable state: instances survive a restart. The file is created on first use.
go run ./cmd/steward -state-file ./steward-state.json
STEWARD_STATE_FILE=/var/lib/steward/state.json go run ./cmd/steward
```

Each state-changing operation is written atomically (temp file + rename) using
only the standard library. On startup Steward loads an existing file before
serving; a corrupt or unreadable file is a fail-closed startup error naming the
path and the fix, never a silent empty start.

By default Steward always binds the inbound HTTP listener on `-addr`, even when
the outbound uplink (`-uplink-url`) is also enabled. A node whose only reason for
using the uplink is that inbound connections are impossible — behind NAT or a
firewall — can set `-disable-inbound-listener` to bind nothing inbound; all
fleet operations then flow through the uplink poll loop only. The flag requires
`-uplink-url` — a node with neither door open is unreachable and fails closed at
startup. See [`docs/disable-inbound-listener.md`](docs/disable-inbound-listener.md)
for the full design.

### Inbound rate limiting

The inbound HTTP listener is unauthenticated by design, so it defends itself from
denial-of-service the same structural way it bounds request bodies and instance
count: a per-source (client IP) request-rate limit. Steward keys a hand-rolled,
standard-library-only token bucket on the connecting IP and, when a source exceeds
its budget, sheds the request with `429 Too Many Requests` and a `Retry-After`
header — never touching the request or response body shape of any operation.

The default budget — `20` requests/second per source with a burst of `40` — is
sized for a control-plane-facing lifecycle API. Railyard drives
provision/start/stop/hibernate/destroy/status/list at reconciler-and-human pace, so
a normal reconciliation spike sits well inside the burst and steady traffic well
under the rate, while a flood from one source is shed in well under a second. The
limit is per-source, so one abusive IP cannot degrade service for the legitimate
control plane on another. A 429 is shed before any handler work runs, so it is
always safe to retry — but whether a bulk operation that exceeds the burst degrades
gracefully depends on the caller honoring `Retry-After`, not on this limiter alone.
Raise `-max-requests-per-second` (or `STEWARD_MAX_REQUESTS_PER_SECOND`) for heavier
bulk operation, or set it to `0` to disable the limiter entirely — appropriate only
when Steward already sits behind a gateway that rate-limits for it. The per-source
bucket map is bounded and its idle entries are swept, so a distributed many-IP
flood cannot grow it without limit.

Because the key is the real TCP peer and never a client-supplied header (an
unauthenticated caller could forge `X-Forwarded-For` to dodge the limit), a
deployment that terminates connections behind a shared proxy sees all traffic as one
source; rate-limit at that proxy and disable Steward's limiter there.

### Metrics

`GET /metrics` is an **opt-in** endpoint (`-enable-metrics` /
`STEWARD_ENABLE_METRICS`, default off) that renders Steward's operational state in
the [Prometheus text exposition
format](https://github.com/prometheus/docs/blob/main/content/docs/instrumenting/exposition_formats.md).
It reports:

- `steward_instances{status="..."}` — current tracked instances, broken down by
  status (a gauge, not a counter — no `_total` suffix, since it can go down as
  well as up).
- `steward_max_instances` — the configured capacity cap.
- `steward_uplink_poll_latency_seconds{stat="min"|"max"|"last"}` — the outbound
  uplink's `/uplink/poll` round-trip latency (present only when `-uplink-url` is
  set).
- `steward_uplink_polls_total` — total polls attempted, success and failure alike.
- `steward_uplink_commands_total{status="success"|"failure"}` — uplink commands
  executed, by outcome.
- `steward_uplink_backoff_seconds` — the poll loop's current interval/backoff.

The `steward_uplink_*` series are present only when the outbound uplink is enabled
(`-uplink-url`); on an inbound-REST-only node the endpoint still serves the
instance-count and capacity gauges.

It is off by default and, when enabled, is reachable **only** through the same
inbound HTTP listener every other endpoint uses — there is no second listener, so
`/metrics` automatically respects `-disable-inbound-listener` (no listener, no
`/metrics`) and the per-source rate limiter above. It is built entirely from the
standard library (`fmt`, `strings`, `net/http`): the Prometheus text format is
simple enough that the official `prometheus/client_golang` library was not needed
to stay within the [zero-dependency invariant](#zero-private-dependencies).

### Command audit log

`-audit-log-file` (env `STEWARD_AUDIT_LOG_FILE`, unset by default) appends one
JSON-lines record to the given file for every uplink command Steward executes to a
terminal (reported) outcome:

```json
{"timestamp":"2025-01-01T00:00:00Z","command_id":"cmd-123","instance_id":"agent-1","kind":"provision","status":"success"}
{"timestamp":"2025-01-01T00:00:05Z","command_id":"cmd-124","instance_id":"agent-1","kind":"stop","status":"failure","error":"stop names an unknown instance"}
```

`error` is present only on a `"failure"` record. The file is opened once (created
if missing) and appended to for the life of the process; each record is written
with a single `os.File.Write` call under a mutex, the same append-only,
torn-write-tolerant discipline `-state-file`'s crash-safety gives durable state,
achieved with a different mechanism suited to an append-only log rather than a
rewritten-in-full snapshot (see [ARCHITECTURE.md](ARCHITECTURE.md) for why). A
failure to open the file at startup is a fail-closed error naming the path; a
failure to write a record at runtime is logged at `WARN` and otherwise ignored — the
audit log is a best-effort operational trail, not a source of truth the tracker or
control plane depend on, so it must never turn a successful command into a failure.

This covers commands the **outbound uplink** dispatches (provision/start/stop/
hibernate/destroy), which carry a `command_id`; it does not cover the direct
inbound REST API, which has no command-id concept of its own. Setting
`-audit-log-file` with no `-uplink-url` is accepted (the file is still created) but
logs a startup `WARN`, since no uplink command will ever exist to record.

### Process supervision

By default Steward tracks lifecycle *status* and spawns nothing — starting an
instance just moves it to `RUNNING`. With `-enable-process-exec` it becomes a real,
`os/exec`-level process supervisor (in the class of systemd/supervisord), turning an
instance whose `spec` carries a `command` into an actual OS process it spawns,
signals, and monitors.

```console
# Enable real process execution, with a 15s SIGTERM→SIGKILL grace period.
go run ./cmd/steward -enable-process-exec -process-stop-grace-period 15s

# Provision an instance whose spec is a real command, then start it.
curl -sX POST localhost:8080/v1/instances \
  -d '{"instance_id":"worker-1","spec":{"command":"/usr/bin/my-agent","args":["--serve"],"env":{"LOG":"debug"},"working_dir":"/srv"}}'
# -> the runtime_ref in the response; POST .../{runtime_ref}/start spawns the process.
```

**The opt-in is backward-compatible by design.** `spec` has always been an opaque
blob callers fill with arbitrary config, so real execution requires **both**
`-enable-process-exec` **and** a `command` field in the spec:

- With execution **off** (the default), a spec **without** a `command` is exactly as
  before (opaque config, no process), and a spec **with** a `command` is rejected
  with `400 process_exec_disabled` — a caller's intent to run a process is failed
  loudly, never silently ignored.
- With execution **on**, a spec without a `command` is still a pure status
  transition; only a `command`-bearing spec spawns a process.

The interpreted spec fields are `command` (string; its presence is the trigger),
`args` (string array), `env` (a name→value object), and `working_dir` (string);
every other key stays opaque.

Lifecycle maps to signals: **start** spawns (or, from hibernation, `SIGCONT`-resumes
the existing process); **stop** sends `SIGTERM`, waits the grace period, then
`SIGKILL`; **hibernate** sends `SIGSTOP`; **destroy** terminates the process. An
already-running start is an idempotent no-op — no duplicate process. A process that
exits on its own (a crash) moves the instance to `STOPPED` (Steward never emits
`FAILED`) and records `last_exit_reason: "crashed"` — distinct from a requested
stop's `"stopped"`/`"killed"` — with a WARN naming it an unexpected exit.

**Security posture** (deliberate): the command is run **directly, never via a
shell**, so args cannot cause shell injection; the child does **not** inherit
Steward's environment (which may hold secrets) — only `PATH` plus the spec's `env`;
and there is **no sandboxing and no resource limiting** in this layer — it is
process supervision, not the separate, still-deferred sandboxed computer-use worker.

**Restart limitation (honest):** an OS process handle and its stdout/stderr pipes
cannot survive a Steward restart. The child's `pid` is persisted (when `-state-file`
is set), and on reload Steward liveness-checks it: a dead pid becomes `STOPPED`
(`last_exit_reason: "supervision_lost"`); a live pid is **reattached in a degraded,
liveness-only mode** — Steward can stop/hibernate/resume it by pid but has lost its
stdout/stderr and can no longer detect a future crash proactively. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the full design and limits.

### Uplink transport security

The outbound uplink is an HTTP client dialing the control plane, so its transport
security is a node-side deployment concern configured the same flag > env > file
way as everything else. Three defenses harden it; all are opt-in except the
credential-permission check, which is always on when the uplink is enabled.

- **Configurable TLS.** By default the uplink verifies the control plane's
  certificate against the host's system root CAs and presents no client
  certificate. A node that talks to a control plane behind a private or internal
  CA can point `-uplink-tls-ca-file` at a PEM CA bundle to trust it without
  touching the system trust store, and a deployment that wants mutual TLS can set
  `-uplink-tls-client-cert` and `-uplink-tls-client-key` (both required together)
  so the node presents a client certificate. All four settings are validated
  fail-closed at startup and under `-check-config`: an unreadable CA, a CA file
  with no usable certificate, or a client cert without its key (or a pair that
  does not load) is a startup error naming the fix, never a silent fall back to
  system defaults. The client **private key** is a secret like the credential, so
  its file must also be `0600` or stricter — a group- or other-accessible key is
  refused fail-closed (the public certificate needs no such check). It is built
  with only `crypto/tls` from the standard library —
  no new dependency. `-uplink-tls-skip-verify` disables certificate verification
  entirely; it is **insecure** (it defeats TLS authentication and exposes the
  channel to a man-in-the-middle), defaults off, and logs a loud warning whenever
  it is set — use it only for a temporary diagnostic, never in production.

- **Bounded poll/report bodies.** The uplink caps every HTTP body it reads or
  writes at the same 1 MiB the inbound REST API bounds a request body to. A poll
  response over the cap is a clean, logged rejection — this poll cycle is dropped
  and retried next, never read unbounded into memory or parsed from a truncated
  prefix — and a report body over the cap is refused before it is sent (the server
  redelivers the command via its claim lease). A hostile or buggy control plane
  therefore cannot make Steward read or send an unbounded body.

- **Secret file permissions.** The uplink credential and the TLS client private
  key are both secrets, so each file must be `0600` or stricter (owner-only). A
  file readable or writable by group or others is refused fail-closed — at startup,
  under `-check-config`, and (for the credential) on the hot-reload watch — with an
  actionable message naming the path and the `chmod 600` fix. The check is on the
  mode bits, so it holds even when Steward runs as root.

## Config file

Any setting can live in a JSON config file, pointed at by `-config` (or
`STEWARD_CONFIG`). It is the lowest-precedence layer: a flag or an env var always
overrides the same key in the file (**flag > env var > config file**). Keys are
`snake_case` — the same names as the `STEWARD_`-prefixed env vars, minus the
prefix — and every key is optional; an omitted key falls back to its env var,
flag, or built-in default. `uplink_poll_interval` and `process_stop_grace_period`
are Go duration strings (e.g. `"30s"`, `"1m30s"`).

```json
{
  "addr": "0.0.0.0:8080",
  "max_instances": 512,
  "log_level": "info",
  "state_file": "/var/lib/steward/state.json",
  "uplink_url": "https://control-plane.example",
  "uplink_credential_file": "/etc/steward/uplink-credential.json",
  "uplink_poll_interval": "30s",
  "disable_inbound_listener": false,
  "enable_process_exec": false,
  "process_stop_grace_period": "10s"
}
```

```console
go run ./cmd/steward -config /etc/steward/config.json

# A flag or env var still wins over the file — here the listen address is
# overridden while the rest of the file's settings apply.
go run ./cmd/steward -config /etc/steward/config.json -addr 127.0.0.1:9090
```

The file is read fail-closed, the same way the state and credential files are: a
missing file, malformed JSON, an unknown key (a typo such as `max_instance` for
`max_instances`), or trailing data is a startup error naming the file and the
problem, never a silently-ignored or half-applied config. Run
`steward -check-config -config <path>` to validate it without starting the server.

### Hot-reloading `max_instances` with `SIGHUP`

Sending `SIGHUP` to a running Steward re-reads the `-config` file and hot-reloads
**`max_instances` only** — the capacity cap — with no restart. Edit the file's
`max_instances`, `kill -HUP <pid>`, and grep the logs for the `sighup reload:` line
that records the change:

```console
# Edit /etc/steward/config.json's max_instances, then:
kill -HUP "$(pidof steward)"
# -> logs: sighup reload: max_instances updated old_max_instances=… new_max_instances=…
```

Scope is deliberately narrow — only `max_instances` reloads. The other settings
(the listen address, the uplink URL and credential, the state file) are a much
larger, riskier live-reconfiguration surface and are out of scope; change them with
a restart. `SIGHUP` never shuts the process down (only `SIGINT`/`SIGTERM` do), and
the reload is fail-closed: with no `-config` file at startup it is a documented
no-op, a `max_instances` pinned by the `-max-instances` flag or
`STEWARD_MAX_INSTANCES` env var still wins over the file (the same
flag > env > file precedence as startup), and an unreadable or invalid file leaves
the live cap unchanged — every outcome is logged, never silent.

**Lowering the cap below the current instance count is safe: it evicts nothing.**
No already-tracked instance is stopped or destroyed; the lower cap simply blocks
*new* provisions (returning `503`) until ordinary `Destroy` attrition drains the
count back under the ceiling. This is the same "circuit breaker on growth, not on
reload" posture Steward already applies when it loads a state file holding more
instances than its cap — a capacity re-tune must never become an outage.

## API at a glance

| Method | Path                        | Operation                                   |
| ------ | --------------------------- | ------------------------------------------- |
| POST   | `/v1/instances`             | Provision (idempotent on `instance_id`)     |
| GET    | `/v1/instances`             | List tracked instances (sorted by `runtime_ref`; optionally filtered — see below) |
| POST   | `/v1/instances/batch`       | Execute an ordered batch of lifecycle operations (see below) |
| GET    | `/v1/instances/{id}`        | Status                                      |
| POST   | `/v1/instances/{id}/start`  | Start                                       |
| POST   | `/v1/instances/{id}/stop`   | Stop                                        |
| POST   | `/v1/instances/{id}/hibernate` | Hibernate                                |
| DELETE | `/v1/instances/{id}`        | Destroy                                     |
| GET    | `/v1/capabilities`          | Advertised skills + operational info        |
| GET    | `/v1/healthz`               | Liveness probe (`{"status": "ok"}`)         |
| GET    | `/v1/readiness`             | Readiness probe (`200` ready / `503` not ready; see [Health and readiness](#health-and-readiness)) |
| GET    | `/metrics`                  | Prometheus metrics (opt-in; see [Metrics](#metrics)) |

`{id}` is the opaque `runtime_ref` returned by provisioning. An unknown
`runtime_ref` returns `404` with `{"error": "unknown_runtime_ref", "message": ...}`.

Every error response carries a stable, machine-readable `error` code drawn from a
small closed taxonomy — `invalid_request`, `invalid_spec` (a malformed instance
`spec`), `unknown_runtime_ref`, `invalid_state_transition` (a lifecycle operation
the instance's current status does not allow — see [Lifecycle transitions](#lifecycle-transitions)),
`capacity_exceeded`, `request_too_large`, `rate_limited`, `not_found`,
`method_not_allowed`, and `internal_error`. Each is documented, with its HTTP
status, as the `Error.error` enum in [`openapi/steward.v1.yaml`](openapi/steward.v1.yaml);
branch on it (or, more portably, on the HTTP status) rather than on the
human-facing `message`.

Every response carries an `X-Request-Id` header: a per-request correlation id,
echoed on the matching structured log line (alongside the client's
`remote_addr`) so a control-plane failure report can be tied to the exact
node-side log entry that served it. It is a logging aid, not distributed tracing
— Steward mints a fresh id per request and never propagates a client-supplied
one.

`GET /v1/capabilities` advertises the (still-empty in v1) `skills` array plus a
small slice of operational state for a control-plane dashboard: `version`, the
current `instance_count`, the configured `max_instances` cap, and `durable_state`
(a boolean — whether `-state-file` is set, never the path).

By default state is held in memory only and restarting the process forgets all
tracked instances. Set `-state-file` (or `STEWARD_STATE_FILE`) to persist state
across restarts; see [Run](#run) above.

### Health and readiness

Steward exposes two distinct probes on the inbound listener:

- **`GET /v1/healthz` — liveness.** A `200 {"status": "ok"}` confirms the process
  is up and serving. It deliberately does **not** probe the state file (durable
  state is already fail-closed at startup and on every mutation), so it stays a
  cheap hot-path check.
- **`GET /v1/readiness` — readiness (rolling-deployment safety).** A `200
  {"status": "ready"}` means the instance may receive traffic; a `503
  {"status": "not_ready", "check": "...", "detail": "..."}` names the first gate
  that failed so a load balancer or orchestrator drains a not-yet-warm or
  degraded instance instead of routing to it. Three gates, checked in order:
  1. the instance tracker is initialized;
  2. when the outbound uplink is enabled (`-uplink-url`), it has completed at
     least one successful poll **or** is not in a persistent-failure state (a
     rejected credential, or sustained polling failure with no success yet) — a
     brief transient blip does not flip readiness;
  3. when durable state is enabled (`-state-file`), its directory is writable —
     the capability persistence needs. Unlike the liveness probe, readiness
     deliberately performs this filesystem check, so a state directory gone
     read-only or full drains the instance even though its process is alive.

Both probes live only on the inbound listener; a `-disable-inbound-listener`
(uplink-only) node has neither — its liveness and readiness signal is its
advancing uplink poll logs (see [Uplink client](docs/uplink-client.md)).

### Lifecycle transitions

`start`/`stop`/`hibernate` are validated against the instance's current status.
Re-applying the same operation is an idempotent no-op (starting an already-`RUNNING`
instance returns `200` unchanged — this is what keeps a retried/redelivered
command safe). A transition that assumes a lifecycle step that never happened —
stopping or hibernating a `PENDING` instance that was never started — is rejected
with `409 invalid_state_transition` and the instance is left unchanged, rather
than silently recording a nonsensical status. `provision` stays idempotent on
`instance_id` and `destroy` is always allowed on a live instance, both unchanged.

By default these transitions are pure status changes. With
[process supervision](#process-supervision) enabled, a `command`-bearing instance
also spawns/signals a real OS process on each transition — but the status
semantics above (including idempotency and the `PENDING` guard) are identical.

### Filtered listing

`GET /v1/instances` accepts three optional query-string filters that compose
via AND when combined; omitting all three is byte-for-byte the same
unfiltered response this endpoint always returned:

| Query param           | Matches                                                      |
| ---------------------- | ------------------------------------------------------------ |
| `status`               | Exact match against the `Status` enum (`PENDING`, `RUNNING`, `STOPPED`, `HIBERNATED`, `DESTROYED`, `FAILED`) |
| `instance_id_prefix`   | A plain string prefix of `instance_id`                       |
| `created_since`        | Instances created at or after this RFC3339 timestamp (inclusive) |

An unrecognized `status` or an unparseable `created_since` is a `400`, never a
silently-ignored filter:

```console
$ curl -s 'localhost:8080/v1/instances?status=RUNNING&instance_id_prefix=web-'
{"instances":[{"instance_id":"web-1","runtime_ref":"rt_...","status":"RUNNING","created_at":"2026-07-10T12:00:00Z"}]}
```

### Batch operations

`POST /v1/instances/batch` executes an ordered list of `provision`/`start`/
`stop`/`destroy` operations, one at a time in exactly the given order, and
returns one result per operation. Each operation is executed through the
exact same tracker call its single-instance endpoint uses, so it keeps that
endpoint's own request/response shape and idempotency behavior.

**This is deliberately not a transaction.** A failure in one operation never
blocks the rest of the batch — if operation 3 of 5 fails, 1, 2, 4, and 5 still
run — and every outcome is reported at its own index in `results`, never
silently swallowed. The overall HTTP response is `200` as long as the request
body itself was well-formed; each operation's own success or failure lives in
that entry's own `status`/`instance`/`error` fields. Because operations run
strictly in order against the live tracker, a later operation sees an
earlier one's effect — for example, destroying an `instance_id` and
re-provisioning it within the same batch works.

```console
$ curl -s localhost:8080/v1/instances/batch -d '{
    "operations": [
      {"op": "destroy", "runtime_ref": "rt_old..."},
      {"op": "provision", "instance_id": "agent-1", "spec": {"model": "example"}}
    ]
  }'
{"results":[
  {"op":"destroy","runtime_ref":"rt_old...","status":200,"instance":{...,"status":"DESTROYED"}},
  {"op":"provision","instance_id":"agent-1","status":201,"instance":{...,"status":"PENDING"}}
]}
```

Retrying an entire batch (for example after a client-side timeout left the
outcome ambiguous) is safe to the extent each constituent operation already
is: `provision` stays idempotent on `instance_id`, and `start`/`stop` converge
on the same terminal state either way — but `destroy` is **not** idempotent
across a retry, since it releases the `runtime_ref`; replaying a batch that
already destroyed an instance gets a `404 unknown_runtime_ref` on that
operation the second time, the same outcome a repeated
`DELETE /v1/instances/{id}` would give. See
[`docs/batch-instance-operations.md`](docs/batch-instance-operations.md) for
the full design.

### Example

```console
$ curl -s localhost:8080/v1/instances \
    -d '{"instance_id": "agent-1", "spec": {"model": "example", "memory_mb": 512}}'
{"instance_id":"agent-1","runtime_ref":"rt_...","status":"PENDING","created_at":"2026-07-10T12:00:00Z","spec":{"model":"example","memory_mb":512}}

$ curl -s -X POST localhost:8080/v1/instances/rt_.../start
{"instance_id":"agent-1","runtime_ref":"rt_...","status":"RUNNING","created_at":"2026-07-10T12:00:00Z","spec":{...}}
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
