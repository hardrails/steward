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
| `-state-file`              | `STEWARD_STATE_FILE`              | (unset)          | path to a JSON file for durable state; unset means in-memory only       |
| `-uplink-url`              | `STEWARD_UPLINK_URL`              | (unset)          | control-plane base URL for the outbound uplink; unset disables it       |
| `-uplink-credential-file`  | `STEWARD_UPLINK_CREDENTIAL_FILE`  | (unset)          | path to the node's uplink credential JSON; required when `-uplink-url` is set |
| `-uplink-poll-interval`    | `STEWARD_UPLINK_POLL_INTERVAL`    | `10s`            | base cadence for uplink polling; jitter is applied on top; clamped to a 5-minute ceiling (the failed-poll backoff cap) |
| `-disable-inbound-listener` | `STEWARD_DISABLE_INBOUND_LISTENER` | `false`          | do not bind an inbound listener; requires `-uplink-url`                |
| `-config`                  | `STEWARD_CONFIG`                  | (unset)          | path to a JSON [config file](#config-file) supplying any of the settings above; a flag or env var overrides it |

`-version` and `-check-config` are action flags rather than settings (they have no
env var):

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

## Config file

Any setting can live in a JSON config file, pointed at by `-config` (or
`STEWARD_CONFIG`). It is the lowest-precedence layer: a flag or an env var always
overrides the same key in the file (**flag > env var > config file**). Keys are
`snake_case` — the same names as the `STEWARD_`-prefixed env vars, minus the
prefix — and every key is optional; an omitted key falls back to its env var,
flag, or built-in default. `uplink_poll_interval` is a Go duration string (e.g.
`"30s"`, `"1m30s"`).

```json
{
  "addr": "0.0.0.0:8080",
  "max_instances": 512,
  "log_level": "info",
  "state_file": "/var/lib/steward/state.json",
  "uplink_url": "https://control-plane.example",
  "uplink_credential_file": "/etc/steward/uplink-credential.json",
  "uplink_poll_interval": "30s",
  "disable_inbound_listener": false
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

## API at a glance

| Method | Path                        | Operation                                   |
| ------ | --------------------------- | ------------------------------------------- |
| POST   | `/v1/instances`             | Provision (idempotent on `instance_id`)     |
| GET    | `/v1/instances`             | List tracked instances (sorted by `runtime_ref`) |
| GET    | `/v1/instances/{id}`        | Status                                      |
| POST   | `/v1/instances/{id}/start`  | Start                                       |
| POST   | `/v1/instances/{id}/stop`   | Stop                                        |
| POST   | `/v1/instances/{id}/hibernate` | Hibernate                                |
| DELETE | `/v1/instances/{id}`        | Destroy                                     |
| GET    | `/v1/capabilities`          | Advertised skills + operational info        |
| GET    | `/v1/healthz`               | Liveness probe (`{"status": "ok"}`)         |

`{id}` is the opaque `runtime_ref` returned by provisioning. An unknown
`runtime_ref` returns `404` with `{"error": "unknown_runtime_ref", "message": ...}`.

Every response carries an `X-Request-Id` header: a per-request correlation id,
echoed on the matching structured log line (alongside the client's
`remote_addr`) so a control-plane failure report can be tied to the exact
node-side log entry that served it. It is a logging aid, not distributed tracing
— Steward mints a fresh id per request and never propagates a client-supplied
one.

`GET /v1/capabilities` advertises the (still-empty in v1) `skills` array plus a
small slice of operational state for a control-plane dashboard: `version`, the
current `instance_count`, the configured `max_instances` cap, and `durable_state`
(a boolean — whether `-state-file` is set, never the path). `GET /v1/healthz` is a
liveness probe returning `{"status": "ok"}`; it confirms the process is up and
serving and deliberately does not probe the state file (durable state is already
fail-closed at startup and on every mutation).

By default state is held in memory only and restarting the process forgets all
tracked instances. Set `-state-file` (or `STEWARD_STATE_FILE`) to persist state
across restarts; see [Run](#run) above.

### Example

```console
$ curl -s localhost:8080/v1/instances \
    -d '{"instance_id": "agent-1", "spec": {"model": "example", "memory_mb": 512}}'
{"instance_id":"agent-1","runtime_ref":"rt_...","status":"PENDING","spec":{"model":"example","memory_mb":512}}

$ curl -s -X POST localhost:8080/v1/instances/rt_.../start
{"instance_id":"agent-1","runtime_ref":"rt_...","status":"RUNNING","spec":{...}}
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
