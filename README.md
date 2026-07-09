# Steward

Steward is a minimal, always-running **lifecycle supervisor for agent instances**
that runs on a node. It tracks the lifecycle of agent instances — provision,
start, stop, hibernate, destroy, and status — behind a small HTTP API, and does
nothing else. It is designed to be managed remotely over HTTP by a separate
control plane.

Steward is deliberately a *walking skeleton*: lifecycle tracking only, no command
execution, no sandboxing, no persistence. See [ARCHITECTURE.md](ARCHITECTURE.md)
for the design boundaries and the deferred decisions (notably how a future
computer-use capability is kept out of Steward's own process).

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

## API at a glance

| Method | Path                        | Operation                                   |
| ------ | --------------------------- | ------------------------------------------- |
| POST   | `/v1/instances`             | Provision (idempotent on `instance_id`)     |
| GET    | `/v1/instances/{id}`        | Status                                      |
| POST   | `/v1/instances/{id}/start`  | Start                                       |
| POST   | `/v1/instances/{id}/stop`   | Stop                                        |
| POST   | `/v1/instances/{id}/hibernate` | Hibernate                                |
| DELETE | `/v1/instances/{id}`        | Destroy                                     |
| GET    | `/v1/capabilities`          | Capabilities (`{"skills": []}` in v1)       |

`{id}` is the opaque `runtime_ref` returned by provisioning. An unknown
`runtime_ref` returns `404` with `{"error": "unknown_runtime_ref", "message": ...}`.

State is held in memory only; restarting the process forgets all tracked
instances.

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
