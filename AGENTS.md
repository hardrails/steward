# Agent contract

Steward has no governance package to hook into — it has zero dependency on
anything private, including the tooling that enforces discipline on its sibling
repos. This document is the substitute: read it before changing code, the same
way you would read a generated `AGENTS.md` elsewhere, except here the guard is
your own discipline plus CI, not a pre-write hook.

## The one invariant that must never regress

**Zero dependency, at build time or runtime, on any private package, API, or
tool.** This is the entire reason Steward is a separate, public repository —
see [README.md](README.md#platforms-and-independence). Before any commit:

```console
$ go list -m all
github.com/hardrails/steward
```

must list only this module. If a change makes this list grow, stop and ask
whether that dependency is actually necessary — the Go standard library covers
everything this service needs today (HTTP server, JSON, mutex-guarded maps,
structured logging via `log/slog`). Do not import a web framework, a
third-party router, or any SDK. Do not add a dependency to make a task
marginally more convenient; the whole point of this repo is that a sovereign
operator with zero trust in any vendor can clone it alone and build it.

## Before you commit

A pre-commit hook at `.githooks/pre-commit` runs `gofmt -l .`, `go vet ./...`,
`go build ./...`, and `go test ./...` against the staged snapshot (not the
working tree — unstaged/untracked changes are autostashed for the check and
restored after) before a commit lands. Enable it once per clone:
`git config core.hooksPath .githooks`.

It deliberately skips `-race`: that's a CI job, not a local one, because it
routinely runs 2-5x slower and a hook slow enough to tempt `--no-verify`
defeats itself. Run `go test -race ./...` yourself before opening a PR,
and always if you touched `internal/runtime` (the mutex-guarded tracker —
exactly what the race detector exists to check). CI's `build / vet / test`
job runs it too and is a required check, so a race can't reach `main` even
if you forget — it'll just cost you a slower feedback loop than doing it
locally first.

`main` is
branch-protected — `build / vet / test`, `golangci-lint`, and `openapi lint`
must all pass before a PR can merge, and force-pushes/deletions are blocked —
so a bypassed local hook does not mean bad code reaches `main`, only that it
takes longer to find out.

## Invariants specific to this codebase

These exist because a reviewer already found and fixed the failure mode once
(see git history / the PR that introduced each). Don't reintroduce them:

- **Every request body is bounded.** `http.MaxBytesReader` wraps every decode
  in `internal/server`. An unbounded body on an unauthenticated-by-design
  service is a one-request OOM — this was found, empirically reproduced (a
  64 MiB body drove RSS from ~12 MB to ~268 MB), and fixed. Any new endpoint
  that reads a body must bound it the same way.
- **The instance tracker has a capacity cap.** `internal/runtime.Tracker` takes
  a `maxInstances` and returns `ErrCapacityExceeded` (mapped to HTTP 503) once
  a *new* instance would exceed it. Don't remove the cap or make it
  effectively unbounded — an unauthenticated loop of distinct `instance_id`s
  is the same OOM shape as the body-size issue, just via instance count
  instead of bytes.
- **The server sets `ReadTimeout`/`WriteTimeout`/`IdleTimeout`**, not just
  `ReadHeaderTimeout`. Headers-fast-then-slow-body is a real DoS shape on an
  unauthenticated service; don't drop these when touching `cmd/steward/main.go`.
- **Every map access in `internal/runtime` is inside the tracker's single
  mutex.** No check-then-act window between reading `byID`/`byRef` and
  mutating them — that's exactly the shape a double-provision or a
  zombie-resurrection-after-destroy bug would take. If you touch this file,
  the concurrency test (`TestConcurrentProvisionCreatesOnlyOne`, run with
  `-race`) must still pass, and stay meaningful — don't loosen it to make a
  change easier.
- **`Provision` is idempotent on `instance_id`**, and that idempotency is
  scoped to the instance's lifetime, not global: `Destroy` releases the id for
  reuse, so a `Provision` after a `Destroy` creates a new, unrelated instance
  with a fresh `runtime_ref` (documented on `Destroy` itself — read that
  comment before changing either function).
- **Every error response is the same JSON shape**
  (`{"error": "...", "message": "..."}`), including the stdlib mux's default
  404/405 (rewritten by `jsonErrors` middleware) and a recovered panic
  (`recoverMiddleware`, → 500). `openapi/steward.v1.yaml` documents this
  shape on every operation. If server behavior and the spec ever disagree,
  that is a defect in one of them — fix the mismatch, don't let a new
  endpoint skip documenting its real error responses.
- **Operator errors identify the failed boundary.** Do not reuse an
  availability code for a durable digest mismatch, or collapse an observed
  upstream HTTP rejection into permit reuse. Keep response bodies secret and
  bounded, but preserve safe evidence such as the boundary, HTTP status, and
  recovery action. Tests must cover both the first failure and replay.
- **Admission reconfiguration is patch-like.** Omitted compatibility choices
  preserve their installed values. Disabling one requires its explicit
  `--disallow-*` option, and a malformed prior value is an error. Any new
  security-sensitive configurator option needs a rerun regression test.
- **Built-in runtime profiles have one source of truth.** Executor admission,
  `agent publish`, capsule preflight, and the runtime-profile reference must
  agree. `TestRuntimeProfileReferenceMatchesBuiltInRegistry` is the change gate.
- **A reconciliation escape hatch may only narrow authority.** Missing-workload
  destroy recovery requires one exact `workload_missing` failure, no pending
  journal, an authorized signed fence, repeated proof of absence, and exact
  identity checks before removing deterministic residual topology. Never turn
  `--force` into adoption, recreation, or unverified deletion.

## The public contract is load-bearing

[`openapi/steward.v1.yaml`](openapi/steward.v1.yaml) is what a sovereign
customer's own auditor reads to decide whether to trust this service. If you
change request/response shapes, status codes, or add an endpoint, update the
spec in the same change — CI lints it, but lint only catches malformed YAML,
not spec/behavior drift. Read the response your handler actually sends before
declaring the spec update done.

`scripts/check-cli-docs-contract.sh` also builds `stewardctl` and rejects any
documented command/subcommand pair absent from that exact source tree. CI and the
release builder both run it. GitHub Pages follows current source and must retain
its visible version-matching warning; tagged docs and tagged binaries are the
authoritative matched pair for an installed release.

## Computer-use stays out of this process

See [ARCHITECTURE.md](ARCHITECTURE.md#deferred-decision-computer-use-is-a-separate-worker-never-in-process).
Do not add command execution, sandboxing, or any agent-capability code to this
repository's own process, even experimentally. That decision has two
independent reasons (dependency purity, isolation) and both still hold.
