---
title: Disabling the inbound listener
description: Design rationale and safety invariants for running Steward in outbound-only mode without binding any inbound management socket.
section: Design record
---

# Design: disabling the inbound listener (a bind-nothing-inbound flag for uplink-only nodes)

Status: **implemented; design provenance.** This document records the shape
chosen, the shapes rejected, the invariants the design must hold, and the exact
task list that was implemented. It follows the same style as
[ARCHITECTURE.md](https://github.com/hardrails/steward/blob/main/ARCHITECTURE.md), [`docs/uplink-client.md`]({{ '/uplink-client/' | relative_url }}),
and [`docs/instance-generation-fencing.md`]({{ '/instance-generation-fencing/' | relative_url }}): it
explains not just *what* but *why*, and it names the failure mode each decision
closes.

This is a pure `cmd/steward` **wiring** change. It adds one startup flag and its
guard; it touches no HTTP handler, no tracker method, and no uplink code, because
the uplink poll loop already drives the tracker in-process and does not depend on
the inbound listener (see [Why this is safe](#why-this-is-safe-the-uplink-does-not-use-the-inbound-listener)).
`openapi/steward.v1.yaml` is unchanged: the flag adds no endpoint, request/response
shape, or status code.

## Why this exists

[`docs/uplink-client.md`]({{ '/uplink-client/' | relative_url }}#deliberately-deferred) names this as a
deliberately-deferred follow-up:

> **Disabling the inbound listener entirely.** v1 always starts the HTTP listener
> (loopback by default) even in "uplink-only" deployments, for local health checks.
> A flag to bind nothing inbound is a plausible follow-up but is not v1.

Steward supports two ways in, and today only one of them can be turned off:

- **Direct-REST mode** (`-uplink-url` unset). The control plane dials *into* the
  node's inbound HTTP listener (`-addr`, default `127.0.0.1:8080`). That listener
  serves the *entire* fleet API — `POST /v1/instances`, `start` / `stop` /
  `hibernate` / `destroy` / status, plus `GET /v1/capabilities` and
  `GET /v1/healthz` (`internal/server/server.go`, the `Handler()` mux). This mode
  **needs** the inbound listener; it is the only way in.
- **Uplink mode** (`-uplink-url` set). The node dials *out* to the control plane,
  polls for queued commands, and executes them against its local tracker. The
  control plane never opens a socket to the node — that is the whole point of the
  uplink for a NAT'd or firewalled node. In this mode the inbound listener is not
  needed for fleet operations.

**Confirmed from the code, not assumed:** `cmd/steward/main.go` builds the
`http.Server` and calls `srv.ListenAndServe()` in a goroutine **unconditionally**
(the `srv := &http.Server{…}` block and the `go func(){ … ListenAndServe() }()`
below it), *after* and *independent of* the `if *uplinkURL != "" { … }` block that
wires the poller. There is no branch that skips the listener when the uplink is on.
So a uplink-only node today still binds `127.0.0.1:8080` on loopback, even though
nothing external can — or should — reach it there.

For a sovereign/enterprise node whose reason for using the uplink is precisely that
inbound connections are impossible or unwanted, binding an inbound socket at all is
surplus surface: an open port on the node (loopback by default, but an operator can
point `-addr` at a routable interface), one more thing to reason about in an audit,
and a listener that exists only to answer a health probe that a uplink-only node's
supervisor does not need over HTTP. This flag lets such a node **bind nothing
inbound**.

## Why this is safe: the uplink does not use the inbound listener

The correctness pre-condition for this whole change is that turning off the inbound
listener leaves the uplink fully functional. It does, and this is structural, not
incidental:

- `cmd/steward/main.go` builds the poller with `uplink.NewPoller(tracker, …)` and
  runs it with `poller.Run(ctx)` — it is handed the **tracker**, not an HTTP client
  pointed at the local server.
- `internal/uplink` polls the **control plane** over its own outbound `http.Client`
  (`pollURL` / `reportURL` derived from `-uplink-url`) and applies each command by
  calling the same `internal/runtime.Tracker` methods the REST handlers call, behind
  the same single mutex. ARCHITECTURE.md already states this: the uplink is "a second
  caller of the same tracker, not a second lifecycle engine."

So the inbound listener and the uplink are two independent front doors onto one
tracker. Removing the inbound door does not touch the outbound one.

## What stays true (invariants)

- **Off by default; today's behavior is the default.** With the flag unset, startup
  is byte-for-byte what it is today: the listener binds `-addr` and logs
  `steward listening`, whether or not the uplink is also enabled. This is a
  regression the test list pins explicitly.
- **A node is never left unreachable.** A node with no inbound listener *and* no
  outbound uplink can neither be dialed nor dial out — it is a dark, useless
  process. Starting one is a **fail-closed startup error**, the same discipline
  Steward already applies to a bad `STEWARD_UPLINK_POLL_INTERVAL`, a missing uplink
  credential, and a malformed `-uplink-url` (`internal/uplink.NewPoller`). There is
  no "silently launched but unreachable" path.
- **Additive, opt-in, zero new dependency, unchanged contract.** The change is one
  `flag.Bool`, its `STEWARD_`-prefixed env twin, and a five-line `envOrBool` helper
  mirroring the existing `envOrInt` — standard library only. It adds no endpoint and
  changes no request/response shape, so `openapi/steward.v1.yaml` is untouched.
  Disabling the listener is a **deployment-mode** concern (which front doors a node
  opens), exactly as durable state is: the spec describes the inbound API a node
  serves *when it serves inbound*, and a uplink-only node simply does not expose it.
- **One front door minimum, enforced at startup.** After this change the startup
  guard reads as a single rule: *a node must open at least one door* — the inbound
  listener, the outbound uplink, or both. The three other combinations
  (listener-only, uplink-only, both) are all valid; only "neither" is refused.

## The shape chosen

### The flag: `-disable-inbound-listener` (boolean, opt-out), env twin `STEWARD_DISABLE_INBOUND_LISTENER`

A boolean flag, default `false`, whose `true` value skips building and starting the
`http.Server` entirely:

```
-disable-inbound-listener   STEWARD_DISABLE_INBOUND_LISTENER   (default false)
    do not bind an inbound HTTP listener; requires -uplink-url. All fleet
    operations then flow through the outbound uplink poll loop only.
```

Its default comes from `envOrBool("STEWARD_DISABLE_INBOUND_LISTENER", false)`, a new
helper alongside `envOr` / `envOrInt` / `envDuration`. `envOrBool` mirrors
`envOrInt`'s posture — a set-but-unparseable value falls back to the default (here,
`false`) rather than failing closed — and that is the *correct* fallback direction
here: a typo (`STEWARD_DISABLE_INBOUND_LISTENER=ture`) falls back to **listener
enabled**, which is the safe, reachable state, and the genuinely-dangerous case
(no listener *and* no uplink) is caught independently by the startup guard below.
This is a deliberate departure from `envDuration`'s fail-closed-on-bad-value rule,
which exists because a wrong *duration* is silently harmful; a wrong *bool* here
falls back to the safe side.

### Interaction rules (the crux)

| `-disable-inbound-listener` | `-uplink-url` | Outcome |
| --- | --- | --- |
| unset (default) | unset | **Today's behavior.** Listener binds `-addr`; no uplink. |
| unset (default) | set | **Today's behavior.** Listener binds `-addr`; uplink also runs (both doors open). |
| **set** | **unset** | **Fail closed at startup.** `os.Exit(1)` with a message naming the contradiction and both fixes. A node with neither door is unreachable. |
| **set** | **set** | **The intended mode.** No inbound listener is built; all fleet operations flow through the uplink poll loop. |

1. **Set + no uplink → fail closed.** Before building the server, if
   `*disableInbound && *uplinkURL == ""`, Steward logs an actionable error and exits
   non-zero — it does *not* start. The message names the problem and both remedies,
   in the same `logger.Error(msg, "hint", …)` + `os.Exit(1)` shape the uplink
   credential check already uses, e.g.:

   > `inbound listener disabled but no uplink configured` — hint: *a node with
   > neither an inbound listener nor an outbound uplink is unreachable; set
   > `-uplink-url` (or `STEWARD_UPLINK_URL`) to poll a control plane, or drop
   > `-disable-inbound-listener` to serve the inbound REST API.*

2. **Set + uplink → skip the listener.** The `srv := &http.Server{…}` value and the
   `go func(){ … ListenAndServe() }()` goroutine are not created. Startup logs a
   single clear line in place of `steward listening`, e.g.
   `logger.Info("inbound listener disabled; serving via uplink only", "version", server.Version)`.
   That line is the successful-startup / readiness signal (and the integration
   test's readiness marker).

3. **Unset → unchanged.** The listener is built and started exactly as today.

4. **Interaction with `-addr`.** When the listener is disabled, `-addr` is simply
   unused — nothing binds it. `-addr` keeps its single, unchanged meaning ("where to
   listen *when* listening"); this flag never overloads it. If an operator sets both
   `-addr` and `-disable-inbound-listener`, the disable wins and the "inbound listener
   disabled" log line makes the ignored `-addr` visible. (No `flag.Visit` bookkeeping
   to detect an explicitly-set `-addr` is warranted — the single log line is enough
   to surface the situation.)

### Graceful shutdown with no server

Today's shutdown block calls `srv.Shutdown(shutdownCtx)` unconditionally. With the
listener disabled there is no `srv`, so the implementation **must guard that call**
(`if srv != nil { … }`) or a nil-pointer panic replaces a clean shutdown. The rest
of the shutdown path is already correct for a server-less process: `<-ctx.Done()`
still waits for `SIGINT`/`SIGTERM`, and the existing `uplinkDone` block waits for the
poll loop to drain within the shutdown deadline. This is the one non-obvious
correctness point in the change and is pinned by the shutdown assertion in the test
list.

### Health and readiness when the listener is disabled — named, not left silent

Disabling the listener removes the local `GET /v1/healthz` probe (and
`GET /v1/capabilities`), because those are served *by* the inbound listener. The
deferred note calls out "local health checks" as the reason v1 kept the listener, so
this must be answered explicitly rather than dropped:

- **The uplink poll loop's logging is the liveness signal.** The poller logs each
  poll outcome (OK / transient / skew / fatal) and logs `uplink enabled` at startup;
  a fatal `401`/`403` stops the loop with a loud, actionable log. A local supervisor
  (systemd, a container runtime) already treats *process alive + poll logs advancing*
  as liveness, and *process exited* as failure. This is the model a uplink-only node
  is on anyway: it is behind NAT/firewall, so nothing external can reach a loopback
  `/v1/healthz` — the only caller of that probe is a co-located supervisor, and a
  co-located supervisor can watch the process and its logs directly.
- **Startup emits a clear success line** (rule 2 above), so "the node came up
  cleanly" is observable in logs even without `steward listening`.
- **What is lost is stated, not hidden.** A uplink-only node has no local HTTP
  health/capabilities endpoint. An operator who *wants* a local HTTP health probe
  simply does not pass `-disable-inbound-listener`: the default loopback listener
  (today's behavior) stays, and it costs one bound loopback port. The flag is the
  operator's explicit, documented trade — one open port for a local health endpoint
  vs. zero inbound surface — not a silent gap.

## Shapes rejected

1. **Reuse `-addr` with an empty value (`-addr=""` = don't bind).** This looks like
   the house "empty string disables the feature" idiom (`-state-file=""`,
   `-uplink-url=""`), and reusing an existing flag is attractive, but it is a false
   match and is rejected:
   - **It breaks the env-var uniformity contract.** README states "Every setting is a
     flag with a matching `STEWARD_`-prefixed env var." But `envOr("STEWARD_ADDR",
     default)` collapses an empty env value to the default (`TestEnvOr` pins
     "empty value falls back"), so `STEWARD_ADDR=""` *cannot* express "off" — the
     env twin would silently keep the listener on. Fixing that means special-casing
     `-addr`'s env handling (`os.LookupEnv`, distinguishing unset from empty), which
     is *more* code and *more* subtlety than a clean boolean.
   - **It inverts the idiom's default polarity.** For `-state-file` / `-uplink-url`,
     empty is the *default and safe off* state; for `-addr` the default is *non-empty*
     and off is a deliberate action. Same surface, opposite semantics — a subtle trap
     for a reader who expects "empty = the default."
   - **It overloads `-addr` and invites a silent accident.** A templating bug that
     renders an empty `-addr` would silently disable inbound. (The fail-closed guard
     catches the truly-unreachable case, but a boolean can't be tripped by an *empty*
     value at all.) A dedicated boolean is explicit, self-documenting in a systemd
     unit, keeps `-addr`'s meaning intact, and has a clean env twin.

2. **Keep a health-only loopback listener when "disabled."** Bind nothing for the
   fleet API but still serve `/v1/healthz` on loopback. Rejected: it reintroduces the
   exact inbound socket the flag exists to remove — the deferred item is literally
   titled "bind nothing inbound" — and the loopback probe is only reachable by a
   local supervisor that can already watch the process and poll logs. It is cost
   (a second server config, a still-open port) without the isolation benefit.

3. **Let a listener-less, uplink-less node start (fail open).** Rejected: it is a
   fully unreachable, useless process, and the fail-closed startup discipline the
   repo applies to every other misconfiguration (bad duration, missing credential,
   malformed URL) applies here too. Neither door open is a configuration error the
   operator must see and fix, not a silent dark start.

4. **Name the flag `-uplink-only`.** Rejected as a misnomer: the flag does not enable
   the uplink (you still need `-uplink-url`), it only disables the inbound listener.
   `-disable-inbound-listener` says exactly what it does.

## Buy vs build

No dependency question arises. The change is `flag.Bool` from the standard library
plus a five-line `envOrBool` helper mirroring the existing `envOrInt` — no new
module, honoring the zero-private-dependency and standard-library-only invariant. The
"reuse" alternative (overloading `-addr`) is rejected above on its own merits, not on
dependency grounds.

## Task list (ordered, each with its acceptance check)

All tasks land in `cmd/steward` (wiring). No `internal/*` package changes.

1. **Add the flag and its env twin.** Add `-disable-inbound-listener`
   (`flag.Bool`, default `envOrBool("STEWARD_DISABLE_INBOUND_LISTENER", false)`) to
   the flag block, and add the `envOrBool` helper next to `envOrInt`
   (`strconv.ParseBool`; a set-but-invalid value falls back to the default, matching
   `envOrInt`). *Check:* `go build ./...`, `go vet ./...`; a `TestEnvOrBool`
   mirroring `TestEnvOrInt` (unset → false; `"true"`/`"1"` → true; invalid →
   fallback). Gate: `build / vet / test` CI job.

2. **Fail-closed guard.** Before building the server, if
   `*disableInbound && *uplinkURL == ""`, `logger.Error(…)` with a hint naming both
   remedies and `os.Exit(1)`. *Check:* an integration test (build the binary, run it
   with `-disable-inbound-listener` and no `-uplink-url`) asserts a non-zero exit
   (`exec.ExitError`) and that the output names both `-disable-inbound-listener` and
   `-uplink-url` — mirroring `TestUplinkBadCredentialExitsNonZero`. Gate:
   `build / vet / test`.

3. **Conditionally skip the listener + guard shutdown.** When `*disableInbound`, do
   not build `srv` or start the `ListenAndServe` goroutine; log
   `inbound listener disabled; serving via uplink only` (with `version`) instead of
   `steward listening`. Guard the shutdown call: `if srv != nil { srv.Shutdown(…) }`.
   *Check:* an integration test starts the binary with `-disable-inbound-listener
   -uplink-url http://127.0.0.1:1 -uplink-credential-file <valid>` (the URL is
   syntactically valid and never actually dialed), scans stdout for the
   `inbound listener disabled` line, asserts the process stays up (does not exit)
   within a window and that `steward listening` never appears, then sends `SIGTERM`
   and asserts a clean (zero) exit with no panic. Gate: `build / vet / test` (with
   `-race`).

4. **Regression guard (flag unset).** *Check:* an integration test confirms that
   without the flag, startup is exactly today's — the listener binds and
   `steward listening` is logged — in both the uplink-off and uplink-on configs.
   (Can extend the existing `-addr 127.0.0.1:0` start pattern.) Gate:
   `build / vet / test`.

5. **Docs.** Add a README flags-table row (`-disable-inbound-listener` /
   `STEWARD_DISABLE_INBOUND_LISTENER` / `false` / "do not bind an inbound listener;
   requires `-uplink-url`") plus a short prose note; and flip the "Disabling the
   inbound listener entirely" bullet in `docs/uplink-client.md`'s "Deliberately
   deferred" list to point at this now-designed doc (the way the fencing follow-up
   was handled). The ARCHITECTURE.md subsection ships with the design (this commit).
   *Check:* `spectral lint` still passes on the unchanged spec (no spec change);
   prose review. Gate: `openapi lint` job (vacuously green) + review.

The full battery for the change is the three required CI jobs:
`go build ./...`, `go vet ./...`, `go test -race ./...`, plus `golangci-lint` and
`spectral lint` (`.github/workflows/ci.yml`).

## What this deliberately does not solve

- **Runtime toggling.** The flag is read once at startup, like every other Steward
  setting. Flipping between "listening" and "uplink-only" is a restart, not a live
  reconfiguration.
- **A local non-HTTP liveness channel** (e.g. a unix-socket ping or a readiness
  file). A supervisor watching the process and the poll logs is sufficient for the
  uplink-only case; a dedicated local liveness channel is a separate follow-up if a
  real operator need appears, not speculative surface added now.
- **Binding the fleet API and the health probe on separate listeners** (so one could
  be kept while the other is dropped). Rejected above as reintroducing the inbound
  socket this flag exists to remove; not revisited here.
