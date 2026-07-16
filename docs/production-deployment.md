---
title: Production deployment
description: Production rollout guidance for Steward configuration, credentials, networking, observability, process supervision, shutdown, and recovery.
section: Operator guide
---

# Production deployment

This guide covers the production settings and procedures for the generic `steward`
supervisor: configuration validation, networking, credentials, rate limits,
observability, live capacity changes, shutdown, and health checks. See the
[configuration reference]({{ '/reference/configuration/' | relative_url }}) for
every setting and [ARCHITECTURE.md](https://github.com/hardrails/steward/blob/main/ARCHITECTURE.md)
for design constraints. Install a pinned package by following the
[installation guide]({{ '/getting-started/' | relative_url }}).

<div class="callout warning">
  <strong>Supervisor uplink scope</strong>
  This page documents the generic <code>steward</code> supervisor and its
  tenant-scoped credential. Do not reuse its unsigned command contract for a
  multi-tenant Executor. Executor requires a node-scoped transport credential,
  verified HTTPS, complete signed admission, tenant-signed normal commands, and a
  site-owned cleanup key restricted to stop/destroy/purge. See the <a href="{{ '/executor/' | relative_url }}#outbound-executor-uplink">Executor uplink contract</a>.
</div>

Steward supports two network topologies:

- **Direct REST:** a control plane connects to the inbound API. The API has no
  built-in authentication or TLS. Keep it on loopback or place it behind a
  mutually authenticated TLS proxy and restrictive firewall; never expose it
  directly to an untrusted network.
- **Outbound uplink:** a node behind network address translation (NAT) or a
  firewall polls the control plane. The node needs no inbound port. This guide
  gives this topology more detail because it uses credential reload and uplink
  backpressure controls.

## Configure a production node

Put supported file-backed settings in JSON and pass the file with `-config` or
`STEWARD_CONFIG`. Rate limiting, metrics, and the audit-log path remain
flag/environment-only settings. The [configuration reference]({{ '/reference/configuration/' | relative_url }})
defines exact sources and precedence.

Prefer a checked-in, validated config file per node or node class. Keep each
node's credential in a separate file rather than embedding it in configuration.
For an uplink-only node:

```json
{
  "uplink_url": "https://control-plane.example",
  "uplink_credential_file": "/etc/steward/uplink-credential.json",
  "uplink_poll_interval": "30s",
  "state_file": "/var/lib/steward/state.json",
  "disable_inbound_listener": true,
  "log_level": "info"
}
```

Every flag has a default, but these combinations are validated at startup:

- Setting `-uplink-url` also requires `-uplink-credential-file`. A credential path
  without a URL is accepted but unused because the uplink remains disabled.
- `-disable-inbound-listener` requires `-uplink-url`; otherwise the node would
  have no management path.

Defaults for `-max-instances`, `-max-requests-per-second`, `-log-level`,
`-uplink-poll-interval`, and `-uplink-command-queue-depth` are usable without
tuning. Change them from observed workload data, not expected traffic alone.

## Validate configuration with `-check-config`

`-check-config` runs the same fail-closed validation used at startup, including a
`-config` file, then exits without binding a port, loading state for service, or
starting the uplink:

```console
$ steward -check-config -config /etc/steward/config.json
configuration valid
```

Run it before distributing configuration. It rejects unknown JSON keys, malformed
durations, non-positive `max_instances` or `uplink_command_queue_depth`, and
`disable_inbound_listener: true` without `uplink_url`.

Steward writes all structured logs to **stdout**, including validation errors.
Automation must use the exit code, not the output stream, to determine success.

## Validate configuration structure with `-schema`

Use `-schema` earlier in the delivery pipeline to emit JSON Schema draft 2020-12:

```console
$ steward -schema > steward.config.schema.json
```

The schema sets `additionalProperties: false`, requires positive
`max_instances` and `uplink_command_queue_depth`, and expresses
`uplink_url` => `uplink_credential_file` and
`disable_inbound_listener: true` => `uplink_url`. Steward derives it from its
config struct, so new file-backed settings appear automatically.

Validate rendered files against this schema in CI/CD, then run `-check-config`
on the node. The schema catches structure errors offline. `-check-config` also
checks node-specific conditions such as credential-file presence; whether an
existing state file is owner-only and has no extended access-control list (ACL);
`-addr`; root process execution; and a resolved non-loopback process-execution
listener. It validates address syntax and policy but does not bind a socket, so it
cannot prove that an address is available.

The schema has two documented simplifications:

- `log_level` lists lowercase `debug`, `info`, `warn`, and `error`. The parser
  also accepts other casing and surrounding whitespace, such as `"INFO"`.
  JSON Schema has no portable case-insensitive enum, so render lowercase values
  to avoid a schema-only rejection.
- `uplink_poll_interval` is a string because Go durations such as `"30s"` have
  no native JSON type. The schema does not encode duration syntax;
  `-check-config` remains authoritative.

## Network exposure

An outbound-uplink node needs no inbound port. The supervisor polls
`-uplink-url`. Enabling the uplink does not open an additional listener, but the
default loopback listener remains active until `-disable-inbound-listener` is set.
The inbound API and outbound uplink are independent callers of the same lifecycle
tracker; see
[outbound uplink design](https://github.com/hardrails/steward/blob/main/ARCHITECTURE.md#outbound-uplink).

Keep the inbound listener for either of these uses:

- direct REST management; or
- local health and administration on an uplink node: `GET /v1/healthz`,
  `GET /v1/readiness`, `GET /v1/capabilities`, and, with `-enable-metrics`,
  `GET /metrics`.

The default `-addr` is loopback-only at `127.0.0.1:8080`. If systemd, a container
runtime, or another supervisor can monitor the process and stdout directly, set
`-disable-inbound-listener` or `STEWARD_DISABLE_INBOUND_LISTENER`. Steward then
constructs no `http.Server` and binds nothing. It rejects this setting without
an uplink. See [Disable the inbound listener]({{ '/disable-inbound-listener/' | relative_url }}).

For an uplink-only node, allow outbound HTTPS to `-uplink-url`; do not open an
inbound firewall port for Steward.

## Provision and rotate the supervisor credential

### Initial provisioning

The uplink credential authenticates the node to the control plane. It does not add
authentication to the inbound API. Enrollment provides a versioned JSON file:

```json
{
  "version": 1,
  "tenant_id": "acme",
  "node_id": "node-7",
  "credential": "<opaque bearer token minted at enrollment>"
}
```

Write it to the path named by `-uplink-credential-file`. Steward sends
`credential` unchanged in the `Authorization` header. At startup,
Steward requires an owner-only regular credential file of at most
64 KiB. It rejects a missing file, symlink, group/other permissions, a file that
changes while being opened, invalid JSON, the wrong `version`, or empty
`tenant_id`, `node_id`, or `credential`. It does not silently disable the uplink.
Store the file as `0600`, owned by the service user; Steward does not set its
permissions.

Protect `-state-file` the same way when durable state is enabled. Steward creates
new snapshots as owner-only files and rejects any existing state file that is
accessible by group or other users or has an extended access-control list (ACL).
Keep it `0600`, ACL-free, and owned by the dedicated Steward account. With
`-enable-process-exec`, the file also contains each instance `spec`, including
`spec.env`, in cleartext.

Process execution also rejects root and a listener reachable beyond loopback.
Run as an unprivileged account and prefer an authenticated outbound uplink with
`-disable-inbound-listener`. `-allow-root-process-exec` and
`-allow-nonloopback-process-exec` are dangerous acknowledgements for exceptional
deployments; each produces a warning.

### Rotation without downtime

After the control plane returns `401` or `403`, `Poller.Run` pauses and rereads
`-uplink-credential-file` until it finds a valid replacement for the same node.
It then resumes without a restart. The watch is reactive: changing the file alone
does not replace the in-memory credential before a rejection.

For planned rotation:

1. Mint the replacement and atomically write it to the credential path using a
   temporary file and rename in the same directory.
2. Revoke the old credential at the control plane.

The next poll is rejected, then the watcher reads the staged file. Steward checks
every five seconds; no flag changes this interval. The rotation window is therefore
about one poll attempt plus at most five seconds.

A transiently absent, truncated, or invalid replacement is logged at `DEBUG` and
retried. A different `node_id` is rejected and logged at `ERROR`; changing node
identity is re-enrollment and requires a restart. If the replacement is also
rejected, Steward returns to the same wait cycle indefinitely. For a compromised
credential, control-plane revocation is the security action; installing the new
file is recovery. See [Node credential]({{ '/uplink-client/' | relative_url }}#node-credential).

## Inbound rate limiting

The unauthenticated inbound listener uses a token bucket per client IP. The
default allows `20` requests per second per source with a burst of `40`. Excess
requests receive `429 Too Many Requests` and `Retry-After` before handler work,
so retrying them is safe.

This control applies only when the listener exists. It is an additional safeguard,
not the primary protection, on the default loopback address and becomes important
when `-addr` is network-reachable.

- Bulk provisioning from one control-plane replica can exceed the burst. Raise
  `-max-requests-per-second` or `STEWARD_MAX_REQUESTS_PER_SECOND` from measured
  demand. Setting it to `0` disables the limiter and is appropriate only when a
  trusted fronting gateway already enforces a limit.
- The key is the real TCP peer, never `X-Forwarded-For`. A client could forge that
  header on an unauthenticated listener. Replicas or proxies sharing one egress IP
  therefore share a bucket; raise the node limit or rate-limit at the proxy.
- The source map is capacity-bounded and idle entries are swept, preventing
  unbounded memory growth during a many-IP flood. Exact internal bounds are in
  `internal/server/ratelimit.go`; operators do not tune them.

## Metrics and command audit log

Both features are opt-in. The
[configuration reference]({{ '/reference/configuration/' | relative_url }}) lists
their flags. This section defines the metric names and JSON Lines record shape.

With `-enable-metrics`, `GET /metrics` uses the same listener and `-addr` as the
API. There is no separate metrics port:

```yaml
scrape_configs:
  - job_name: steward
    static_configs:
      - targets: ["node-host:8080"]
    metrics_path: /metrics
```

An uplink-only node with `-disable-inbound-listener` has no scrape endpoint, and
`-enable-metrics` has no effect. Monitor it from the control-plane side or through
an external host monitor. The endpoint also shares the per-source rate limiter.
A 15–60 second scrape interval fits comfortably within the default budget, but a
scraper and lifecycle traffic from the same IP share one bucket.

Uplink metrics expose queue pressure:

- `steward_uplink_command_queue_depth` measures queued plus in-flight commands.
- `steward_uplink_command_queue_max_depth` reports the
  `-uplink-command-queue-depth` cap.
- `steward_uplink_commands_rejected_total` grows when a poll exceeds that cap.

A depth held at the cap or a steadily growing rejection counter means work is
arriving faster than the node executes it. Durable per-command state writes are a
common bottleneck when `-state-file` is set. Sustained backlog makes
`GET /v1/readiness` fail until the queue drains. Raise the default cap of `256`
only for a legitimate burst the node can absorb. A rejected command is not
reported. Its control-plane claim lease must expire before the control plane can
redeliver it, so a small count during a spike is healthy backpressure, not data
loss.

`-audit-log-file` appends one JSON object per line. Steward does not rotate or
truncate the file; configure journald, Fluent Bit, OpenTelemetry `filelog`, or
another shipping agent to do so. It records only uplink-dispatched commands,
because direct REST requests have no `command_id`. On a direct-REST-only node,
the flag creates the file but writes no records and logs a `WARN`.

## Reload `max_instances` with `SIGHUP`

`SIGHUP` reloads configuration; `SIGINT` and `SIGTERM` shut down. A reload never
terminates the process. Only `max_instances` reloads, and only from the startup
`-config` file.

```console
# 1. Edit the node's config file, changing only max_instances.
$EDITOR /etc/steward/config.json
# 2. Signal the running process to re-read it.
kill -HUP "$(systemctl show -p MainPID --value steward)"   # or: kill -HUP <pid>
# 3. Confirm the reload in the logs — every outcome logs a "sighup reload:" line.
journalctl -u steward | grep 'sighup reload'
# -> sighup reload: max_instances updated old_max_instances=512 new_max_instances=1024
```

Add this systemd directive to support `systemctl reload steward`:

```ini
ExecReload=/bin/kill -HUP $MAINPID
```

Reload behavior is explicit and non-destructive:

- Listen address, uplink settings, credentials, and state-file path require a
  restart.
- Lowering the cap below the current instance count evicts nothing. New
  provisions return `503 capacity_exceeded` until normal `Destroy` operations
  lower the count.
- Startup precedence remains `flag > env > file`. If a flag or
  `STEWARD_MAX_INSTANCES` set the value at startup, a file reload cannot replace
  it and Steward logs the rejection.
- Without a startup `-config`, `SIGHUP` is a logged no-op. An unreadable or
  invalid file leaves the current cap unchanged and logs the reason; reload never
  applies a partial change or crashes the process.

`GET /v1/capabilities` reports the live value after a successful reload. See the
[capacity reload design](https://github.com/hardrails/steward/blob/main/ARCHITECTURE.md#capacity-reload).

## Graceful shutdown

After startup validation, Steward handles `SIGINT` and `SIGTERM`. On either signal:

1. Steward logs `"shutting down"` and opens one 10-second deadline.
2. If the inbound listener exists, Steward stops accepting requests and drains
   active connections. A failure here exits non-zero.
3. The cancelled uplink loop drains under the same deadline. A timeout logs a
   `WARN`, but shutdown still exits `0`.

Send `SIGTERM`, not `SIGKILL`, and give the process more than ten seconds before
force-killing it. CI's `scripts/smoke.sh` exercises this path on the compiled
binary.

A minimal systemd unit is:

```ini
[Unit]
Description=Steward lifecycle supervisor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/steward -config /etc/steward/config.json
User=steward
Group=steward
Restart=on-failure
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=15
StateDirectory=steward

[Install]
WantedBy=multi-user.target
```

`TimeoutStopSec=15` leaves margin above Steward's internal deadline. In a
container, use an exec-form entrypoint or an init such as `tini` so `SIGTERM`
reaches Steward. Give `terminationGracePeriodSeconds`, or its equivalent, the
same margin.

## Health and readiness

When the listener exists:

- `GET /v1/healthz` returns `200 {"status":"ok"}` as a **liveness** check.
  It intentionally performs no durable-state I/O. Startup validates the existing
  state file. Ordinary reversible mutations persist a new complete snapshot before
  success, but they do not reread the current file first; use separate file-integrity
  monitoring when out-of-process modification is in scope. A process exit cannot
  be rolled back and may leave the in-memory status ahead of disk if persistence
  fails. Use liveness only for restart decisions.
- `GET /v1/readiness` returns `200 {"status":"ready"}` or
  `503 {"status":"not_ready","check":"...","detail":"..."}`. It checks
  tracker initialization, persistent uplink failure or rejection, sustained
  queue backpressure, and durable-state writability. Use it to remove a node from
  traffic without restarting it.
- `GET /v1/capabilities` reports `version`, `instance_count`, `max_instances`,
  and `durable_state`. It is rollout introspection, not a readiness gate.

With `disable_inbound_listener: true`, these endpoints do not exist. The service
manager can observe process liveness. Logs expose startup, failure, credential
recovery, and command events, but a quiet successful poll is not logged on every
cycle. The control plane must provide the positive signal that polls continue.
Alert on lines such as:

```json
{"level":"INFO","msg":"uplink enabled","url":"https://control-plane.example","node_id":"node-7","tenant_id":"acme","poll_interval":"30s"}
{"level":"WARN","msg":"uplink poll failed; backing off and retrying","consecutive_failures":1,"next_backoff":"1m0s"}
{"level":"ERROR","msg":"uplink credential rejected; pausing the poll loop and waiting for a new credential","node_id":"node-7","path":"/etc/steward/uplink-credential.json"}
{"level":"INFO","msg":"uplink credential file changed; resuming the poll loop","node_id":"node-7"}
```

A rejected credential pauses the loop but leaves the process alive, so alert on
the `ERROR` line rather than waiting for exit. If a listener-disabled poll loop
returns unexpectedly without an active shutdown, Steward logs `ERROR`, starts
the normal graceful shutdown, and exits nonzero. `Restart=on-failure` therefore
restarts the service. See
[Disable the inbound listener]({{ '/disable-inbound-listener/' | relative_url }}).

## Minimal rollout

For an outbound-uplink node:

1. Install a pinned release artifact and confirm it with `steward -version`.
2. Enroll the node and obtain its `tenant_id`, `node_id`, and bearer
   `credential`.
3. Write `/etc/steward/uplink-credential.json` as `0600`, owned by the service
   user.
4. Write `/etc/steward/config.json` with the required uplink, state, listener,
   and logging settings.
5. Run `steward -check-config -config /etc/steward/config.json`.
6. Install the systemd unit above, then run
   `systemctl daemon-reload && systemctl enable --now steward`.
7. Check `journalctl -u steward -f` for `"uplink enabled"` with the expected
   `node_id`, `tenant_id`, and URL. If the listener exists,
   `curl localhost:8080/v1/healthz` must return `200 {"status":"ok"}`.
8. Confirm at the control plane that the node polls and claims lifecycle
   commands. The bundled `steward-control` service implements Executor's signed
   multi-tenant delivery protocol, not this generic supervisor protocol; use a
   compatible external controller for this path.

## Release-build evidence

CI (`.github/workflows/ci.yml`) requires six jobs for every pull request and push
to `main`:

- **build / vet / test:** `go build`, `go vet`, and `go test -race ./...`.
- **golangci-lint**.
- **openapi lint:** Spectral checks `openapi/*.yaml`, covering Steward Control,
  supervisor, Executor, and Gateway contracts.
- **coverage:** `scripts/coverage.sh` requires 85% aggregate unit and
  instrumented-`main()` coverage.
- **mutation:** Gremlins and `.gremlins.yaml` require tests to reject at least 70%
  of generated code mutations.
- **smoke:** `scripts/smoke.sh` starts the compiled binary, checks
  `GET /v1/healthz`, sends `SIGTERM`, and requires a clean, panic-free exit `0`.

Green CI on the deployed commit or tag is the evidence for these checks. The
smoke job exercises one startup, health-check, and graceful-shutdown path; it does
not prove every target operating system or deployment environment satisfies the
contract.
