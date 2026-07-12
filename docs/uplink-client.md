---
title: Outbound uplink client
description: Design and wire contract for Steward's outbound command and reporting channel.
section: Design record
---

# Outbound uplink client

Status: **implemented.** This document defines the generic `cmd/steward` uplink.
It records the public wire contract, failure behavior, security boundaries, and
tradeoffs required to build a compatible control plane.

## Why this exists

An inbound REST API works only when the caller can connect to the node. That is
often impossible behind network address translation (NAT), an inbound firewall, or
a private site boundary.

The uplink reverses the connection. Steward opens an outbound HTTP connection to a
control plane, polls for queued commands, applies them locally, and reports the
result. The control plane never needs to open a connection to the node.

Steward contains the client half only. An independent control plane must provide
enrollment, credential issuance, command queuing and claim leases (time-limited
ownership of claimed commands), the poll and report endpoints, and retirement of
completed or superseded commands.

## Boundaries and invariants

- **Opt-in:** an empty `-uplink-url` disables the uplink. The default remains the
  inbound REST API.
- **One lifecycle engine:** the uplink and REST handlers call the same
  `internal/runtime.Tracker`. They share its mutex, idempotency rules, capacity cap,
  and optional `-state-file`.
- **Tenant-scoped generic client:** `cmd/steward` accepts the tenant-scoped
  credential shown below. It executes commands for one enrolled node and tenant at
  a time. The node-scoped multi-tenant protocol belongs to `steward-executor`; see
  [Executor]({{ '/executor/' | relative_url }}).
- **No inbound contract added:** the uplink adds no route to Steward. Its endpoints
  are served by the external control plane, so they do not appear as Steward routes
  in `openapi/steward.v1.yaml`.
- **Standard library only:** HTTP, JSON, TLS, timers, randomized polling delay
  (jitter), and logging use the Go standard library. The uplink adds no module
  dependency.

## Configuration

Every setting has a matching environment variable. A command-line flag overrides
the environment, which overrides the JSON config file.

| Flag | Environment variable | Default | Purpose |
| --- | --- | --- | --- |
| `-uplink-url` | `STEWARD_UPLINK_URL` | empty | Absolute control-plane `http` or `https` base URL. Its presence enables the uplink. |
| `-uplink-credential-file` | `STEWARD_UPLINK_CREDENTIAL_FILE` | empty | Owner-only credential JSON. Required when the uplink is enabled. |
| `-uplink-poll-interval` | `STEWARD_UPLINK_POLL_INTERVAL` | `10s` | Base poll cadence before jitter and failure backoff. |
| `-uplink-command-queue-depth` | `STEWARD_UPLINK_COMMAND_QUEUE_DEPTH` | `256` | Maximum queued plus in-flight commands. Must be positive. |
| `-uplink-tls-ca-file` | `STEWARD_UPLINK_TLS_CA_FILE` | empty | PEM CA bundle for a private control-plane CA; empty uses system roots. |
| `-uplink-tls-client-cert` | `STEWARD_UPLINK_TLS_CLIENT_CERT` | empty | PEM client certificate for mutual TLS (mTLS). Requires the client key. |
| `-uplink-tls-client-key` | `STEWARD_UPLINK_TLS_CLIENT_KEY` | empty | Owner-only PEM private key for mTLS. Requires the client certificate. |
| `-uplink-tls-skip-verify` | `STEWARD_UPLINK_TLS_SKIP_VERIFY` | `false` | Dangerous diagnostic option that disables server-certificate verification. |
| `-audit-log-file` | `STEWARD_AUDIT_LOG_FILE` | empty | Optional best-effort JSON Lines record of terminal command outcomes. |
| `-disable-inbound-listener` | `STEWARD_DISABLE_INBOUND_LISTENER` | `false` | Bind no inbound HTTP socket. Requires the uplink. |

Invalid durations, booleans, queue depths, URLs, credentials, and TLS inputs stop
startup and fail `-check-config`. A poll interval above five minutes is accepted but
clamped to five minutes, with a warning.

## Node credential

Enrollment produces this file:

```json
{
  "version": 1,
  "tenant_id": "acme",
  "node_id": "node-7",
  "credential": "<opaque bearer token minted at enrollment>"
}
```

The token is opaque. Steward sends it verbatim and never parses a private token
format. `tenant_id` and `node_id` remain explicit so the client can identify its
scope without decoding the token.

The loader fails closed when the file is missing, unreadable, too large, not a
regular file, group- or world-accessible, invalid JSON, an unsupported version, or
missing a required value. The file must have mode `0600` or stricter. The complete
file is limited to 64 KiB; each tenant and node identifier is limited to 128 bytes,
and the bearer value is limited to 32 KiB and cannot contain a newline or NUL (zero)
byte.
Symlinks and a file changed during opening are rejected.

Steward does not create or rewrite this file. An operator or provisioning system
owns enrollment and rotation. `POST /uplink/nodes`, when a control plane provides
it, is an out-of-band operator action; this client does not call it.

## Transport

The base URL must be absolute and use `http` or `https`. The generic client permits
plain HTTP for compatibility, but HTTP exposes the bearer and commands to the
network. Use verified HTTPS in any environment where the network is not fully
trusted.

For HTTPS, Steward requires TLS 1.2 or later and verifies the server certificate
against system roots unless `-uplink-tls-ca-file` supplies a private CA. A client
certificate and key enable mTLS; both must be configured together, and the private
key must be owner-only. Invalid CA, certificate, or key inputs stop startup.

`-uplink-tls-skip-verify` disables control-plane authentication and permits a
man-in-the-middle attack. It is off by default and logged loudly when enabled. It is
for temporary diagnostics, not production.

One shared `http.Client` handles polling and reports. Its 30-second timeout bounds a
black-holed request. Every request carries:

```
Authorization: Bearer <credential>
Content-Type: application/json
```

Poll responses, reports, and report responses are each limited to 1 MiB. Steward
rejects an oversized poll response as a whole rather than parsing a truncated batch.
It refuses an oversized report before transmission. In both cases, the control
plane's claim lease can redeliver the command.

## Poll loop and failure behavior

A background Go task (goroutine) polls the control plane. A single consumer drains
the bounded command queue and executes commands. Both stop through the process
shutdown context, including during a timer wait or an in-flight HTTP request. `Run`
waits for the consumer before returning.

The steady poll delay is the configured interval plus random jitter of up to 20% in
either direction. This prevents a fleet that restarts together from polling in one
synchronized burst.

| Poll result | Behavior |
| --- | --- |
| Valid, bounded `2xx` JSON | Accept the batch and reset failure backoff. |
| Malformed or oversized `2xx` body | Reject the whole response and retry as a transient failure. |
| Network error, timeout, `5xx`, or `429` | Log `WARN`; use exponential backoff with jitter, capped at five minutes. |
| `401` or `403` | Log `ERROR`; pause polling and watch the credential file. |
| Other `4xx` | Log probable protocol or version skew; retry at the five-minute cap. |

A rejected credential is not retried repeatedly. `cmd/steward` always provides the
credential path, so the poller rereads it every five seconds while paused and makes
no outbound poll during that wait. It compares decoded credential content, not file
modification time. An unchanged, absent, truncated, or temporarily invalid file is
ignored until the next check. A replacement for a different `node_id` is refused.
A valid file for the same node with a different bearer resumes polling without a
restart. If a library caller creates a `Poller` without `CredentialPath`, a `401` or
`403` stops the loop and recovery requires a restart.

Readiness treats three consecutive full-queue polls as backpressure. Before the
first successful poll, three consecutive poll failures or a rejected credential
also make the node not ready. After any successful poll, later reachability failure
alone does not change readiness; sustained queue backpressure still does. A
listener-free node exposes no local readiness or metrics endpoint. See
[Disabling the inbound listener]({{ '/disable-inbound-listener/' | relative_url }}).

## Command queue and ordering

The in-memory first-in, first-out (FIFO) queue holds at most
`-uplink-command-queue-depth` commands, counting both queued and executing work.

- Commands are admitted in poll order. Excess commands are rejected, logged at
  `WARN` with the prefix `uplink command queue full:`, and not reported. The control
  plane can redeliver them after the queue drains.
- A non-empty `command_id` already queued or in flight is skipped. Deduplication
  lasts through execution, then the ID is released. An empty, out-of-contract ID is
  never deduplicated but still consumes capacity.
- Deduplication saves work and state-file writes; tracker idempotency remains the
  correctness boundary.
- The consumer drains the FIFO as one batch. This preserves order even when work
  from several poll cycles is waiting.

The wire does not promise causal order within a batch, so Steward does not invent
one. It executes the returned order and makes one bounded retry pass for `start`
commands that initially name an unknown instance. A later sibling `provision` may
make that retry succeed.

Only `start` is deferred. Deferring `stop` or `hibernate` could apply an old command
to an instance that a later sibling just provisioned. Moving every `provision` to
the front is also unsafe: a valid replacement batch
`destroy(x)` then `provision(x)` would become `provision(x)` then `destroy(x)` and
leave the instance absent. Steward therefore reorders nothing.

## Command execution

Each command carries a control-plane reference in this format:

```
uplink:<code-point-count-of-node_id>:<node_id>:<instance_id>
```

The length prefix makes the format unambiguous even when `instance_id` contains a
colon. Steward rejects a bad prefix, non-decimal or overrun length, missing
separator, or empty component. Before any tracker access, both the explicit
`node_id` field and the node encoded in `runtime_ref` must equal the enrolled
`node_id` and each other.

The control-plane reference and Steward's local `rt_<hex>` reference are different
names for the same live instance. `provision` addresses the tracker by
`instance_id`. Other commands resolve `instance_id` through the locked
`RefForInstance` index, then call the existing tracker method. No second mapping is
stored, and `-state-file` already preserves the tracker index across restart.

| `kind` | Tracker operation | Successful `reported_status` |
| --- | --- | --- |
| `provision` | `Provision(instance_id, instance_generation, payload)` | `provisioning` |
| `start` | `Start(runtime_ref)` | `running` |
| `stop` | `Stop(runtime_ref)` | `stopped` |
| `hibernate` | `Hibernate(runtime_ref)` | `hibernated` |
| `destroy` | `Destroy(runtime_ref)` | `stopped` |

A present provision `payload` must be a JSON object. `null` and an absent payload
mean no spec. This is the same shape enforced by the inbound provision endpoint.
Unknown command kinds, malformed references, identity disagreement, invalid
payloads, and rejected lifecycle transitions produce a `failed` report without
changing the tracker.

Commands can also carry `instance_generation`. Steward persists the current
generation and drops a command older than the live lineage without a report. See
[Instance-generation fencing]({{ '/instance-generation-fencing/' | relative_url }}).

Tracker behavior makes at-least-once delivery safe in effect:

- `provision` is idempotent on `instance_id`;
- without a competing transition, repeated valid `start`, `stop`, and `hibernate`
  operations converge on the same state; and
- `destroy` of an already-absent instance reports `done`, because the requested end
  state is already true.

An unknown instance is a real failure for `start`, `stop`, or `hibernate` after the
bounded `start` retry described above.

Concurrent direct and uplink transitions can supersede one another between locked
tracker calls. The instance returned in each result is authoritative; callers must
not infer a later state from the operation name alone.

## Reporting

Every non-fenced terminal outcome copies the received `command_id` and
`claim_generation` into a report. `claim_generation` is the control plane's fencing
token for a reclaimed command claim; Steward never creates or changes it.

Steward does not maintain a durable report queue and does not retry a failed report
in an inner loop. If a report is lost, the command remains claimed until its lease
expires. The control plane then redelivers it with a higher `claim_generation`, and
the idempotent tracker path runs again.

Status translation is explicit:

| Steward status | `reported_status` |
| --- | --- |
| `PENDING` | `provisioning` |
| `RUNNING` | `running` |
| `STOPPED` | `stopped` |
| `HIBERNATED` | `hibernated` |
| `FAILED` | `failed` |
| `DESTROYED` | `stopped` |

The wire has no `destroyed` status. A successful destroy removes the tracked
instance, so `stopped` is the available “not running” value. `provision` and `start`
remain separate commands; a provisioned `PENDING` instance therefore reports
`provisioning` until a later `start` drives it to `running`.

## Wire contract

The uplink routes have no `/v1` prefix.

### Poll

`POST {uplink-url}/uplink/poll` sends `{}`. The credential identifies the node; the
request carries no heartbeat or node ID. A successful response is:

```json
{
  "commands": [
    {
      "command_id": "…",
      "node_id": "node-7",
      "runtime_ref": "uplink:6:node-7:agent-1",
      "kind": "provision",
      "payload": { },
      "claim_generation": 3,
      "instance_generation": 2
    }
  ]
}
```

An empty poll returns `{"commands": []}` with `200`, not `204`. Polling uses
`POST` because claiming work changes control-plane state from pending to claimed.

### Report

`POST {uplink-url}/uplink/report` sends:

```json
{
  "command_id": "…",
  "status": "done",
  "reported_status": "running",
  "claim_generation": 3,
  "result": { }
}
```

`status` is `done` or `failed`. A successful `result` is `{}`; a failed result is an
object with a human-readable `error` string.

The response is:

```json
{"applied": true}
```

`applied: false` means the report was stale, fenced, duplicated, or already
terminal. The control plane returns that no-op with `200`, not `4xx`. Steward logs
it and does not retry.

## Audit log

`-audit-log-file` appends one JSON object per terminal reported outcome with
`timestamp`, `command_id`, `instance_id`, `kind`, `status`, and an optional `error`.
Fenced commands and the first pass of a deferred `start` are not terminal outcomes
and are not recorded. A failed audit write is logged but does not block command
execution or reporting.

This file is a best-effort operational log, not signed evidence. It is append-only,
not fsynced per record, and a crash can leave a malformed final line. Readers must
tolerate that trailing line. Use Steward's evidence system when tamper-evident,
offline-verifiable receipts are required.

## Alternatives rejected

- **A third-party HTTP, retry, or backoff library:** the loop is small and the
  dependency would break Steward's one-repository, standard-library-only build.
- **A client-owned instance-reference map:** the tracker already owns and persists
  the mapping. A second map could drift.
- **Inline execution without a queue:** one poll could commit the node to unbounded
  work and stall later polls.
- **Blocking when the queue is full:** it would stop polling and hide pressure.
  Rejecting without a report reuses claim-lease redelivery.
- **Deduplicating on `(runtime_ref, kind)`:** two legitimate commands can share that
  pair. `command_id` is the protocol identity.
- **A durable outbound report queue:** the control plane's lease and claim fencing
  already recover a lost report without another node-side state machine.
- **Combining poll and report:** reports are sent immediately. Piggybacking them on a
  later poll remains a possible optimization, not part of this contract.

One control-plane URL is supported. Health-based failover between several control
planes is not implemented.

## Implementation evidence

Key behavior is pinned by these tests:

- `TestLoadCredentialFailsClosed`,
  `TestLoadCredentialRejectsOversizeAndSymlink`, and
  `TestLoadCredentialRejectsOverPermissiveFile`
- `TestNewHTTPClientVerifiesServerCert`, `TestNewHTTPClientMutualTLS`, and
  `TestNewHTTPClientRejectsOverPermissiveClientKey`
- `TestPollerExecutesAndReportsCommand`, `TestPollerBacksOffAndRetriesOn5xx`, and
  `TestPollerEntersWatchModeAndResumesOnCredentialFileChange`
- `TestPollerRejectsBurstExceedingQueueDepthAndRedelivers` and
  `TestPollerDeduplicatesRedeliveredCommandInFlight`
- `TestExecuteBatchReplaceDestroyThenProvision`,
  `TestExecuteBatchStartBeforeProvisionRetries`, and
  `TestExecuteBatchStopBeforeProvisionFailsImmediately`
- `TestDispatchRejectsExplicitNodeIDThatDisagreesWithRuntimeRef`,
  `TestDispatchNonObjectPayloadRejectedBeforeProvision`, and
  `TestDispatchRedeliveredDestroyReportsDone`
- `TestPollRejectsOversizedResponse`, `TestSendReportRefusesOversizedBody`, and
  `TestSendReportRejectsOversizedResponse`

Run the affected packages with the race detector after changing the tracker or
uplink:

```console
go test -race ./internal/runtime ./internal/uplink ./cmd/steward
```
