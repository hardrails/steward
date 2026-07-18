---
title: APIs and protocol schemas
description: Authoritative Steward Control, supervisor, Executor, and Gateway OpenAPI contracts, endpoint summaries, authentication, error shapes, and outbound uplink protocol documentation.
section: Reference
---

# APIs and protocol schemas

The OpenAPI documents are Steward's public HTTP contracts. OpenAPI describes
endpoints and schemas in machine-readable form. Any behavior/specification mismatch
is a defect, not an extension clients should use.

- [Steward supervisor OpenAPI](https://github.com/hardrails/steward/blob/main/openapi/steward.v1.yaml)
- [Steward Control OpenAPI](https://github.com/hardrails/steward/blob/main/openapi/steward-control.v1.yaml)
- [Steward Executor OpenAPI](https://github.com/hardrails/steward/blob/main/openapi/steward-executor.v1.yaml)
- [Steward Gateway task lifecycle OpenAPI](https://github.com/hardrails/steward/blob/main/openapi/steward-gateway.v1.yaml)
- [Raw supervisor YAML](https://raw.githubusercontent.com/hardrails/steward/main/openapi/steward.v1.yaml)
- [Raw Steward Control YAML](https://raw.githubusercontent.com/hardrails/steward/main/openapi/steward-control.v1.yaml)
- [Raw Executor YAML](https://raw.githubusercontent.com/hardrails/steward/main/openapi/steward-executor.v1.yaml)
- [Raw Gateway task lifecycle YAML](https://raw.githubusercontent.com/hardrails/steward/main/openapi/steward-gateway.v1.yaml)

## Steward Control API

Default base URL: `http://127.0.0.1:8443`. A non-loopback listener requires TLS,
so its origin is `https://...`.

Every request must also use the controller's exact HTTP authority in its `Host`
header. For loopback HTTP, that authority is the literal bound IP and port. For
TLS, the host must be an exact, non-wildcard DNS or IP Subject Alternative Name
(SAN) from the leaf certificate at the listener port. Steward rejects malformed
or mismatched authorities with `400 Bad Request` before API or console routing.

The embedded console assets, health, readiness, and one-time enrollment exchange
do not use an operator bearer. Console assets contain no fleet data; their
same-origin API reads still require an appropriate operator bearer. Enrollment
exchange uses the one-time enrollment bearer in its request. Operator credentials
are either site-wide or scoped to one tenant. Node credentials can call only the
command and evidence uplink poll and report routes for their bound node.

| Method and path | Purpose |
| --- | --- |
| `GET or HEAD /console`, `/console/`, and committed `/console/*` assets | Serve the embedded React console without a CDN or separate web server; the loaded SPA uses the existing operations reads and exact signed-command endpoint |
| `GET /v1/healthz`, `GET /v1/readiness` | Process liveness and durable-store readiness |
| `POST /v1/tenants`, `GET /v1/tenants` | Create and page through tenants |
| `GET /v1/tenants/{tenant_id}` | Read one visible tenant |
| `POST /v1/operators`, `DELETE /v1/operators/{credential_id}` | Issue idempotent scoped operators and revoke them; the last live site administrator cannot be revoked |
| `POST /v1/enrollments`, `POST /v1/enroll` | Idempotently create a one-time node enrollment and exchange it |
| `DELETE /v1/node-credentials/{credential_id}` | Revoke one node bearer during staged credential rotation |
| `GET /v1/tenants/{tenant_id}/nodes` | Page through bounded tenant node inventory |
| `GET /v1/tenants/{tenant_id}/nodes/{node_id}` | Read one tenant-visible node |
| `DELETE /v1/nodes/{node_id}` | Revoke a node and all of its credentials site-wide |
| `GET /v1/nodes/{node_id}/evidence` | Read the site-admin-only last-good Executor receipt checkpoint and any sticky divergence finding |
| `GET /v1/nodes/{node_id}/evidence/export` | Sign a portable evidence checkpoint with the controller's dedicated witness key |
| `POST /v1/nodes/{node_id}/evidence/captures` | Arm one site-admin-only bounded activation evidence capture from the current witnessed head |
| `GET or DELETE /v1/nodes/{node_id}/evidence/captures/{capture_id}` | Inspect the frame-free capture state or irreversibly delete the retained capture |
| `POST /v1/nodes/{node_id}/evidence/captures/{capture_id}/seal` | Bind one observed checkpoint range to a matching successful activation-canary command |
| `GET /v1/nodes/{node_id}/evidence/captures/{capture_id}/export` | Export exact signed frames and the controller's purpose-separated witness signature |
| `POST /v1/tenants/{tenant_id}/nodes/{node_id}/commands` | Retain one exact signed Executor command |
| `GET .../commands/{command_id}` | Read durable delivery and terminal status |
| `GET /v1/operations/summary` | Read tenant-projected capacity, command, evidence, and attention totals |
| `GET /v1/operations/attention` | Page and filter deterministic action-required facts |
| `GET /v1/operations/commands` | Page and filter command metadata without command or result bodies |
| `GET /v1/operations/credentials` | Page and filter non-secret credential metadata |
| `GET /metrics` | Optional authenticated Prometheus exposition with fixed bounded labels |
| `POST /executor-uplink/poll`, `POST /executor-uplink/report` | Lease signed commands to an enrolled Executor and settle fenced reports |
| `POST /evidence-uplink/poll`, `POST /evidence-uplink/report` | Return a credential-bound challenge, then verify and retain a receipt-key-signed evidence batch |

Every request body and response is bounded. Tenant and node inventory uses the
exclusive `after` cursor. Operations inventory uses an opaque `cursor` that is
valid only with the same filters. The controller rejects duplicate and unknown
query parameters, redirects are not used, and every error has the common
`{"error":"...","message":"..."}` shape. The controller parses signed-command
identity to bind it to the route but does not treat that parse as authorization;
Executor verifies the signature and local policy before applying the command.

Evidence enrollment proves possession of the node receipt key and pins it to one
controller, enrollment, control node, receipt node, stream, and epoch. A report
signs the exact controller checkpoint returned by its poll, the reported local
head, frame count, and a domain-separated digest of the exact decoded frames. An
exact retry is a no-op. A stale report cannot manufacture a rollback finding, and
adding, removing, replacing, or reordering frames invalidates the proof.
One report carries at most 128 frames and 700 KiB of decoded frame data; each
length-prefixed frame is at most 64 KiB plus its four-byte length prefix. The
frame collection may be omitted when empty but cannot be JSON `null`. The complete
request body remains limited to 1 MiB.

The online evidence inspection and portable export require a site-admin
credential. The export embeds a public witness key only to describe its signer;
offline verification must use a witness public key obtained through an independent
trusted channel. The controller retains a bounded latest checkpoint and first
sticky rollback or equivocation finding, including the exact historical
checkpoint used to classify the observed conflicting head. It does not retain
the full node receipt archive. Evidence export uses optimistic linearization:
three consecutive witness updates return `409 Conflict` with `Retry-After: 1`;
a 409 without that header is a retained-state conflict rather than a retry hint.

Activation evidence captures are also site-admin-only. Arming fixes a baseline at
the node's current finding-free witnessed head and a one-second-to-one-hour
absolute observation deadline. Operators arm before submitting activation, but
the resulting proof establishes controller observation after that baseline, not
receipt generation time. The controller permits one `armed` capture per
node, 16 active captures and 256 retained captures site-wide, with 128 frames and
512 KiB of decoded frame data per capture and 16 MiB of aggregate reserved or
captured frame data. A portable export is limited to 1 MiB of JSON. Exact arm and
seal retries are idempotent and do not extend the original deadline.

The capture state progresses from `armed` to `observed` only after one matching,
allowed, error-free activation begin is followed by one matching committed,
error-free checkpoint, then to `sealed` only after
the named protocol-4 activation-canary command has a matching successful terminal
result. Only `sealed` can be exported. `expired` and `failed` are terminal;
`failure` is one of `capture_overflow`, `coordinate_changed`, `evidence_finding`,
`target_contradiction`, or `storage_capacity`. Expiry is persisted lazily on the next evidence report
or capture operation after the deadline, not by a background timer.

An export contains the exact native frames required to replay the receipt chain.
Those frames can include unrelated tenants because removing an interleaved frame
would break chain continuity. The controller signs with its dedicated evidence
witness key, which must be distinct from the node's receipt key. Offline clients
must pin that witness public key independently; the key embedded in the response
is not a trust anchor. Capture failure never blocks ordinary evidence witnessing,
and no capture endpoint retries, rolls back, stops, destroys, or otherwise changes
a workload. Deletion changes only retained capture state.

Operations findings are derived observations, not mutable tickets. The API cannot
acknowledge, dismiss, retry, or clear them. A tenant operator is always projected
to its own tenant; a cross-tenant filter is indistinguishable from an unknown
resource. Command inventory excludes signed command bytes, terminal result bodies,
reported status text, and error codes. Credential inventory excludes bearer
material and token verifiers.

Evidence-report recency is intentionally held in bounded process memory. After a
controller restart, evidence is conservatively stale or unknown until the node
reports again; the durable checkpoint and sticky rollback or equivocation finding
remain intact. `/metrics` is absent unless explicitly enabled and still requires
an operator bearer. It does not label tenant, node, credential, or command IDs or
include prompts, bodies, results, or credentials. When one scraper requests
several tenant projections, it must add distinct trusted target labels or jobs;
the `tenant_id` query parameter alone is not part of Prometheus series identity.

See [Operate the bundled control plane]({{ '/guides/control-plane/' | relative_url }})
for installation and lifecycle examples.

## Supervisor API

Default base URL: `http://127.0.0.1:8080`

| Method and path | Purpose |
| --- | --- |
| `POST /v1/instances` | Idempotently provision lifecycle state |
| `GET /v1/instances` | List/filter tracked instances |
| `POST /v1/instances/batch` | Execute up to 256 lifecycle operations in order |
| `GET /v1/instances/{runtime_ref}` | Read instance state |
| `POST .../start`, `.../stop`, `.../hibernate` | Apply a lifecycle transition |
| `DELETE /v1/instances/{runtime_ref}` | Destroy and release identity |
| `GET /v1/capabilities` | Discover version and optional capabilities |
| `GET /v1/healthz`, `GET /v1/readiness` | Liveness and readiness |
| `GET /metrics` | Optional Prometheus text exposition |

The loopback API has no built-in authentication. Keep it on loopback, put it behind
an authenticated host control boundary, or disable it and use the authenticated
outbound uplink.

## Executor API

Default base URL: `http://127.0.0.1:8090`

Every endpoint except `GET /v1/healthz` requires
`Authorization: Bearer <token-from-token-file>`.

The bearer has one node-local role. `observer` can read inspection endpoints;
`operator` adds workload lifecycle and maintenance changes; `host-admin` adds
admission, state purge, and activation authorization. Roles are host-wide API
limits, not tenant identities. Signed operations still enforce tenant, node, and
generation authority independently.

| Method and path | Purpose |
| --- | --- |
| `GET /v1/local-principal` | Return the authenticated local credential ID and role |
| `POST /v1/admissions` | Verify a publisher-signed profile, local policy, and tenant-bound instance request; optionally bind an activation begin digest; journal the mutation; and create a receipt-bound workload |
| `POST /v1/workloads/{runtime_ref}/activation-canary-preflight` | Recheck current policy, tenant authority, activation identity, reconciliation, lifecycle, and complete runtime topology immediately before the uplink contacts Gateway |
| `POST /v1/workloads/{runtime_ref}/activation-checkpoints` | Append an idempotent, content-free signed checkpoint after a running activation has verified terminal Gateway evidence |
| `POST /v1/state/purge` | Permanently purge an inactive, authorized state lineage with a receipt |
| `POST /v1/workloads` | Validate and create a stopped gVisor container |
| `GET /v1/workloads/{runtime_ref}` | Read observed container state; signed runtimes also return their complete committed admission projection |
| `POST .../start`, `.../stop` | Idempotent lifecycle operation; while reconciliation is degraded, start is blocked and stop becomes a safety-only containment operation |
| `GET .../logs` | Read a combined log tail capped at 1 MiB |
| `GET .../egress` | Read bounded allow/deny, byte, and last-destination statistics for a signed egress grant |
| `DELETE /v1/workloads/{runtime_ref}` | Remove a managed workload; unsigned mode treats absence as success, while signed mode requires an authorized retained tombstone |
| `GET /v1/healthz` | Process liveness |
| `GET /v1/readiness` | Report readiness and the latest bounded reconciliation summary for present signed runtimes |

The signed admission request can include an optional `activation` object with
schema `steward.executor-activation-admission.v1`, a bounded `activation_id`, and
a canonical SHA-256 `begin_digest`. Executor requires the signed runtime
capability topology. After authority, policy, image, capacity, and other read-only
preflights pass, Executor writes an idempotent `activation_begin` receipt before
the admission-allow receipt, mutation journal, or host mutation. It stores the
activation identity with the runtime. An exact replay can recover the same
admission; a different activation ID or begin digest conflicts. The object does
not grant authority and does not bypass capsule, policy, intent, generation,
capacity, or topology checks.

The activation-checkpoint endpoint accepts one strict JSON object capped by the
same 1 MiB request limit as admission. It requires schema
`steward.executor-activation-checkpoint.v1`, the same bounded activation ID, and a
canonical SHA-256 `checkpoint_digest`; the request does not carry a begin digest.
Executor derives all lifecycle identity from the committed signed fence. An
uplink-injected tenant principal must match the retained tenant, node, and
generation. A direct host-local call is accepted only when
`-admission-allow-host-admin-intent` is explicitly enabled, in which case the
loopback bearer acts with host-administrator authority rather than tenant
authentication. Current site policy must still authorize the fence. The request
activation ID must match the live runtime, the persisted begin digest must match
the earlier signed marker, reconciliation must be ready, and the exact topology
must be running. An exact retry does not add another receipt. A missing begin
marker, conflicting digest, runtime drift, degraded reconciliation, or unavailable
evidence log fails closed. A signed stop, destroy, revocation, drift, closed
state purge, or workload compensation after the proven start invalidates the
checkpoint even if the same workload is running again. This causal check also
applies to an exact retry of a previously retained checkpoint. The response and
every error use the schemas in the Executor OpenAPI contract.

The activation-canary preflight endpoint is the read-only authorization boundary
immediately before Gateway use. It accepts one strict JSON object capped at 1
MiB with schema `steward.executor-activation-canary-preflight.v1`, the retained
activation ID, and the retained activation-begin digest. Executor serializes the
check with signed lifecycle mutations. It requires ready reconciliation, the
current site policy, the authenticated tenant principal or explicitly enabled
host-administrator authority, and the complete admitted runtime topology in its
running state. A successful response returns the exact committed admission
projection and writes no receipt. A failed preflight prevents the uplink from
contacting Gateway.

For a securely admitted workload, `GET /v1/workloads/{runtime_ref}` returns the
capsule and policy digests, generation, evidence key ID, grant and route-policy
identity, service and public task authorities, configured egress or connector
projection, and—when activation metadata was used—`activation_id` and
`activation_begin_digest`. Authorized-effects admission also returns the public
action authorities and approval threshold narrowed by signed tenant policy. This
lets a caller recover an exact admission response
after an ambiguous transport failure without treating a different live workload
as the same activation.

Executor readiness describes the latest scan of present signed runtimes. With no
present runtime that needs Gateway, it does not probe Gateway health. Capability
availability is checked separately during admission and may still fail closed.
When readiness is 503, signed admission, activation checkpoint, start, destroy,
and state purge are blocked. An authenticated stop can still deactivate the
Gateway grant identified by the retained signed admission record and stop exactly
identified local agent and relay containers. It never settles the operation
journal or removes a drifted object.

## Gateway task lifecycle API

Default base URL: `http://127.0.0.1:8091`

Both endpoints require `Authorization: Bearer <gateway-service-token>`. Gateway
accepts only the configured loopback listener and host credential; these are not
tenant-facing endpoints.

| Method and path | Purpose |
| --- | --- |
| `GET /v1/tasks/{task_digest}/permits/{permit_digest}` | Read durable lifecycle evidence without contacting the agent |
| `POST /v1/tasks/{task_digest}/permits/{permit_digest}/observe` | Ask Gateway to make one policy-bounded status request to the configured agent service |

The path binds two values: the deterministic SHA-256 task correlation digest and the
digest of the exact permit envelope that authorized that task. They must identify
the same retained authorization. A missing task, a mismatched pair, a legacy task,
an alternate encoded path, or a query string returns 404. Both requests are
bodyless.

The observation endpoint is not a general proxy. The active grant fixes the
agent-service origin. Node operation policy fixes the status-path prefix, timeout,
response limit, and minimum poll interval. Gateway appends the already recorded run
ID, sends one bodyless GET, and does not forward caller headers or credentials.
Concurrent observation of one task returns 409. Host policy can return 429;
poll-interval throttling includes `Retry-After`.

`dispatch_accepted` means Gateway durably recorded the run ID returned by the agent
service. A terminal `agent_reported_*` state means Gateway received that report for
the recorded run and durably recorded its exact response digest and byte length. It
does not prove the agent did the requested work, that an output is correct, or that
the report is truthful.

Gateway never persists the agent response body. A live terminal observation returns
the exact bounded response as `observation_base64` only after its run ID, terminal
state, byte length, and SHA-256 digest match durable evidence. If delivery is lost,
a later POST—including after Gateway restarts—can recover the same report while the
exact grant remains active. A changed agent report returns 502 and cannot replace
the durable terminal record. GET remains passive and never returns raw bytes. A
`queued` or `running` report is returned as the transient `observed_status`; durable
state remains `dispatch_accepted`.

## MCP server

`steward-mcp` implements Model Context Protocol (MCP) `2025-11-25` over standard
input/output. With a control-plane operator credential, its fleet tools list
visible tenants and nodes, submit or inspect already signed commands, read
operations and attention summaries, and page secret-free command or credential
metadata. A site-admin credential is required to create tenants, revoke nodes, or
read the evidence checkpoint; a tenant-scoped credential confines the remaining
fleet operations to that tenant. The evidence tool omits raw proof signatures and
export files. Fleet tools do not issue operator or enrollment secrets. Its admit, status,
logs, egress, start, stop, destroy, and
state-purge tools call the loopback Executor API. When configured with a loopback
Gateway origin, separate owner-only Gateway token, and fixed result directory, it
also exposes pre-signed task submit, passive status, and one-shot observation
tools. Raw agent output is written only to a deterministic owner-only file; MCP
receives its path, digest, length, and status metadata. The task-submit
acknowledgment is not human approval: signed permit and Gateway policy remain
authoritative. The adapter opens no listener and adds no authority of its own. See
[MCP setup]({{ '/guides/mcp/' | relative_url }}).

## Per-workload connector protocol

The trusted relay exposes a grant-owned connector origin inside an admitted
workload as `STEWARD_CONNECTOR_URL`. This is an internal capability protocol, not a
host management listener or a public OpenAPI endpoint:

```text
METHOD /v1/connectors/{connector_id}/operations/{operation_id}
X-Steward-Task-ID: <bounded one-use task ID>
Content-Type: application/json
X-Steward-Action-Permit: <canonical base64url DSSE envelope>
```

`METHOD`, connector ID, operation ID, and whether a body is allowed come from node
configuration. `Content-Type` applies only to POST, PUT, and PATCH; those methods
require one strict JSON value. GET, HEAD, and DELETE are bodyless and omit that
header. Gateway hashes and forwards the exact validated bytes. A permit-enabled
connector requires exactly one `X-Steward-Action-Permit`; a connector without
action authorities omits it and rejects an unsolicited copy. The permit must match
the live node, tenant, instance, generation, admitted artifact and policy digests,
route policy, operation-policy
digest, task, request digest and length, content type, and time window. The
operation-policy digest fixes the canonical upstream origin, credential injection
mode, credential epoch, connector and operation IDs, method, and exact path.
Bodyless GET, HEAD, and DELETE bind an empty request and content type.

For an authorized-effects grant, Gateway accepts
`steward.action-permit.v2` for a one-approver policy or
`steward.action-permit.v3` for a multi-party policy, with `effect_mode` fixed to
`authorized`. Version 3 requires the exact signed number of distinct admitted
authorities over one unchanged payload. Gateway rejects a legacy version-1 permit.
Receipt format 5 binds a one-approver call's mode and operation-policy digest;
format 6 additionally binds a multi-party signer set and threshold. Standard
permit-enabled connectors continue to use version 1.

When signed policy requires context locking, Gateway accepts only
`steward.action-permit.v5`. The permit also binds the current influence sequence
and hash reconstructed from the grant's signed connector-response history. Format
7 receipts preserve those fields and commit the terminal response digest. A later
completed connector call makes the prior permit stale. Context-required grants are
serialized to one call and do not accept exact-effect bundles.

The task claim and call budget are spent in the signed connector ledger before DNS.
A clean relayed response ends with `X-Steward-Connector-Receipt: recorded`.
Connector errors use the common JSON shape; a permit failure is HTTP 403
`action_permit_denied`. In authorized mode, Gateway writes at most one stable
format-5 denial marker per retained grant. If that bounded marker cannot be made
durable, the request fails closed with HTTP 503 `evidence_unavailable`. The marker
is the first observed attacker-selected invalid request, not an exhaustive record
of later denials. See
[authenticated API operations]({{ '/guides/connectors/' | relative_url }}) for the
complete request, evidence, and failure contract.

## Tenant-signed service-task protocol

Gateway's loopback service listener can require a tenant signature for one exact
agent-service operation. This is an internal capability protocol, not a public
management endpoint and not a generic tenant ingress API:

```text
POST /v1/services/{grant_id}/{configured_path}
Authorization: Bearer <host Gateway service token>
Content-Type: application/json
Content-Length: <positive exact byte length>
X-Steward-Task-Permit: <canonical base64url DSSE envelope>
```

The request may have no query, alternate encoded path, transfer coding, WebSocket
upgrade, or caller-selected headers beyond Gateway's accepted host interface. Node
configuration fixes the service ID, operation ID, `POST` method, canonical path,
`application/json` content type, request and response byte ceilings, timeout, and
maximum permit lifetime. The body must be one strict JSON value and is limited to
64 KiB. A permit is limited to 16 KiB decoded and 15 minutes even if configuration
would attempt a larger value.

Signed site policy scopes each public tenant task key to exact service IDs.
The permit binds the node, tenant, logical instance, runtime and grant, generation,
capsule, site policy, effective route policy, service and operation-policy digest,
task ID, exact request digest and length, content type, and validity window. Gateway
checks those values against the active grant and request, then writes a signed
authorization record before contacting the service.

Only HTTP 200, 201, and 202 with one bounded JSON `run_id` count as an accepted
dispatch. Gateway records the observed HTTP status, response length, and run ID,
discards the untrusted upstream body and headers, and returns a new canonical
`{"run_id":"..."}` response with `X-Steward-Task-Receipt: recorded`. A
lifecycle-enabled operation writes this as a distinct durable dispatch receipt. An
exact replay within the retained ledger returns the same stored ID with
`X-Steward-Task-Receipt: replayed` and does not dispatch again. A pending,
conflicting, failed, or unknown result returns a bounded JSON error and is not
automatically retried.

The replay fence is `(tenant_id, instance_id, task_id)`, so a new workload
generation does not make the same logical task spendable again. It is node-local
at-most-once dispatch within one receipt-ledger epoch, not fleet or upstream
exactly-once execution. Gateway restart reconstructs completed spends and pending
lifecycle dispatches. A durable authorization with neither a dispatch nor terminal
record is closed as `outcome_unknown`. Replacing the ledger or advancing to a new
epoch creates a new replay boundary. The service supplies the run ID, so the signed
receipt records what Gateway observed, not whether the agent completed useful work.

If the authorization write or filesystem sync has an ambiguous result, Gateway does
not contact the service. The request and its exact replay return
`evidence_unavailable` until Gateway restarts and verifies the ledger. A complete
authorization is then closed as `outcome_unknown`; if no authorization was retained,
the task remains available for a later submission.

A lifecycle-enabled operation also fixes `steward.task-lifecycle.v1`, a canonical
status-path prefix, a status timeout, and a minimum poll interval in its signed
operation-policy digest. After durable dispatch, clients use the Gateway task
lifecycle endpoints above. They cannot provide an upstream URL or path. Gateway
requests the configured prefix plus the recorded run ID and accepts only one bounded
HTTP 200 JSON object whose `run_id` matches and whose `status` is `queued`, `running`,
`completed`, `failed`, or `cancelled`.

`queued` and `running` are transient observations. A terminal report becomes a
signed terminal receipt with `agent_reported_completed`, `agent_reported_failed`, or
`agent_reported_cancelled`, plus the exact response digest and byte length. These
names deliberately preserve the claim boundary: Gateway records what the agent
reported; it does not validate the work product. See the
[Hermes guide]({{ '/guides/hermes-agent/' | relative_url }}) for the qualified
adapter and the
[Gateway task lifecycle OpenAPI](https://github.com/hardrails/steward/blob/main/openapi/steward-gateway.v1.yaml)
for response and failure schemas.

## Offline operator tools

Executor exposes three authenticated, host-local maintenance operations:

- `GET /v1/maintenance` returns the durable cordon, bounded reason and entry time,
  exact active signed runtime references, and pending journal count.
- `POST /v1/maintenance/enter` accepts one strict `{"reason":"..."}` object no
  larger than 1 MiB. The reason is 1 through 256 bytes of trimmed UTF-8 without
  control characters. An exact retry is idempotent; a different reason returns
  `409 maintenance_conflict`.
- `POST /v1/maintenance/exit` requires an empty body and successful Executor
  reconciliation. It is idempotent and returns the disabled state. It never
  clears an ambiguous journal entry.

All three require the loopback Executor bearer. They are host-administration
operations, not tenant scheduling APIs. Entering maintenance blocks new signed
admission, starts, activation canary dispatch, and activation checkpoints. It does
not stop a workload or remove state. The CLI composes these operations with the
existing signed-runtime destroy endpoint; no separate drain engine exists.

`stewardctl image`, `stewardctl evidence`, `stewardctl permit`, `stewardctl task`,
`stewardctl activation`, `stewardctl rollout`, and `stewardctl upgrade` are CLIs,
not HTTP endpoints. They provide bounded,
policy-bound Open Container Initiative (OCI) inspection and import; offline evidence
verification and export; exact connector- and service-request permit issuance,
verification, dispatch, and receipt correlation; one-node and ordered-fleet
composition of a fixed qualified agent activation contract; authenticated
node-local maintenance and drain; and read-only release and durable-format
inspection. The rollout coordinator uses existing controller
node, command, and evidence-capture APIs; there is no controller `/rollouts`
resource and the controller does not hold rollout signing keys. The coordinator
retains its signed plan authorization and chained batch promotions in the local
workspace, then includes the applicable envelope digest in each rollout command's
signed `authorization_context_digest`. A compatible protocol-4 Executor must
advertise `admission-projection-v1`, `activation-canary-v1`, and
`rollout-authorization-context-v1`. Executor verifies that digest as signed command
data; the coordinator and offline verifier authenticate the referenced envelope.
The final CLI-generated `proof.json` is not an HTTP resource or a signature. Its
plan-authorization and ordered promotion digests bind those exact signed envelopes.
Each target's `admit_command_digest`, `start_command_digest`, and
`canary_command_digest` binds the exact signed outer Executor command envelopes
(`admit`, `start`, and `activation-canary`) into the aggregate proof digest.
Permit issuance consumes an authenticated but unsigned
trust inventory as mismatch preflight; live Gateway configuration remains
authoritative. `task submit`, `status`, `observe`, and `wait` are the online task
operations and contact only an explicit literal-loopback Gateway origin. See
[local operator tools]({{ '/reference/offline-tools/' | relative_url }}) for flags,
output formats, and failure boundaries.

## Common behavior

- Request bodies are bounded before JSON decoding.
- Unknown fields and trailing JSON are rejected where a body is accepted.
- Signed-admission envelopes and payloads also reject duplicate JSON members.
- All JSON errors use `{"error":"code","message":"human-readable detail"}`.
- Standard 404/405 and recovered panic responses use the same shape.
- Runtime references are opaque; clients must not parse meaning from them.
- Executor uplink delivery invokes the same handlers as its direct API. The generic
  supervisor uplink calls the same lifecycle tracker through a bounded dispatcher.
- A version-3 Executor delivery ID is derived from the verified tenant, node, and
  command identity. The unsigned wrapper cannot select an alias. `done` and
  `rejected` are safe terminal results; `failed` and `outcome_unknown` remain
  non-replayable until an operator reconciles the effect.

Multi-tenant uplink uses a node credential and DSSE
`steward.executor-command.v2` statements. DSSE binds a typed payload to its
signature. Site policy must authorize a tenant key for `admit`, `start`, `stop`,
`destroy`, `read`, or `purge`. A site cleanup key may authorize only `stop`,
`destroy`, or `purge`, including after tenant removal. Signatures bind tenant, node,
instance, runtime, generations, sequence, validity window, kind, and payload to
Executor's durable admission record. The bearer cannot select a tenant; legacy
credentials remain single-tenant.

`admit` carries exact `capsule_dsse_base64` and OpenAPI `intent`; identity and
generation must match the command. Positive capabilities are explicit state or
network grants. Network grants require configured Gateway and relay components.
State also requires the dedicated-host-only compatibility flag for a volume without
enforced byte or inode quotas; it is unavailable on shared hosts. A missing
enforcement component returns HTTP 501. Signed admission disables legacy
`POST /v1/workloads`. Uplink lifecycle operations record verified tenant, node, and
generation in journal and evidence.

Inference, task-authorized service, connector, or egress admission returns
`route_policy_digest`, a deterministic non-secret digest of retained Gateway route
settings and public task authority. Executor records and reconciles it; Gateway
rejects semantic route changes while a retained grant references the route.

An authorized-effects admission also returns `effect_mode: authorized`. Signed
tenant policy pins action keys to selected connector IDs, authenticated intent must
explicitly select the mode, and generic egress is unavailable. Executor projects
those narrowed public authorities into immutable Gateway state; private action keys
are never node inputs.

Inference grants expose only the fixed OpenAI-compatible paths listed in the
[positive-capability guide]({{ '/guides/positive-capabilities/' | relative_url }}).
Each model-bearing request needs exactly one top-level `model` matching the grant
alias. Gateway generates `GET /v1/models` from it. Authenticated service paths apply
bounds to HTTP and RFC 6455 WebSockets and close active streams on revocation.

For outbound transport, identity fencing, retry, and reporting details, read
[Executor uplink]({{ '/executor/' | relative_url }}#outbound-executor-uplink),
[supervisor uplink]({{ '/uplink-client/' | relative_url }}),
[disable inbound listener]({{ '/disable-inbound-listener/' | relative_url }}), and
[instance-generation fencing]({{ '/instance-generation-fencing/' | relative_url }}).
