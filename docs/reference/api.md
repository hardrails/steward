---
title: APIs and protocol schemas
description: Authoritative Steward supervisor and Executor OpenAPI contracts, endpoint summaries, authentication, error shapes, and outbound uplink protocol documentation.
section: Reference
---

# APIs and protocol schemas

The OpenAPI documents are Steward's public HTTP contracts. OpenAPI describes
endpoints and schemas in machine-readable form. Any behavior/specification mismatch
is a defect, not an extension clients should use.

- [Steward supervisor OpenAPI](https://github.com/hardrails/steward/blob/main/openapi/steward.v1.yaml)
- [Steward Executor OpenAPI](https://github.com/hardrails/steward/blob/main/openapi/steward-executor.v1.yaml)
- [Raw supervisor YAML](https://raw.githubusercontent.com/hardrails/steward/main/openapi/steward.v1.yaml)
- [Raw Executor YAML](https://raw.githubusercontent.com/hardrails/steward/main/openapi/steward-executor.v1.yaml)

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

| Method and path | Purpose |
| --- | --- |
| `POST /v1/admissions` | Verify a publisher-signed profile, local policy, and tenant-bound instance request; journal the mutation; and create a receipt-bound workload |
| `POST /v1/state/purge` | Permanently purge an inactive, authorized state lineage with a receipt |
| `POST /v1/workloads` | Validate and create a stopped gVisor container |
| `GET /v1/workloads/{runtime_ref}` | Read observed container state |
| `POST .../start`, `.../stop` | Idempotent lifecycle operation; while reconciliation is degraded, start is blocked and stop becomes a safety-only containment operation |
| `GET .../logs` | Read a combined log tail capped at 1 MiB |
| `GET .../egress` | Read bounded allow/deny, byte, and last-destination statistics for a signed egress grant |
| `DELETE /v1/workloads/{runtime_ref}` | Remove a managed workload; unsigned mode treats absence as success, while signed mode requires an authorized retained tombstone |
| `GET /v1/healthz` | Process liveness |
| `GET /v1/readiness` | Report readiness and the latest bounded reconciliation summary for present signed runtimes |

Executor readiness describes the latest scan of present signed runtimes. With no
present runtime that needs Gateway, it does not probe Gateway health. Capability
availability is checked separately during admission and may still fail closed.
When readiness is 503, signed admission, start, destroy, and state purge are
blocked. An authenticated stop can still deactivate the Gateway grant identified
by the retained signed admission record and stop exactly identified local agent and
relay containers. It never settles the operation journal or removes a drifted object.

## MCP server

`steward-mcp` implements Model Context Protocol (MCP) `2025-11-25` over standard
input/output. Its admit, status, logs, egress, start, stop, destroy, and state-purge
tools call the loopback Executor API. It is a local adapter, not another authority
or remote endpoint. See
[MCP setup]({{ '/guides/mcp/' | relative_url }}).

## Offline operator tools

`stewardctl image`, `stewardctl evidence`, and `stewardctl upgrade` are local CLIs,
not HTTP endpoints.
They provide bounded, policy-bound Open Container Initiative (OCI) inspection and
import; offline evidence verification and export; and read-only release drain and
durable-format inspection. See
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

Inference or egress returns `route_policy_digest`, a deterministic non-secret digest
of retained Gateway route settings. Executor records and reconciles it; Gateway
rejects semantic route changes while a retained grant references the route.

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
