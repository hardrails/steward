---
title: APIs and protocol schemas
description: Authoritative Steward supervisor and Executor OpenAPI contracts, endpoint summaries, authentication, error shapes, and outbound uplink protocol documentation.
section: Reference
---

# APIs and protocol schemas

The hand-written OpenAPI documents are the authoritative public HTTP contracts. If
implementation behavior and a document differ, that is a defect to fix—not an
undocumented extension to rely on.

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
| `POST /v1/instances/batch` | Execute a bounded ordered batch |
| `GET /v1/instances/{runtime_ref}` | Read instance state |
| `POST .../start`, `.../stop`, `.../hibernate` | Apply a lifecycle transition |
| `DELETE /v1/instances/{runtime_ref}` | Destroy and release identity |
| `GET /v1/capabilities` | Discover version and optional capabilities |
| `GET /v1/healthz`, `GET /v1/readiness` | Liveness and readiness |
| `GET /metrics` | Optional Prometheus text exposition |

The loopback API has no built-in authentication. Keep it loopback-only, place it
behind an authenticated host control boundary, or disable it and use the authenticated
outbound uplink.

## Executor API

Default base URL: `http://127.0.0.1:8090`

Every endpoint except `GET /v1/healthz` requires
`Authorization: Bearer <token-from-token-file>`.

| Method and path | Purpose |
| --- | --- |
| `POST /v1/admissions` | Verify capsule + local policy + fenced intent, journal the mutation, and create a receipt-bound workload |
| `POST /v1/state/purge` | Permanently purge an inactive, authorized state lineage with a receipt |
| `POST /v1/workloads` | Validate and create a stopped gVisor container |
| `GET /v1/workloads/{runtime_ref}` | Read observed container state |
| `POST .../start`, `.../stop` | Idempotent lifecycle operation |
| `GET .../logs` | Read a combined log tail capped at 1 MiB |
| `DELETE /v1/workloads/{runtime_ref}` | Idempotently remove a managed workload |
| `GET /v1/healthz` | Process liveness |

## MCP server

`steward-mcp` implements MCP revision `2025-11-25` over stdio. It exposes
admit, status, logs, start, stop, destroy, and state-purge tools by calling the
same loopback Executor API. It is an operations adapter, not another authority
or a remotely exposed MCP endpoint. See [MCP setup]({{ '/guides/mcp/' | relative_url }}).

## Common behavior

- Request bodies are bounded before JSON decoding.
- Unknown fields and trailing JSON are rejected where a body is accepted.
- Signed-admission envelopes and payloads also reject duplicate JSON members.
- All JSON errors use `{"error":"code","message":"human-readable detail"}`.
- Standard 404/405 and recovered panic responses use the same shape.
- Lifecycle references are opaque; clients must not parse meaning from them.
- Uplink delivery invokes the same handlers as direct APIs.

The outbound Executor command kind `admit` carries the exact
`capsule_dsse_base64` plus instance `intent` object documented by the OpenAPI
schema. Its tenant, node, instance, and generation must match the enrolled uplink
command identity. Positive capability requests are enforced through the configured
state or gateway/relay topology and return HTTP 501 if that topology is absent.
When signed admission is configured, legacy `POST /v1/workloads` creation is
disabled. Uplink-authenticated start, stop, and destroy carry the same tenant/node/
generation principal into the lifecycle journal and receipt chain.

For outbound transport, identity fencing, retry, and reporting details, read
[Uplink client]({{ '/uplink-client/' | relative_url }}),
[disable inbound listener]({{ '/disable-inbound-listener/' | relative_url }}), and
[instance-generation fencing]({{ '/instance-generation-fencing/' | relative_url }}).
