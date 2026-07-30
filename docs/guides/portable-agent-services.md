---
title: Run a portable agent service
description: Package any agent behind Steward's fixed health, invocation, and bounded result contract without moving application workflows into Steward.
section: Guide
---

# Run a portable agent service

Use `steward.agent-service.v1` when an agent is not one of Steward's qualified
runtime adapters but can run as an immutable OCI image behind a small HTTP API.
The contract is language- and model-provider-neutral. Steward supplies signed
deployment authority, private routing, idempotent task dispatch, lifecycle
observation, result bounds, and evidence. Your service supplies the agent's
reasoning and application result.

This is transport compatibility, not worker qualification. Steward does not
assert that a conforming service follows instructions, cites sources, evaluates
output correctly, or performs safe external actions.

## Inspect the exact contract

The installed CLI emits the machine-readable deployment and service constants:

```console
stewardctl agent service contract
```

The authoritative HTTP schemas are in the
[portable agent service OpenAPI](https://github.com/hardrails/steward/blob/main/openapi/steward-agent-service.v1.yaml).
The fixed runtime boundary is:

| Field | Value |
| --- | --- |
| Runtime engine | `agent-service` |
| Adapter contract | `steward.agent-service.v1` |
| Profile | `agent-service-v1@v1` |
| Process command | `serve` |
| Linux identity | `65532:65532` |
| Mutable state | `/state` |
| Private service | `agent-api:8080` |
| Health | `GET /v1/healthz` |
| Invoke | `POST /v1/invocations` |
| Observe | `GET /v1/invocations/{run_id}` |

The container must have an executable named `serve` on its `PATH`. It must not
require a writable root filesystem, root identity, ambient cloud credentials, a
published host port, or mutable files outside `/state` and `/tmp`.

## Implement the three endpoints

Health identifies the exact deployed release:

```json
{
  "schema_version": "steward.agent-health.v1",
  "status": "ready",
  "adapter_contract": "steward.agent-service.v1",
  "deployment_id": "research-worker",
  "release_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

Return HTTP 200 only for `ready`. Return HTTP 503 with `not_ready` or `draining`
when the service cannot accept another invocation.

Invocation requests are strict JSON objects of at most 64 KiB:

```json
{
  "schema_version": "steward.agent-invocation.v1",
  "invocation_id": "mission-42-stage-research",
  "input": {
    "question": "Compare the primary sources and retain material uncertainty."
  }
}
```

On a new accepted invocation, return HTTP 202:

```json
{"run_id":"run_0123456789abcdef"}
```

The service must bind `invocation_id` to the exact request. An exact replay
returns the same `run_id` with HTTP 200. Reusing the identity with different
bytes returns HTTP 409 and must not start new work. Gateway already prevents
ordinary signed-task replay; service-side idempotency keeps recovery safe across
an independently replaced Gateway evidence epoch.

Status responses are at most 1 MiB:

```json
{
  "schema_version": "steward.agent-invocation.v1",
  "invocation_id": "mission-42-stage-research",
  "run_id": "run_0123456789abcdef",
  "status": "completed",
  "result": {
    "artifact_ref": "objects/reports/report-42.json",
    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }
}
```

Use `queued` or `running` before a terminal `completed`, `failed`, or `cancelled`
state. A terminal response must remain byte-stable for the retained run lifetime;
Gateway may fetch it again after an interrupted observation and compare its exact
digest and length. Store large reports, datasets, media, and traces in a separate
artifact system and return a bounded reference plus content digest.

## Author the portable application

Create a JSON definition and replace the image placeholder with the immutable
digest you built:

```json
{
  "schema": "steward.agent.v1",
  "name": "portable-worker",
  "runtime": {
    "engine": "agent-service",
    "image": "registry.example/portable-worker@sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "adapter_contract": "steward.agent-service.v1"
  },
  "tool_profile": "workspace",
  "model": {"route": "local/default"},
  "resources": {
    "cpu_millis": 1000,
    "memory_mib": 1024,
    "disk_mib": 2048,
    "pids": 256
  },
  "placement": {
    "architectures": ["amd64"],
    "isolation": "hardened"
  },
  "state": {"persistent": true},
  "lifetime": {"mode": "service"}
}
```

The neutral runtime accepts only the `workspace` tool profile. That name does not
grant workspace access or define a workflow; it means the portable bundle asks
for no Hermes-specific research or coding profile.

Validate and build the bundle:

```console
stewardctl agent validate -file agent.json
stewardctl agent build -file agent.json -out agent.bundle.json
```

## Publish and activate it

Authorize `agent-api` when creating the site. The service ID is authority and is
not inferred from the image:

```console
stewardctl site init steward-site \
  -tenant-id default \
  -repository registry.example/portable-worker \
  -service-id agent-api
```

Use the normal image inspection, signed publication, deployment authorization,
and desired-state flow from [Build and run an agent]({{ '/guides/build-agents/' |
relative_url }}). The composed publisher selects the fixed
`agent-service-v1@v1` profile from the bundle and refuses a different command,
port, state path, or adapter contract.

On the selected node, configure the exact invocation operation and export its
tenant signing inventory:

```console
sudo stewardctl agent service activate \
  -bundle agent.bundle.json \
  -tenant-id default \
  -node-id node-a \
  -trust-out /secure/steward/agent-service-trust.json
```

Run the exact reload or restart action in the JSON response. Transfer the
non-secret trust inventory through an authenticated channel, connect the task
key, and submit requests through the existing `stewardctl task` or Control task
courier. Gateway records authorization before it contacts the service, returns
the same recorded run identity on an exact replay, and never automatically
replaces an invocation after an uncertain outcome.

## Deliberate limits

The portable contract does not add a workflow engine, team protocol, prompt
format, semantic schema, memory model, result evaluator, report renderer, secret
vault, public ingress, automatic scale-to-zero, or provider SDK. Those concerns
remain replaceable above or beside Steward. Add network, inference, connector,
and secret authority through Steward's existing positive-capability contracts;
do not put reusable credentials in the worker image or invocation body.
