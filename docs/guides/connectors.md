---
title: Broker authenticated API operations
description: Give an agent exact, budgeted HTTPS operations without putting upstream credentials or origins in the workload.
section: How-to
---

# Broker authenticated API operations

A Steward **connector** is a small allowlist of named API operations. The agent
chooses a connector and operation ID; the node operator fixes the upstream HTTPS
origin, method, path, credential type, address policy, and resource limits.

Use a connector when an agent must call an authenticated API. Use ordinary
[signed egress]({{ '/guides/egress/' | relative_url }}) when the agent must speak a
standard protocol directly and may hold its own application credential. Steward
does not add credentials inside an HTTPS `CONNECT` tunnel because doing so would
require TLS interception or would expose the credential to the workload.

Four permissions must agree:

1. the publisher capsule permits the `connector` capability;
2. site policy permits named connector IDs for the tenant;
3. the instance intent requests a subset of those IDs; and
4. the node configuration defines each connector and exact operation.

If any layer is missing, admission fails closed.

## Define one exact operation

Create the credential as an owner-only file. An external secret manager may
materialize this file; Steward does not implement or require a vault.

```console
sudo install -o steward-gateway -g steward-gateway -m 0600 /dev/null \
  /etc/steward/credentials/ticket-api
printf %s "$TICKET_API_TOKEN" | sudo -u steward-gateway tee \
  /etc/steward/credentials/ticket-api >/dev/null
unset TICKET_API_TOKEN
```

The file must contain one non-empty line. Do not put the value in
`gateway.json`, shell history, a capsule, site policy, or instance intent.

Add a connector to `/etc/steward/gateway.json`:

```json
{
  "connectors": [
    {
      "id": "ticketing",
      "base_url": "https://tickets.example.com",
      "credential_file": "/etc/steward/credentials/ticket-api",
      "credential_mode": "bearer",
      "allowed_cidrs": [],
      "max_concurrent": 2,
      "max_request_bytes": 65536,
      "max_response_bytes": 1048576,
      "max_seconds": 30,
      "max_calls_per_grant": 16,
      "operations": [
        {
          "id": "create-ticket",
          "method": "POST",
          "path": "/api/tickets"
        }
      ]
    }
  ]
}
```

`base_url` is one HTTP or HTTPS origin; production credentials should use HTTPS.
An operation contains one exact method and path. It cannot contain a query,
fragment, user information, wildcard, path parameter, or redirect target. Split
different paths or methods into separate operations so the authority remains easy
to review.

`credential_mode` is either `bearer` or `x-api-key`. Gateway removes agent-supplied
Authorization, Proxy-Authorization, Cookie, and API-key headers, then adds only the
configured credential at the last hop. The agent cannot choose a header name,
scheme, origin, address, method, or path.

Gateway resolves the configured hostname and dials the exact checked address. It
rejects private and IANA special-purpose ranges unless `allowed_cidrs` explicitly
contains the resolved address. Leave the list empty for a public API. For a private
on-site endpoint, add only its narrow network:

```json
"allowed_cidrs": ["10.40.12.0/24"]
```

Never allow cloud instance-metadata ranges for an agent connector.

Validate the complete file before reload:

```console
sudo stewardctl gateway validate -config /etc/steward/gateway.json
sudo systemctl reload steward-gateway
```

Reload may add or change an unreferenced connector. A retained workload grant pins
the connector configuration and the loaded credential digest. Changing either
while a stopped or running workload retains the grant rejects the whole reload.
Drain and replace the workload before rotating that authority.

## Bind the connector in signed authority

Permit the capability in the publisher capsule:

```json
"capabilities": {
  "state": false,
  "inference": true,
  "service": true,
  "egress": false,
  "connector": true
}
```

Permit the connector ID in the tenant rule:

```json
{
  "tenant_id": "tenant-a",
  "connector_ids": ["ticketing"]
}
```

Request the same subset in the instance intent:

```json
"capabilities": {
  "state": false,
  "inference": true,
  "service": true,
  "egress": false,
  "connector": true
},
"connector_ids": ["ticketing"]
```

Sign and install the artifacts as described in
[signed admission]({{ '/guides/signed-admission/' | relative_url }}). A connector
cannot be requested through the unsigned compatibility endpoint.

## Call it from the agent

When the grant is active, Executor supplies this non-secret endpoint to the
workload:

```text
STEWARD_CONNECTOR_URL=http://steward-relay:8081
```

Send one strict JSON request to the logical operation. Use a fresh, unpredictable
task ID for each intended external effect:

```console
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -H 'X-Steward-Task-ID: task-4bd6ce188f8b4e09a92af56d59a5df0e' \
  --data '{"title":"Review backup alarm","severity":"high"}' \
  "$STEWARD_CONNECTOR_URL/v1/connectors/ticketing/operations/create-ticket"
```

Gateway validates and durably spends the task claim before opening the upstream
request. The same task, connector, and operation cannot be replayed after a lost
response or process restart. A replay fails closed rather than guessing whether an
external mutation happened. Every attempt also consumes the connector's
`max_calls_per_grant` budget; an upstream error does not restore spent authority.
Concurrent attempts to spend the final call permit only one request.

This is a bounded workload grant, not proof of human intent. The workload can mint
task IDs until it exhausts its signed connector and node-configured budget. A later
task-authority layer can narrow that further without changing the connector's
network and credential boundary.

## What is recorded

The admission receipt binds the capsule, site policy, tenant, instance generation,
and effective Gateway policy digest. Connector records bind the workload grant,
connector operation, one-way task digest, decision, outcome, status class, and byte
counts without storing the credential, request body, response body, raw task ID,
headers, query, or upstream URL.

These records prove that Steward mediated the documented operation inside its node
trust boundary. They do not prove what the prompt meant, that the agent's reason was
honest, that the upstream service applied the request exactly once, or that a
host-root attacker preserved the complete record set.

## Failure behavior

| Error | Meaning |
| --- | --- |
| `connector_denied` | The grant does not contain the connector or exact operation. |
| `task_id_required` | The request lacks a valid bounded `X-Steward-Task-ID`. |
| `task_replay` | That task, connector, and operation was already spent. Steward does not retry an ambiguous external effect. |
| `call_budget_exhausted` | The retained grant spent its maximum connector calls. |
| `connector_busy` | The connector concurrency ceiling is in use. |
| `address_denied` | The origin resolved only to prohibited or unpinned addresses. |
| `request_too_large` / `response_too_large` | The configured body ceiling was reached. |
| `state_unavailable` | Gateway could not persist the spend before the external effect, so it refused the call. |
| `upstream_unavailable` | The exact configured origin did not complete the bounded request. The task remains spent. |

Stopping a workload deactivates its connector socket before stopping the agent.
Destroying it removes the grant, socket, task claims, and counters. A recreated
instance receives a new generation-bound grant; it cannot reuse the old connector
socket or claims.
