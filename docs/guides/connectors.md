---
title: Broker authenticated API operations
description: Give an agent exact, budgeted HTTPS operations without directly handing it upstream credentials or origins.
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
sudo install -d -o root -g steward-gateway -m 0750 /etc/steward/credentials
sudo install -o steward-gateway -g steward-gateway -m 0600 /dev/null \
  /etc/steward/credentials/ticket-api
printf %s "$TICKET_API_TOKEN" | sudo -u steward-gateway tee \
  /etc/steward/credentials/ticket-api >/dev/null
unset TICKET_API_TOKEN
```

The file must contain one line of 12 to 16,384 visible ASCII bytes. The minimum
reduces false matches when Gateway filters routine response content. Do not put the
value in
`gateway.json`, shell history, a capsule, site policy, or instance intent.

The packaged installer creates a separate Gateway receipt key and configures its
owner-only receipt ledger. Add the connector atomically:

```console
sudo stewardctl gateway connector set \
  -id ticketing \
  -base-url https://tickets.example.com \
  -credential-file /etc/steward/credentials/ticket-api \
  -credential-mode bearer \
  -max-concurrent 2 \
  -max-request-bytes 65536 \
  -max-response-bytes 1048576 \
  -max-seconds 30 \
  -max-calls-per-grant 16 \
  -tenant-budget tenant-a=4194304 \
  -operation create-ticket=POST:/api/tickets
sudo systemctl restart steward-gateway
```

The command validates the complete candidate file, existing signed receipt chain,
and every retained grant before replacing the configuration. The resulting entry
is equivalent to:

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
  ],
  "connector_receipt_tenant_budgets": [
    {
      "tenant_id": "tenant-a",
      "bytes": 4194304
    }
  ]
}
```

Every connector-bearing grant must name an exact tenant in
`connector_receipt_tenant_budgets`; Gateway rejects an unbudgeted grant before it
creates a connector socket. Budgets do not borrow from one another. One tenant
cannot consume another tenant's unused receipt capacity.

Each tenant budget counts the encoded signed record, including its newline, plus
space reserved for the terminal record of every authorized call that has not yet
finished. A budget must be at least 262146 bytes. The table accepts at most 128
tenants, and all budgets together must not exceed the 64 MiB ledger limit.

`base_url` is one exact HTTPS origin. Plain HTTP is rejected unless the operator
adds `allow_insecure_http: true` or passes `-allow-insecure-http`; that exception can
expose the injected credential and should be limited to a protected local network.
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

Validate the complete file before activation:

```console
sudo stewardctl gateway validate -config /etc/steward/gateway.json
```

Reload may add or change an unreferenced connector. A retained workload grant pins
the connector configuration and the loaded credential digest. Changing either
while a stopped or running workload retains the grant rejects the whole reload.
Drain and replace the workload before rotating that authority. For a connector-only
change, run `sudo systemctl reload steward-gateway`.

Changing a receipt identity or tenant budget requires a Gateway restart, not a
reload; run `sudo systemctl restart steward-gateway`. Repeated
`-tenant-budget TENANT=BYTES` flags add or update exact tenants in the existing
table; they never remove an entry. The command splits each value at its final `=`,
so an exact tenant ID such as `tenant=west` remains intact.

To reduce a budget in the current ledger, first drain every retained connector
grant that binds the old route policy. Set a value that still covers the tenant's
verified historical signed lines and any pending terminal reservation, then restart
Gateway. Startup rejects a smaller value. The change produces a new route-policy
digest for future grants and does not reclaim historical bytes.

Removing a tenant with ledger history requires a new receipt file and incremented
receipt epoch. Decide how long to retain and where to checkpoint the old chain,
drain retained grants, preserve the old ledger and public verification material,
then configure the new file and budget table. Steward does not provide in-place
ledger compaction or a budget-removal command.

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

Gateway signs and fsyncs the authorization before DNS or any upstream connection.
For one tenant and logical instance, the same task, connector, and operation cannot
be replayed across generation-bound grants, after a lost response, after grant
deletion, or after mutable Gateway state is removed. Other tenant and logical
instance namespaces remain independent. A replay fails closed rather than guessing
whether an external mutation happened.
Every valid, allowed operation that reaches authorization consumes the connector's
`max_calls_per_grant` budget; an address or upstream error does not restore spent
authority. Malformed, forbidden, and oversized requests do not consume that effect
budget, but a separate fixed per-grant attempt limit bounds repeated invalid work.
Concurrent attempts to spend the final call permit only one request.

Gateway allows at most 32 connector calls across the host and four per grant at a
time, even when a connector's own limit is higher. These fixed ceilings bound
trusted-service memory and reduce one workload's ability to monopolize a connector.

This is a bounded workload grant, not proof of human intent. The workload can mint
task IDs until it exhausts its signed connector and node-configured budget. A later
task-authority layer can narrow that further without changing the connector's
network and credential boundary.

## What is recorded

The admission receipt binds the capsule, site policy, tenant, instance generation,
and effective Gateway policy digest. Connector records use a separate Gateway key
and bind the workload grant, admission policy digest, effective route-policy
digest, connector operation, one-way call digest, authorization, terminal outcome,
HTTP status, and byte counts without storing the credential, request body, response
body, raw task ID, headers, query, or upstream URL. The authorization ledger is also
the replay database. Gateway reserves worst-case space for the matching terminal
record before it authorizes an effect.

Connector responses use an integrity trailer. A clean response ends with
`X-Steward-Connector-Receipt: recorded`; if Gateway cannot fsync the terminal
receipt after an upstream effect, it aborts the stream instead of presenting a
cleanly framed success. After an unclean restart, an authorization without a
terminal record is closed as `outcome_unknown`. That label does not claim whether
the upstream service accepted or applied the request. A `responded` terminal outcome
means Gateway received and relayed a complete HTTP response; it does not interpret
the application's HTTP status as proof that the requested work happened.

Steward itself sends the configured credential only from Gateway to the fixed
upstream operation; it does not directly configure the workload with that
credential or the private upstream origin. Gateway removes credential, cookie,
redirect, and `X-Steward-*` response headers. It also rejects the response if any
header field name, header value, or decoded body stream contains the exact
configured credential, including a match split across body chunks. Header field
names are compared without regard to ASCII letter case. It does not detect an
encoded or transformed credential, private-origin disclosure, or other application
secrets. Use a narrow trusted upstream endpoint.

These records prove that Steward mediated the documented operation inside its node
trust boundary. They do not prove what the prompt meant, that the agent's reason was
honest, that the upstream service applied the request exactly once, or that a
host-root attacker preserved the complete record set.

## Failure behavior

| Error | Meaning |
| --- | --- |
| `connector_denied` | The grant does not contain the connector or exact operation. |
| `invalid_task_id` | The request lacks exactly one valid bounded `X-Steward-Task-ID`. |
| `connector_task_replayed` | That task, connector, and operation was already spent. Steward does not retry an ambiguous external effect. |
| `connector_call_limit` | The generation-bound grant spent its maximum connector calls. |
| `connector_busy` | The connector concurrency ceiling is in use. |
| `connector_rate_limited` | The grant exceeded the fixed attempt budget for the current minute. |
| `address_denied` | The origin resolved only to prohibited or unpinned addresses. |
| `resolution_failed` | Gateway could not resolve the configured origin. The task remains spent and the terminal receipt records the failure. |
| `grant_revoked` | The grant was deactivated while Gateway was resolving the origin. The task remains spent and the terminal receipt records the revocation. |
| `request_too_large` / `response_too_large` | The configured body ceiling was reached. |
| `credential_reflected` | The upstream returned the exact configured credential in a header or decoded body stream. Gateway aborts the response and records a failed terminal outcome. |
| `connector_evidence_quota_exhausted` | HTTP 503. This tenant has no remaining connector receipt capacity; other tenants cannot lend it unused bytes. |
| `evidence_unavailable` | Gateway could not durably record an authorization or terminal result. No upstream effect starts unless authorization was recorded. |
| `upstream_unavailable` | The exact configured origin did not complete the bounded request. The task remains spent. |

Stopping a workload deactivates its connector socket before stopping the agent.
Destroying it removes the live grant and socket, but signed task tombstones and
generation-bound call counts remain until the connector receipt ledger is retired.
A recreated instance uses a new generation-bound grant and cannot reuse the old
connector socket or claims.
