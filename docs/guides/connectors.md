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

Four permissions always agree:

1. the publisher capsule permits the `connector` capability;
2. site policy permits named connector IDs for the tenant;
3. the instance intent requests a subset of those IDs; and
4. the node configuration defines each connector and exact operation.

If any layer is missing, admission fails closed.

For a connector that requires independent approval of each effect, enable a fifth
layer: a tenant-scoped action authority signs a short-lived **action permit** for
one exact request. Gateway then requires the workload grant and the permit. This
mode is opt-in per connector; a connector without action authorities keeps the
four-layer, budgeted behavior.

For sensitive operations, use
[Authorized Effects]({{ '/guides/authorized-effects/' | relative_url }}). It adds
signed-policy continuity to the fifth layer: tenant policy pins each action key to
connector IDs, intent explicitly selects the mode, generic egress is prohibited,
Gateway accepts only version-2 permits, and format-5 evidence records the enforced
mode and exact operation policy. Steward assumes the agent is compromised for this
decision; it does not ask the agent to detect prompt injection.

## Define one exact operation

Create the credential as an owner-only file. An external secret manager may
materialize this file; Steward does not implement or require a vault. For a
hardened OpenBao template and provider-neutral readiness check, see
[Store and distribute Gateway credentials]({{ '/guides/secrets/' | relative_url }}).

```console
sudo install -d -o root -g steward-gateway -m 0750 /etc/steward/credentials
sudo install -d -o root -g root -m 0700 /root/steward-staged-credentials
# First stage the value at this path as a root-owned mode-0600 regular file.
sudo install -o steward-gateway -g steward-gateway -m 0600 \
  /root/steward-staged-credentials/ticket-api \
  /etc/steward/credentials/ticket-api
sudo rm -- /root/steward-staged-credentials/ticket-api
```

The file must contain 12 to 16,384 ASCII bytes in the range `0x21` through `0x7e`,
with no whitespace. The minimum reduces false matches when Gateway filters routine
response content. Do not put the value in `gateway.json`, shell history, a capsule,
site policy, or instance intent.

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

## Require one signed action permit

Use an action permit when the admitted workload may choose *when* to ask for work,
but another authority must approve the exact outbound operation and request before
Gateway can cause an external effect. Keep the signing key off the Steward node. A
disconnected signing station is sufficient; no hosted identity or policy service
is required.

On the signing station, create a dedicated Ed25519 key pair. The private output is
owner-only and `stewardctl permit issue` rejects a private key readable by group or
other users:

```console
mkdir -m 0700 action-authority
stewardctl keygen \
  -private-out action-authority/approver-a.private.pem \
  -public-out action-authority/approver-a.public \
  -key-id approver-a
```

Transfer only `approver-a.public` to the node through your authenticated artifact
process. Add it to the complete connector definition:

```console
sudo stewardctl gateway connector set \
  -id ticketing \
  -base-url https://tickets.example.com \
  -credential-file /etc/steward/credentials/ticket-api \
  -credential-mode bearer \
  -credential-epoch 1 \
  -max-concurrent 2 \
  -max-request-bytes 65536 \
  -max-response-bytes 1048576 \
  -max-seconds 30 \
  -max-calls-per-grant 16 \
  -tenant-budget tenant-a=4194304 \
  -operation create-ticket=POST:/api/tickets \
  -action-node-id node-a \
  -action-authority approver-a=/srv/transfer/approver-a.public \
  -action-authority-tenant approver-a=tenant-a \
  -max-action-permit-seconds 300
sudo systemctl reload steward-gateway
```

`action_permit_node_id` is one stable node identity shared by all permit-enabled
connectors and must match the instance intent's node. Each action key belongs to
one exact tenant. The same public key bytes cannot be registered under another key
ID in one configuration. The configurator refuses to change an existing key ID to
another key or tenant; use a new ID for rotation. A connector accepts at most eight
action keys; the complete configuration accepts at most 64. The local maximum
permit lifetime is one through 86,400 seconds.

`credential_epoch` is an operator-managed positive counter used only by a
permit-enabled connector. It is part of the effective route-policy digest.
Increment it whenever the upstream credential's authority changes, including
replacement with a new value, even though Gateway also pins the loaded credential
digest. The epoch makes the rotation explicit in policy and prevents a permit
issued for the prior admitted route policy from surviving that change.

The relevant configuration is equivalent to:

```json
{
  "action_permit_node_id": "node-a",
  "action_authorities": [
    {
      "key_id": "approver-a",
      "tenant_id": "tenant-a",
      "public_key": "<canonical-base64-Ed25519-public-key>"
    }
  ],
  "connectors": [
    {
      "id": "ticketing",
      "credential_epoch": 1,
      "action_authority_ids": ["approver-a"],
      "max_action_permit_seconds": 300,
      "operations": [
        {"id": "create-ticket", "method": "POST", "path": "/api/tickets"}
      ]
    }
  ]
}
```

The abbreviated connector above omits required origin, credential, address, and
resource fields already shown in the complete example. Do not use it as a full
configuration file.

After validating the node configuration, export the portable action-trust
inventory:

```console
sudo stewardctl gateway connector trust \
  -config /etc/steward/gateway.json \
  -tenant-id tenant-a > action-trust.json
```

The required tenant filter prevents one tenant's signing station from receiving
another tenant's action-authority or connector metadata. The inventory contains the
selected tenant, node ID, tenant/key relationships, public-key digests, connector
origins, credential modes, exact operation methods and paths, operation-policy
digests, credential epochs, and lifetime ceilings. It contains no private key or
upstream credential.
It is also **unsigned**. Authenticate its source and integrity when transferring it
to the signing station. `permit issue` uses it only as an operator preflight against
common node/key/tenant/operation mismatches. Gateway's live, validated configuration
remains the final enforcement authority; possession of an inventory cannot add
authority to a node.

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
  "connector_ids": ["ticketing"],
  "authorized_effects": {
    "mode": "required",
    "keys": [{
      "key_id": "approver-a",
      "public_key": "<canonical-base64-Ed25519-public-key>",
      "connector_ids": ["ticketing"]
    }]
  }
}
```

The action public key appears once in Gateway configuration and once in signed
tenant policy by design. Those two values must be identical. Each JSON object has
only one `public_key` member; repeating a member inside one object is invalid.

Request the same subset in the instance intent:

```json
"capabilities": {
  "state": false,
  "inference": true,
  "service": true,
  "egress": false,
  "connector": true
},
"connector_ids": ["ticketing"],
"effect_mode": "authorized"
```

The policy block and `effect_mode` are required only for Authorized Effects. A
standard permit-enabled connector can omit both, but then node configuration—not
signed tenant policy—selects the permit requirement. Do not use generic egress in
authorized mode.

Sign and install the artifacts as described in
[signed admission]({{ '/guides/signed-admission/' | relative_url }}). A connector
cannot be requested through the unsigned compatibility endpoint.

## Call it from the agent

When the grant is active, Executor supplies this non-secret endpoint to the
workload:

```text
STEWARD_CONNECTOR_URL=http://steward-relay:8081
```

For a connector without action authorities, send one strict JSON request to the
logical operation. Use a fresh, unpredictable task ID for each intended external
effect:

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

Without an action authority, this is a bounded workload grant, not proof of human
intent: the workload can mint task IDs until it exhausts the connector budget. A
permit-enabled connector adds independently signed, exact-request authority. It
still does not prove that a natural-language instruction was correct or that the
upstream will apply the request exactly once.

### Issue and send an exact-request permit

For a permit-enabled connector, retain the exact admission response returned for
the instance and prepare the exact request file. Transfer the admission response,
instance intent, request, and authenticated action-trust inventory to the signing
station. Treat the resulting permit as short-lived authorization even though it
cannot authorize different bytes.

For host-local admission, capture that response directly:

```console
sudo stewardctl node admit \
  -token-file /etc/steward/executor-token \
  -capsule capsule.dsse.json \
  -intent instance-intent.json > admission.json
```

This local path requires the explicit host-admin-intent option described in
[signed admission]({{ '/guides/signed-admission/' | relative_url }}). A production
control plane can supply the same bounded response from its authenticated
tenant-admission flow.

```console
umask 077
printf '%s' '{"title":"Review backup alarm","severity":"high"}' > request.json

stewardctl permit issue \
  -admission admission.json \
  -intent instance-intent.json \
  -trust action-trust.json \
  -request request.json \
  -connector-id ticketing \
  -operation-id create-ticket \
  -task-id task-4bd6ce188f8b4e09a92af56d59a5df0e \
  -valid-for 5m \
  -clock-skew 5s \
  -key action-authority/approver-a.private.pem \
  -key-id approver-a \
  -out action-permit.dsse.json \
  -header-out action-permit.header
```

The command refuses to overwrite either owner-only output. It signs a canonical
single-signature DSSE envelope that binds node, tenant, instance, generation,
capsule, admission policy, effective route policy, connector, operation, task ID,
operation-policy digest, exact request SHA-256 and length, outbound content type,
and validity times. The operation-policy digest commits to the connector ID,
canonical upstream origin, credential injection mode, credential epoch, operation
ID, HTTP method, and exact path without exposing the credential. The non-secret
mode is `bearer` or `x-api-key` and identifies the header Gateway will use. For
POST, PUT, and PATCH, the request must
contain one strict JSON value. Steward hashes those exact bytes without
reformatting and binds `application/json`. For GET, HEAD, and DELETE, omit
`-request`; the permit binds an empty request and empty content type.

When admission and intent select Authorized Effects, the command emits
`steward.action-permit.v2` with `effect_mode` fixed to `authorized`. Gateway rejects
a version-1 permit for that grant. A standard permit-enabled connector emits and
requires version 1.

Standard output contains only the exact permit digest. Standard error contains one
canonical JSON approval summary with the exact target, request digest and byte
count, validity window, authority, and resulting permit digest. Keep the streams
separate in automation and compare the summary with independently reviewed request
bytes before releasing the permit. It excludes request content and cannot prove
that the approver understood hostile context or the external effect.

`-clock-skew` moves `not_before` earlier without extending the `-valid-for`
interval. The default allowance is five seconds, the maximum is five minutes, and
it must be shorter than the validity interval. Keep node and signing-station clocks
synchronized and use the smallest allowance that covers measured error.

Deliver the exact request, task ID, and header value through the application's
authenticated work channel. The workload must send the same bytes; `--data-binary`
avoids curl reformatting them:

```console
ACTION_PERMIT="$(tr -d '\n' < action-permit.header)"
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -H 'X-Steward-Task-ID: task-4bd6ce188f8b4e09a92af56d59a5df0e' \
  -H "X-Steward-Action-Permit: $ACTION_PERMIT" \
  --data-binary @request.json \
  "$STEWARD_CONNECTOR_URL/v1/connectors/ticketing/operations/create-ticket"
unset ACTION_PERMIT
```

Gateway accepts exactly one canonical, unpadded base64url permit header. It checks
the signing key's tenant scope and every signed binding against the active grant,
route policy, exact origin, method, path, credential injection mode and epoch, task
ID, content type, and body bytes. It then fsyncs the authorization before DNS or an
upstream connection.
If the permit expires while that durable write is in progress, Gateway records
`action_permit_expired`, keeps the task spent, and does not contact the upstream.

### Verify and audit a permit offline

Verify a permit at the current time and compare its request binding:

```console
stewardctl permit verify \
  -in action-permit.dsse.json \
  -public-key action-authority/approver-a.public \
  -key-id approver-a \
  -request request.json
```

For a historical check, add `-at 2026-07-13T19:22:00Z`. The value must be canonical
UTC RFC 3339 at whole-second precision. Verification reports the evaluation time,
key ID, exact envelope digest, and complete signed statement. `-max-validity`
applies an independent local lifetime ceiling and cannot exceed 24 hours.

Correlate the permit with a copied signed Gateway receipt chain:

```console
stewardctl permit audit \
  -in action-permit.dsse.json \
  -public-key action-authority/approver-a.public \
  -key-id approver-a \
  -request request.json \
  -receipts connector-receipts.ndjson \
  -receipt-public-key connector-receipts.public \
  -receipt-node-id steward-0123456789abcdef0123456789abcdef/gateway \
  -receipt-epoch 1 \
  -expected-sequence '<retained-sequence>' \
  -expected-chain-hash 'sha256:<retained-chain-hash>'
```

`permit audit` verifies the whole mixed-format receipt chain, finds the exact
permit digest, checks every available grant, task, request, policy, operation, and
authority-key binding, and verifies that the permit was valid at the signed
authorization observation time. A terminal record may be absent when an outcome
is still unknown. The optional expected head detects a removed or advanced suffix
relative to an independently retained checkpoint.

### Rotate or remove action authority

A retained grant pins the connector's credential epoch, action-key digests and
tenant scopes, node ID, lifetime, operations, and other route fields. Drain and
destroy every retained workload grant that uses the connector before changing any
of them; Gateway rejects a reload that would change authority beneath a retained
grant.

For a credential rotation, replace the owner-only credential through your secret
process, increment `-credential-epoch`, rewrite the complete connector definition,
and reload Gateway before admitting replacement workloads. For an action-key
rotation, add a new key ID and public key rather than changing an existing ID. To
stage more than one accepted key, repeat `-action-authority` for every key that the
connector should retain and provide `-action-authority-tenant` for each new key.
After new workloads use the new route policy, drain again before removing the old
key. Unreferenced keys are pruned from the configuration.

`-clear-action-permit` deliberately returns that connector to the broader
grant-and-task-budget model. It cannot be combined with action-authority flags.
It also removes `credential_epoch`, which is part of only the permit-enabled
contract. Treat that operation as a security-policy downgrade, drain retained
grants first, and record the operator approval.

## What is recorded

The admission receipt binds the capsule, site policy, tenant, instance generation,
and effective Gateway policy digest. Connector records use a separate Gateway key
and bind the workload grant, admission policy digest, effective route-policy
digest, connector operation, one-way call digest, authorization, terminal outcome,
HTTP status, and byte counts without storing the credential, request body, response
body, raw task ID, headers, query, or upstream URL. The authorization ledger is also
the replay database. Gateway reserves worst-case space for the matching terminal
record before it authorizes an effect.

Permit-backed records additionally contain the action-authority key ID, exact
permit-envelope digest, and exact request digest. Legacy connector events use
receipt schema `steward.connector-receipt.v1`; permit-backed events use
`steward.connector-receipt.v2`. Historical two-record agent-service tasks use
`steward.connector-receipt.v3`; current lifecycle tasks use
`steward.connector-receipt.v4` and add task-local sequence and hash links across
authorization, dispatch, and terminal records. Authorized connector calls use
`steward.connector-receipt.v5`; they add the explicit effect mode and exact
operation-policy digest. A stable pre-effect permit denial may add one format-5
marker per retained grant without claiming a verified permit or authority key. One
chain may contain all five schemas, and the verifier checks them as one sequence.
Configuring any action authority requires a reader for format 2, configuring any
current service-task operation requires a reader for format 4, and an authorized
grant requires format 5, even before its first accepted call.
Service-task records carry exact permit and request digests, service and
operation-policy bindings, bounded status, and an observed run ID, but no raw
prompt or request body. See the
[tenant-signed service-task boundary]({{ '/limitations/' | relative_url }}#tenant-signed-service-task-boundary).

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
| `action_permit_denied` | HTTP 403. A permit is missing, duplicated, malformed, outside its validity window, signed by the wrong tenant key, uses the wrong schema/effect mode, or mismatches the live grant, route policy, task, operation, or exact request. The workload receives this generic message; Gateway writes the specific reason to its host service log. Authorized mode writes at most one stable denial marker per retained grant; it is the first observed attacker-selected invalid request, not an exhaustive denial log. If that marker cannot be persisted, the call fails closed with HTTP 503. The connector's fixed per-grant attempt limit also bounds repeated failures. |
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
