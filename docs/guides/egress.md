---
title: Configure signed HTTP(S) egress
description: Create named deny-by-default routes, bind them through signed admission, test HTTPS CONNECT, and inspect safe egress audit statistics.
section: How-to
---

# Configure signed HTTP(S) egress

Steward v1.4 gives proxy-aware agents useful outbound HTTP, HTTPS, SSE, and
WebSockets-over-HTTPS without giving the container a raw Internet route. Four
authorities must agree:

1. the publisher capsule permits the `egress` capability;
2. site policy permits named route IDs for the tenant;
3. the instance intent requests a subset of those IDs; and
4. the node operator maps each ID to destinations and hard limits.

Anything missing is denied. The unsigned compatibility endpoint cannot request
egress.

## 1. Define a node route

The safe configurator preserves file ownership, renders to a temporary file,
validates the complete Gateway configuration, fsyncs it, and then renames it:

```console
sudo stewardctl gateway route set \
  -config /etc/steward/gateway.json \
  -id public-web \
  -destination api.github.com:443 \
  -destination '*.githubusercontent.com:443' \
  -max-concurrent 8 \
  -max-request-bytes 16777216 \
  -max-response-bytes 268435456 \
  -max-seconds 900
sudo systemctl reload steward-gateway
```

An exact hostname does not match subdomains. `*.example.com` matches one or more
subdomain labels but not `example.com`; list both when both are required. There is
no open or default-allow rule.

Public IPs are accepted only after the Gateway resolves the hostname and pins the
exact checked address for the dial. Private, loopback, and link-local addresses
require an explicit CIDR pin:

```console
sudo stewardctl gateway route set \
  -id internal-api \
  -destination api.corp.example:8443 \
  -allow-cidr 10.40.0.0/16
sudo systemctl reload steward-gateway
```

The CIDR applies to every destination supplied in that command. Use separate route
IDs when destinations need different address pins. Metadata endpoints such as
`169.254.169.254` stay unreachable unless the host operator explicitly adds their
CIDR; do not do that for agent workloads.

`systemctl reload` is atomic. It can add or change route definitions and rotate the
Gateway service token without dropping active connections. A reload that removes a
route referenced by any persisted grant is rejected, leaving the running policy
unchanged. Changing `max_concurrent` while that route has in-flight requests is
also rejected instead of resetting the live limit; retry when the route is idle.
`systemctl reload` only delivers the signal, so confirm `configuration reloaded`
in the Gateway journal when automating a policy rollout.

## 2. Bind the route in signed authority

Add the route ID to the tenant rule in `site-policy.json`:

```json
{
  "tenant_id": "tenant-a",
  "publisher_key_ids": ["publisher-1"],
  "resource_ceiling": {
    "memory_bytes": 1073741824,
    "cpu_millis": 2000,
    "pids": 256
  },
  "egress_route_ids": ["public-web"]
}
```

Set the capsule ceiling:

```json
"capabilities": {
  "state": true,
  "inference": true,
  "service": false,
  "egress": true
}
```

Then request the route in the instance intent:

```json
"capabilities": {
  "state": true,
  "inference": true,
  "service": false,
  "egress": true
},
"egress_route_ids": ["public-web"]
```

Sign the policy and capsule as described in [Signed admission]({{ '/guides/signed-admission/' | relative_url }}).
On a node, the transactional setup command validates the site signature, generates
the receipt key locally, initializes the durable fence once, derives and pins the
trusted relay image, runs preflight, and restarts an already-active Executor:

```console
sudo /usr/local/libexec/steward/configure-admission \
  --policy site-policy.dsse.json \
  --site-root-public-key site-root.public \
  --site-root-key-id site-root-1 \
  --node-id node-a
```

For a local evaluation only, add `--allow-host-admin-intent`. That opt-in lets the
host-wide loopback token select tenant intent; production remote admission should
use the authenticated outbound command identity instead.

## 3. What the agent receives

Executor injects only derived, non-secret settings:

```text
HTTP_PROXY=http://steward-relay:8082
HTTPS_PROXY=http://steward-relay:8082
NO_PROXY=steward-relay,agent,localhost,127.0.0.1
STEWARD_EGRESS_PROXY=http://steward-relay:8082
```

Lower-case variants are supplied too. Agent DNS is set to a non-forwarding local
address, so proxy-aware clients send the hostname to Steward and raw DNS cannot be
used as an exfiltration path. Software that ignores proxy variables will fail;
Steward does not silently add transparent interception.

HTTPS uses standard `CONNECT`. Gateway checks route, hostname, port, resolved IP,
concurrency, byte ceilings, and lifetime before opening the tunnel. It does not
decrypt TLS, so it cannot inspect paths or methods inside that tunnel. End-to-end
Authorization and Cookie headers belong to the agent and destination; Steward does
not log them or inject generic credentials.

## 4. Inspect and troubleshoot

The admission response and status output show the effective proxy and sorted route
IDs. Read bounded counters through either local interface:

```console
sudo stewardctl node egress \
  -token-file /etc/steward/executor-token \
  -runtime-ref executor-REPLACE
```

The equivalent MCP tool is `steward_egress`. The result contains allow/deny counts,
byte totals, and the last destination/decision. Durable JSONL decisions are written
to `/var/lib/steward-gateway/egress-audit.jsonl` and rotate at 64 MiB. Records omit
paths, queries, headers, bodies, and credentials.

Common failures:

| Error | Meaning |
| --- | --- |
| `route_denied` | No route in the signed grant matches the hostname and port. |
| `address_denied` | DNS returned no public or explicitly CIDR-pinned address. |
| `route_busy` | The route concurrency ceiling is in use. |
| `request_too_large` / `response_too_large` | The configured byte ceiling was reached. |
| `grant_inactive` | The workload is stopped, being destroyed, or not fully activated. |
| `audit_unavailable` | An allow decision could not be durably recorded, so Steward refused it. |

Stopping the agent deactivates the proxy grant before the container stops.
Destroying it removes the Unix socket, relay, internal network, statistics, and
grant. A stopped agent cannot retain an ambient route.
