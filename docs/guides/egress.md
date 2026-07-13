---
title: Configure signed HTTP(S) egress
description: Create named deny-by-default routes, bind them through signed admission, test HTTPS CONNECT, and inspect bounded egress audit statistics.
section: How-to
---

# Configure signed HTTP(S) egress

Steward gives proxy-aware agents bounded HTTP, HTTPS, server-sent events (SSE), and
secure WebSocket (WSS) egress without a raw Internet route. Four permissions must
agree:

1. the publisher capsule permits the `egress` capability;
2. site policy permits named route IDs for the tenant;
3. the instance intent requests a subset of those IDs; and
4. the node operator maps each ID to destinations and hard limits.

Steward denies the request if any permission is missing. The unsigned compatibility
endpoint cannot request egress.

## 1. Define a node route

The configurator preserves ownership, validates a temporary complete configuration,
flushes it with `fsync`, then renames it atomically:

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

An exact hostname excludes subdomains. `*.example.com` matches one or more subdomain
labels but not `example.com`; list both if needed. No route is open or default-allow.

Gateway resolves the hostname, checks each address against the default address
rules and any route-wide Classless Inter-Domain Routing (CIDR) ranges, then dials
the exact accepted address. Without an explicit CIDR, Gateway rejects every range
in the IANA special-purpose registries. This includes private, loopback, link-local,
documentation, benchmarking, and `100.64.0.0/10` shared address space used by
carrier-grade NAT and Tailscale. It also rejects unallocated IPv6 unicast space.
Permit a required internal range explicitly:

```console
sudo stewardctl gateway route set \
  -id internal-api \
  -destination api.corp.example:8443 \
  -allow-cidr 10.40.0.0/16
sudo systemctl reload steward-gateway
```

Each allowed CIDR applies to every destination in that route. Use separate route
IDs when destinations need different private ranges. An explicit CIDR can permit
special-purpose unicast, but it cannot permit an unspecified, multicast, or limited
broadcast address. Metadata endpoints such as `169.254.169.254` remain unreachable
unless explicitly allowed. Do not allow them for agent workloads.

Reload is atomic. It can add routes, alter unreferenced routes, and rotate the
service token without dropping connections. A retained inference grant pins the
base URL, credential-file path and presence, loaded credential contents, and
concurrency. A retained egress grant pins destinations, concurrency, byte limits,
allowed CIDRs, and lifetime. Changing a pinned field rejects the whole reload.
Remove the workload and grant before changing that authority. Changing concurrency
on an unreferenced route also fails while its old limit is in use. Automation must
confirm `configuration reloaded` in the journal; `systemctl reload` only sends the
signal.

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
{
"capabilities": {
  "state": false,
  "inference": true,
  "service": false,
  "egress": true
}
}
```

Then request the route in the instance intent:

```json
{
"capabilities": {
  "state": false,
  "inference": true,
  "service": false,
  "egress": true
},
"egress_route_ids": ["public-web"]
}
```

Sign the policy and capsule as described in
[Signed admission]({{ '/guides/signed-admission/' | relative_url }}).
On an already configured node, this command updates signed admission atomically. It
validates the site signature, generates a missing receipt key, initializes missing
fence, journal, and evidence stores with their service ownership, ensures that the
active release has a verified relay-image binding, runs preflight, and restarts
Executor if active. A failed transaction removes only stores and keys that it
created:

```console
sudo /usr/local/libexec/steward/configure-admission \
  --policy site-policy.dsse.json \
  --site-root-public-key site-root.public \
  --site-root-key-id site-root-1 \
  --node-id node-a
```

For local evaluation only, `--allow-host-admin-intent` lets the host-wide loopback
token select a tenant. Production remote admission should use authenticated outbound
command identity.

## 3. What the agent receives

Executor injects only derived, non-secret settings:

```text
HTTP_PROXY=http://steward-relay:8082
HTTPS_PROXY=http://steward-relay:8082
NO_PROXY=steward-relay,agent,localhost,127.0.0.1
STEWARD_EGRESS_PROXY=http://steward-relay:8082
```

Lowercase variants are also supplied. Agent DNS is non-forwarding, so proxy-aware
clients send hostnames to Steward and raw DNS cannot carry data out. Software that
ignores proxy variables fails; Steward does not intercept traffic transparently.

HTTPS uses `CONNECT`. Gateway checks route, hostname, port, resolved IP, concurrency,
byte limits, tunnel lifetime, and the first TLS ClientHello. The ClientHello message
is limited to 64 KiB and at most eight TLS records. The client must send it within
five seconds, or sooner when the route lifetime is shorter.
A hostname CONNECT target requires a matching TLS Server Name Indication (SNI)
value. An IP-literal target requires the ClientHello to omit SNI. Gateway cannot
inspect methods or paths because it does not decrypt TLS. Grant deactivation cancels
active requests and tunnels. Either side ending a tunnel closes the other side and
releases its concurrency slot. Steward neither logs end-to-end Authorization or
Cookie headers nor injects generic credentials.

For HTTP responses with a known length above the route limit, Gateway returns
`502 response_too_large` before forwarding body bytes. For an unknown-length
response, Gateway preserves streaming and advertises the
`X-Steward-Stream-Status` trailer. A complete response ends with `completed`. If
the upstream read fails or another byte exists after the configured limit, Gateway
aborts the HTTP stream. The client receives a framing or body-read error instead of
a valid-looking truncated success. Gateway classifies the outcome as
`terminal:stream_failed` or `terminal:response_too_large` and attempts to write that
terminal audit record. The probe byte is never forwarded.

Gateway must persist an allow decision before it opens an upstream route. If that
write fails, a plain HTTP request returns `audit_unavailable`; an HTTPS `CONNECT`
closes before Gateway dials the upstream. Audit writes for denials and
terminal outcomes are best-effort so an audit-storage failure cannot turn a denial
into access or keep a completed connection open.

Denied requests have a layered fixed-window limit of 30 per grant, 120 per tenant,
and 480 across the host per minute. Gateway reserves capacity at all three layers
before a synchronous denial-audit write, so one tenant cannot borrow another
tenant's allocation. When any layer is exhausted, a request that is actually denied
returns HTTP 429 `egress_rate_limited` instead of adding another audit write or
denial statistic. An inactive or revoked grant still returns `grant_inactive` or
`grant_revoked`; the limiter may suppress its audit record but never conceals the
authority transition. Gateway still evaluates and permits traffic that satisfies
its route, address, lifecycle, and resource policy. A backward wall-clock jump keeps
denial-audit capacity closed rather than reopening spent capacity; it does not block
otherwise allowed traffic.

## 4. Inspect and troubleshoot

The admission response and status output show the effective proxy and sorted route
IDs. Read bounded counters through the local CLI:

```console
sudo stewardctl node egress \
  -token-file /etc/steward/executor-token \
  -runtime-ref executor-REPLACE
```

The MCP equivalent is `steward_egress`. Results contain allow/deny counts, bytes,
and the last destination and decision. JSON Lines records in
`/var/lib/steward-gateway/egress-audit.jsonl` rotate at 64 MiB and omit paths,
queries, headers, bodies, and credentials. Denial and terminal counters can advance
even when their best-effort audit write fails.

Common failures:

| Error | Meaning |
| --- | --- |
| `route_denied` | No route in the signed grant matches the hostname and port. |
| `address_denied` | DNS returned no public or explicitly CIDR-pinned address. |
| `route_busy` | The route concurrency ceiling is in use. |
| `egress_rate_limited` | A policy or resource request was denied after its grant, tenant, or the host exhausted denied-attempt audit capacity. Further denials return HTTP 429 without another audit write until the one-minute window resets; allowed traffic continues. Lifecycle responses remain `grant_inactive` or `grant_revoked` even when their denial record is suppressed. |
| `request_too_large` / `response_too_large` | The configured byte ceiling was reached. |
| `grant_inactive` | The workload is stopped, being destroyed, or not fully activated. |
| `audit_unavailable` | An allow decision could not be durably recorded, so Steward refused it. |

Stopping the agent deactivates its proxy grant before stopping the container.
Destroying it removes the Unix socket, relay, internal network, statistics, and
grant. A stopped agent has no usable route.
