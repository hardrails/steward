---
title: Steward architecture
description: Understand Steward's service separation, signed local admission path, Docker and gVisor isolation, offline receipts, and separately controlled inference.
section: Explanation
---

# Steward architecture

Steward is the open-source node layer of an agent orchestration system. It splits
node authority among three long-running services with separate Unix identities.
A fixed relay runs for each instance that receives a network capability; the relay
has no host authority.

```text
Independent control plane or host operator
  owns users, desired state, approvals, rollout; submits tenant-bound intent
       |
       | outbound HTTPS command channels
       v
Linux node
  steward                 steward-executor             steward-gateway
  lifecycle + uplink      OCI admission + Docker       finite route grants
  no Docker authority     journal, fences, receipts    no Docker authority
       |                           |                           |
       v                           v                           v
  independent lifecycle    tenant agent container <--> steward-relay <--> per-grant sockets
  state and API             Docker runtime: runsc                         Gateway-owned

Outbound data: agent -> relay -> Gateway -> approved inference or HTTP(S)
Service ingress: authenticated host caller -> Gateway -> relay -> agent

Host-local steward-mcp: bounded stdio adapter
Mostly offline stewardctl: keys, signed capsule/policy, receipt verification;
                         image import is a root-run, bounded Docker client
Inference system: separately selected and operated
```

## Why Steward uses separate services

The Docker socket provides authority that is effectively equivalent to host root.
Only the long-running `steward-executor` service receives Docker-group membership.
The lifecycle supervisor and the agent cannot open the socket, so unrelated
supervisor features remain outside the Docker compromise boundary. The root-run,
one-shot `stewardctl image import` command is a separate bounded Docker client: it
verifies and sanitizes one archive before loading it.

`steward-gateway` holds upstream route credentials and enforces bounded,
per-instance inference, service, connector, and egress grants, but it cannot open the Docker
socket. Executor creates, activates, deactivates, and removes grants over Gateway's
local control socket without receiving upstream credentials. The per-instance relay
runs in the workload network and receives only its matching per-grant Unix-socket
directory. Fixed socket names carry inference, service, connector, and egress traffic; Docker
publishes no agent or relay port to the host.

Systemd hardening reduces each service's host access, but it cannot make Docker
socket access safe. Executor's closed request shape is the primary control. A
caller can select an immutable Open Container Initiative (OCI) image, explicit
command, tenant and profile identity, and bounded resources. The API has no fields
for privileged mode, host mounts, devices, host networking, or other Docker escape
hatches.

## Direct and outbound control

The supervisor and Executor use different packaged defaults. The supervisor package
disables its listener and requires the outbound uplink. Executor keeps its
bearer-protected API on `127.0.0.1:8090` for `stewardctl` and MCP clients and may
also poll its own uplink. Neither service binds a non-loopback management listener.
Executor uplink commands invoke the same HTTP handlers as direct requests. The
generic supervisor uplink has a bounded dispatcher, but it calls the same tracker
methods and applies the same instance-spec validation as the direct API.

Multi-tenant Executor commands use DSSE (Dead Simple Signing Envelope), a standard
format that signs a typed payload. A tenant key in site-root-signed policy may sign
only its allowed operations. A separate site-owned cleanup key may sign only
`stop`, `destroy`, and `purge`, so the site can contain a workload after tenant
authority is removed. The node bearer authenticates transport but cannot select a
tenant.

The signed command binds the tenant, node, instance, runtime reference,
generations, sequence, validity window, operation, and payload. Executor stores the
highest accepted position for each `(tenant_id, instance_id)` before reporting
completion. This generation fence—a durable high-water mark—prevents a delayed or
replayed command from crossing tenants or resurrecting a destroyed workload after
a restart. A `read` command checks the existing fence but does not advance the
lifecycle sequence, so read-only authority cannot block a later mutation.

## Signed local admission

Signed admission separates three authorities. A publisher signs a reusable profile
capsule. The site root signs local policy. An authenticated caller supplies intent
bound to one tenant, node, instance, lineage, and generation. Executor admits only
the intersection of those inputs.

Executor imports a bounded single-image OCI archive through an offline verification
path, then runs the exact signed local config digest. Before a Docker change, it
fsyncs (flushes to durable storage) an operation journal and a pre-effect receipt.
After creating and inspecting the workload, it appends a commit receipt and
advances its durable fences. Receipts use Ed25519 public-key signatures and hash
links.

Reconciliation means comparing durable signed records with the objects that
actually exist. Executor runs a bounded reconciliation before accepting normal
mutations and every 30 seconds. A failed scan leaves the process, listener, and
uplink available with readiness at 503, but only an authenticated safety-only stop
may mutate the host. Reconciliation may repair limited lifecycle drift, but it
never recreates or adopts a missing or structurally changed workload.

For inference, connector, and egress policy, Gateway durably pins a non-secret digest of the effective
route policy and a private binding to the loaded credential. Executor stores the
public policy digest in its admission fence and evidence. A restart, reload, start,
or reconciliation refuses mismatched route semantics. Inference requests must use
the exact authorized model alias; a route credential that can reach other models
does not grant access to them.

`stewardctl` is a CLI, not a daemon. Its key, capsule, policy, archive-inspection,
and evidence commands run offline without contacting a node, control plane,
publisher, or transparency service. Only `image import` connects to the local
Docker daemon, after offline policy and archive verification.

## Control-plane neutrality

The dependency points from an independently operated control plane to Steward's
public contracts. Any system may implement the documented API and uplink protocols.

This boundary lets an operator audit and build the node software without access to
a control plane's source. It also keeps SSO, approvals, organization hierarchy,
fleet scheduling, and rollout policy out of the process that holds Docker authority.

## Inference, connector, and egress separation

Steward does not host, schedule, or select models. Gateway can expose an
operator-selected local or remote OpenAI-compatible inference system through a
finite, per-instance grant.

For an authenticated connector, the agent sends a logical connector and operation
ID to its Relay. Gateway selects one exact operator-configured origin, method, and
path, pins an allowed resolved address, strips agent-supplied credentials, and adds
the owner-provided credential at the last hop. Spend-before-effect task claims and
per-grant call budgets survive restart. The connector is not an arbitrary proxy or
secret-delivery mechanism.

For HTTP(S) egress, the agent receives standard proxy variables that point to its
relay. The relay has no Internet route; it forwards bytes to one grant-owned Unix
socket. Gateway intersects the grant with operator route configuration, resolves
and pins an allowed IP address, and performs the network connection. Stop and
destroy deactivate or remove the same grant. DNS checks, private-address policy,
auditing, and lifecycle enforcement therefore stay at the trusted boundary.

For implementation details and residual risks, read
[`ARCHITECTURE.md`](https://github.com/hardrails/steward/blob/main/ARCHITECTURE.md)
and the [security model]({{ '/concepts/security-model/' | relative_url }}).
