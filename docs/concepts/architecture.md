---
title: Steward architecture
description: Understand Steward's service separation, signed local admission path, Docker and gVisor isolation, offline receipts, and separately controlled inference.
section: Explanation
---

# Steward architecture

Steward is the open-source node half of an agent orchestration system. It narrows
the privileged host interface to two small processes with different identities and
different authority.

```text
Independent control plane or host operator
  owns users, desired state, approvals, rollout; submits tenant-bound intent
       |
       | outbound HTTPS command channels
       v
Linux node
  steward                    steward-executor
  lifecycle supervisor       OCI admission boundary
  generic uplink             Docker socket access
  no Docker authority        fixed gVisor policy
                              journal + fences + receipts
       |                            |
       +------ node status ---------+
                                    v
                           tenant agent container
                           Docker runtime: runsc
                              | internal network only
                              v
                         hardened relay --Unix grant--> host gateway
                                                   inference / service / HTTP(S)

Offline stewardctl: keys, signed capsule/policy, receipt verification
Inference gateway: a separate operator-controlled system
```

## Why two processes

The Docker socket is effectively root authority over the host. Giving it to a large
lifecycle daemon—or to the agent itself—would make every unrelated feature part of
the host compromise boundary. `steward-executor` alone receives Docker-group
membership. The `steward` service account cannot open the socket.

Systemd hardening further constrains both processes, but it does not make Docker
socket access harmless. The intentionally small Executor contract is the main
control: a caller can describe an immutable image, explicit command, tenant and
profile identity, and bounded resources. It cannot request Docker's dangerous
escape hatches because those fields do not exist.

## Direct and outbound control

Both binaries can expose loopback APIs for host-local integration. Production node
packages default to outbound-only uplinks so no management listener is reachable
through an inbound firewall. The uplink dispatcher invokes the same internal API
handler as direct mode, preventing two policy implementations from drifting.

Commands carry generation and sequence fences. Executor persists its highest
accepted position before reporting completion, so a delayed or replayed command
cannot resurrect a destroyed workload after restart.

## Signed local admission

The opt-in v1.4 path separates three authorities: a publisher signs a reusable
profile capsule, the site root signs local policy, and an authenticated caller
submits a tenant/node/instance intent. Executor admits only their intersection.
It persists policy-epoch and instance-generation high-water marks, journals the
Docker mutation before effect, and appends Ed25519-signed hash-linked receipts.

`stewardctl` is an offline CLI, not a daemon. It can create keys, sign or verify
capsules and policies, and verify a copied receipt chain without contacting the
node, control plane, publisher, or a transparency service.

## Control-plane neutrality

The dependency arrow goes from an independently operated control plane to Steward's
public contract. Any system can implement the documented API and uplink protocol.

This separation allows a sovereign operator to audit and build Steward without
receiving the proprietary control-plane source. It also keeps enterprise functions
such as SSO, approvals, organization hierarchy, and fleet policy out of the node's
privileged process.

## Inference and egress separation

Steward does not host, schedule, or select models. A local or remote inference system
can be exposed through an OpenAI-compatible gateway under separate policy.

For ordinary outbound HTTP(S), the agent receives standard proxy variables pointing
at its per-instance relay. The relay has no Internet route; it bridges bytes to one
grant-owned Unix socket. The host Gateway intersects that grant with operator route
configuration, resolves and pins a permitted IP, and performs the dial. Stopping or
destroying the instance deactivates or removes the same grant. This keeps DNS,
private-address protection, audit, and lifecycle at the trusted boundary without
placing a generic proxy SDK in the agent image.

For implementation-level decisions, read the repository's
[`ARCHITECTURE.md`](https://github.com/hardrails/steward/blob/main/ARCHITECTURE.md).
