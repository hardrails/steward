---
title: Steward architecture
description: Understand Steward's two-process node architecture, remote control-plane boundary, Docker and gVisor isolation path, and separately controlled inference.
section: Explanation
---

# Steward architecture

Steward is the open-source node half of an agent orchestration system. It narrows
the privileged host interface to two small processes with different identities and
different authority.

```text
Control plane
  owns users, tenants, policy, desired state, approvals, rollout, fleet evidence
       |
       | outbound HTTPS command channels
       v
Linux node
  steward                    steward-executor
  lifecycle supervisor       OCI admission boundary
  generic uplink             Docker socket access
  no Docker authority        fixed gVisor policy
       |                            |
       +------ node status ---------+
                                    v
                           tenant agent container
                           Docker runtime: runsc

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

## Control-plane neutrality

Railyard is a proprietary, first-party control plane for Steward fleets. The
dependency arrow goes from Railyard to Steward's public contract, never from Steward
to Railyard. Any system can implement the documented API and uplink protocol.

This separation allows a sovereign operator to audit and build Steward without
receiving the proprietary control-plane source. It also keeps enterprise functions
such as SSO, approvals, organization hierarchy, and fleet policy out of the node's
privileged process.

## Inference separation

Steward does not host, schedule, or select models. A local or remote inference system
can be exposed through an OpenAI-compatible gateway under separate policy. Future
Executor egress grants should reference approved destinations; they should not
embed model governance inside the node runtime.

For implementation-level decisions, read the repository's
[`ARCHITECTURE.md`](https://github.com/hardrails/steward/blob/main/ARCHITECTURE.md).
