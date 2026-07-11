---
title: Steward and the control-plane boundary
description: Learn which responsibilities belong to open-source Steward, which belong to a separate orchestration control plane, and why that separation matters.
section: Explanation
---

# Steward and the control-plane boundary

Steward is independently installable open-source node software. A control plane is a
separately hosted product or operator implementation that coordinates many Steward
nodes. It is a consumer—not a dependency—of Steward.

| Steward owns on each node | A control plane owns across the fleet |
| --- | --- |
| Host capability validation | Users, organizations, and tenant hierarchy |
| Generic lifecycle state | Authentication, authorization, and approvals |
| OCI workload admission | Agent profiles and desired-state resolution |
| Fixed sandbox enforcement | Scheduling and placement decisions |
| Command ordering and replay fences | Rollouts, retries, and reconciliation |
| Node-local health and evidence | Fleet inventory, audit views, and policy |
| Public APIs and uplink protocol | Product workflows and operator experience |

## Why the split matters

Sovereign operators can audit, rebuild, and operate the privileged node component
without access to private services. Control-plane vendors can innovate above a stable
contract without adding their SDK or credentials to the host boundary. A compromised
control-plane payload still cannot ask Executor for privileged mode, raw networking,
host mounts, devices, or the Docker socket.

The control plane remains security-critical: it decides which tenant and image
should run and sends lifecycle intent. Steward limits the consequences of malformed
or malicious intent but cannot determine whether a valid, policy-conforming business
request was authorized correctly.

## Integration surfaces

- The [Steward API](https://github.com/hardrails/steward/blob/main/openapi/steward.v1.yaml)
  covers generic lifecycle tracking and node capabilities.
- The [Executor API](https://github.com/hardrails/steward/blob/main/openapi/steward-executor.v1.yaml)
  covers hardened OCI workload lifecycle.
- Outbound uplink protocols reuse those node handlers and add authenticated node
  identity, delivery, reporting, generation fencing, and causal sequencing.

No contract requires a private package, private schema registry, private SDK, or
Hardrails-hosted endpoint.
