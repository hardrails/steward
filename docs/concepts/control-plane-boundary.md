---
title: Steward and the control-plane boundary
description: Learn which responsibilities belong to open-source Steward, which belong to a separate orchestration control plane, and why that separation matters.
section: Explanation
---

# Steward and the control-plane boundary

Steward is independently installable, open-source node software. A separately
hosted control plane coordinates the fleet through Steward's public contracts;
Steward does not depend on it.

| Steward owns on each node | A control plane owns across the fleet |
| --- | --- |
| Docker, gVisor, service-account, and configuration preflight | Users, organizations, and tenant hierarchy |
| Node-local workload lifecycle state | User authentication, approvals, and business authorization |
| Open Container Initiative (OCI) artifact and workload admission | Agent-profile catalog and desired-state resolution |
| Fixed sandbox and capability enforcement | Host selection, scheduling, and placement |
| Command ordering and durable anti-replay state | Fleet rollouts, retries, and desired-state reconciliation |
| Node-local health checks and signed evidence | Fleet inventory, evidence collection, dashboards, and policy distribution |
| Public APIs and uplink protocols | Enrollment workflows, fleet user interface, and incident-response tools |

## Why the split matters

Operators can audit, rebuild, and run the privileged node component without private
services. Control planes add fleet features through public contracts without
placing an SDK or credentials inside the privileged host boundary. Even a
compromised control plane cannot request privileged mode, raw networking, host
mounts, devices, or the Docker socket.

The control plane remains security-critical: it chooses tenants and images and
sends lifecycle commands. Steward limits malformed or malicious commands, but
cannot verify the business approval behind a valid, policy-compliant command.

## Integration surfaces

- The [Steward API](https://github.com/hardrails/steward/blob/main/openapi/steward.v1.yaml)
  covers generic lifecycle tracking and node capabilities.
- The [Executor API](https://github.com/hardrails/steward/blob/main/openapi/steward-executor.v1.yaml)
  covers hardened OCI workload lifecycle.
- Executor uplink invokes the Executor HTTP handlers and adds authenticated node
  identity, tenant-signed commands, reporting, and durable anti-replay positions.
- The generic supervisor uplink calls the same tracker methods as its HTTP API. It
  preserves command order within one poll response. A later poll is not guaranteed
  to wait for or observe every effect from an earlier poll, so the control plane must
  use instance state and idempotent retries rather than assuming cross-poll order.

These contracts require no private package, private schema registry, private SDK,
or Hardrails-hosted endpoint.
