---
title: Steward's control-plane boundary
description: Learn what the bundled controller coordinates, what each node enforces, and why those responsibilities remain separate services.
section: Explanation
---

# Steward's control-plane boundary

Steward ships an optional open-source controller as `steward-control`. It
coordinates a fleet through the same public contracts that any compatible control
plane may implement. Nodes remain independently installable and keep enforcing
signed admission when the controller is absent or unreachable.

| Steward owns on each node | `steward-control` owns across the fleet |
| --- | --- |
| Docker, gVisor, service-account, and configuration preflight | Controller TLS, credential, capacity, and durable-state readiness |
| Node-local workload lifecycle state | Tenant records, scoped operators, and bounded fleet inventory |
| Open Container Initiative (OCI) artifact and workload admission | Bounded desired deployments and public signed workload artifacts |
| Fixed sandbox and capability enforcement | One-time node enrollment and explicit tenant bindings |
| Tenant-signature verification and durable anti-replay state | Deterministic, cache-aware placement and delegated lifecycle command creation |
| Independent verification of tenant delegation and controller command | Exact signed-command retention, leasing, reclaim, and outcomes |
| Node-local health checks and signed evidence | Bounded node inventory and command status |
| Public APIs and outbound uplink protocols | Controller health, readiness, and operator API |

The bundled controller provides a deliberately narrow desired-state loop for
exact, pre-authorized agent instances. It does not provide enterprise SSO,
business approvals, autoscaling, preemption, high-availability consensus, or a
general container scheduler. An organization can add those functions without
replacing Steward's node enforcement or giving Control tenant private keys.

## Why the split matters

Operators can audit, rebuild, and run both sides without a private service. The
packaged controller runs on a separate management host from Executor nodes and
does not receive a Docker socket. Even a compromised controller cannot request
privileged mode, raw networking, host mounts, or devices because the signed command
and Executor APIs contain no such fields.

The controller remains security-critical: it retains node credential verifiers, fleet
metadata, public delegations, its bounded online signing key, and command bytes.
It can deny service and can exercise any lifecycle verb until an active delegation
expires. It cannot add instances, nodes, generations, resources, capabilities, or
verbs outside that signed scope because Executor verifies both signatures and all
constraints locally. Steward also cannot verify the business approval behind an
otherwise valid, policy-compliant tenant signature.

## Integration surfaces

- The [Steward API](https://github.com/hardrails/steward/blob/main/openapi/steward.v1.yaml)
  covers generic lifecycle tracking and node capabilities.
- The [Executor API](https://github.com/hardrails/steward/blob/main/openapi/steward-executor.v1.yaml)
  covers hardened OCI workload lifecycle.
- The [Steward Control API](https://github.com/hardrails/steward/blob/main/openapi/steward-control.v1.yaml)
  covers tenant records, one-time enrollment, desired deployments, bounded
  inventory, signed-command delivery, and terminal reports.
- Executor uplink invokes the Executor HTTP handlers and adds authenticated node
  identity, opaque tenant-signed commands, fenced delivery leases, reporting, and
  durable anti-replay positions.
- The generic supervisor uplink calls the same tracker methods as its HTTP API. It
  preserves command order within one poll response. A later poll is not guaranteed
  to wait for or observe every effect from an earlier poll, so the control plane must
  use instance state and idempotent retries rather than assuming cross-poll order.

These contracts require no private package, private schema registry, private SDK,
hosted endpoint, Kubernetes cluster, database server, or message broker. The
bundled store is a bounded, single-writer design: run one active controller for a
state directory. It is not a high-availability database.
