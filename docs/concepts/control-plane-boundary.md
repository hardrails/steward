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
| Open Container Initiative (OCI) artifact and workload admission | No artifact catalog or desired-state authority; callers submit already signed commands |
| Fixed sandbox and capability enforcement | One-time node enrollment and explicit tenant bindings |
| Tenant-signature verification and durable anti-replay state | Exact signed-command retention, leasing, reclaim, and outcomes |
| Node-local health checks and signed evidence | Bounded node inventory and command status |
| Public APIs and outbound uplink protocols | Controller health, readiness, and operator API |

The bundled controller deliberately does not provide enterprise SSO, approval
workflows, automatic placement, desired-state reconciliation, or a fleet user
interface. An organization can add those higher-level functions without replacing
Steward's node enforcement or giving the controller tenant private keys.

## Why the split matters

Operators can audit, rebuild, and run both sides without a private service. The
packaged controller runs on a separate management host from Executor nodes and
does not receive a Docker socket. Even a compromised controller cannot request
privileged mode, raw networking, host mounts, or devices because the signed command
and Executor APIs contain no such fields.

The controller remains security-critical: it retains node credential verifiers, fleet
metadata, and already signed command bytes. It can deny service or replay delivery
attempts. It cannot create tenant authority because tenant and site private signing
keys stay outside it. Steward also cannot verify the business approval behind an
otherwise valid, policy-compliant signature.

## Integration surfaces

- The [Steward API](https://github.com/hardrails/steward/blob/main/openapi/steward.v1.yaml)
  covers generic lifecycle tracking and node capabilities.
- The [Executor API](https://github.com/hardrails/steward/blob/main/openapi/steward-executor.v1.yaml)
  covers hardened OCI workload lifecycle.
- The [Steward Control API](https://github.com/hardrails/steward/blob/main/openapi/steward-control.v1.yaml)
  covers tenant records, one-time enrollment, bounded
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
