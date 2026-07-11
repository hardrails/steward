---
title: Steward v0.1 limitations
description: Understand what Steward v0.1 deliberately does not support, including connected Hermes and OpenClaw operation, and the explicit capability grants planned next.
section: Release boundary
---

# Steward v0.1 limitations

v0.1 establishes the safe node boundary: packaging, enrollment, command delivery,
anti-replay state, Docker/gVisor admission, tenant labels and capacity, lifecycle,
logs, and air-gapped operation. It is a foundation release, not yet a complete
general-purpose agent hosting environment.

## Not available in Executor v0.1

- Outbound network or hostname allowlists
- Published container ports or inbound service routing
- Secret, environment-variable, or file injection
- Durable tenant volumes or host mounts
- Per-workload UID/GID selection
- GPU or other device assignment
- Writable image root filesystems
- Interactive terminal/exec sessions
- Image pulling, signing-policy verification, or registry authentication
- Container checkpoint/restore
- Kubernetes scheduling or multi-host placement

Because Hermes Agent and OpenClaw need several of the first four capabilities, v0.1
can only perform hardened image and lifecycle compatibility tests for them.

## Intended capability model

Future support should preserve deny-by-default operation through narrow grants:

1. **Secret references** resolved locally from an operator-selected provider, never
   plaintext secret values inside fleet command history.
2. **Durable volume claims** created and scoped by tenant/profile policy, never
   arbitrary host paths.
3. **Egress grants** enforced through a tenant-aware proxy with explicit destinations,
   DNS behavior, audit, and fail-closed revocation.
4. **Service grants** that publish only declared ports through authenticated ingress,
   without host networking.
5. **Device grants** only after a host policy explicitly inventories and assigns an
   approved device class.

These are design goals, not promises in the v0.1 API. The public contract will remain
the authority for implemented behavior.

## Scope outside Steward

The control plane supplies identity, authorization, placement, desired state, and
fleet policy. Inference is controlled separately through the operator's model
infrastructure or OpenAI-compatible gateway. Host hardening, disk encryption,
hardware roots of trust, network segmentation, vulnerability management, and
facility controls remain deployment responsibilities.

If your evaluation requires a missing capability, open a use-case issue describing
the minimum authority the agent needs and the threat model. Avoid proposing a broad
Docker escape hatch as the interface.
