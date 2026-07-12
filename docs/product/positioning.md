---
title: Why Steward exists
description: "Steward's product direction: operator-controlled local admission, named HTTP(S) routes, tenant-bound commands, and offline-verifiable receipts."
section: Product
---

# Why Steward exists

> This page describes shipped behavior. Proposed hardening is listed separately in
> [current limitations]({{ '/limitations/' | relative_url }}#runtime-hardening-still-ahead).

Autonomous agents are useful because they can act: run code, retain state, call
models, and offer services. Before an agent starts, an operator must know which
tenant it serves, which artifact may run, which capabilities it may receive, and
what the local runtime will enforce.

A sandbox isolates a workload, but does not explain why that workload was
authorized. Steward connects a local admission decision to a constrained workload
and records a receipt that the operator can verify without contacting a vendor.

## The operator outcome

After preparing a Docker and gVisor host and importing the required artifacts, an
operator can:

1. admit a signed, immutable agent profile for one tenant, node, and instance;
2. require that profile to comply with site-root-signed policy, per-workload
   resource limits, and host/tenant aggregate memory, CPU, PID, and
   workload-count caps;
3. run the agent in a tenant-labelled, gVisor-sandboxed Docker workload with
   no default network access, while granting only approved state, inference,
   service, or named HTTP(S) routes; and
4. export a node-local, tamper-evident receipt of the accepted inputs and recorded
   enforcement decisions. Tamper-evident means changes within the supplied chain
   can be detected; detecting removal of a complete suffix requires an independently
   retained exact head. It does not mean the host cannot replace the entire chain.

The operator keeps control of keys, policy, artifacts, infrastructure, and
evidence when external services are unavailable. Steward does not rely on the
agent's own account of its behavior.

## The control path

```text
publisher-signed profile capsule
              +
site-root-signed local policy
              +
authenticated tenant instance intent
              |
              v
       Steward admission and generation fence
              |
              v
gVisor workload + optional dedicated-host state + per-instance trusted relay
              |
              v
node-local signed, hash-linked enforcement receipt
```

Each input has a separate purpose:

- A **profile capsule** is a publisher-signed description of an immutable image
  and the maximum capabilities of a reusable agent profile. It contains no secret,
  raw upstream URL, arbitrary host path, Docker option, or caller-selected
  privilege.
- A **site policy** is signed by the operator's site root key. It limits publishers,
  tenants, profiles, repositories or exact image digests, resources, inference
  routes, services, egress routes, and publisher revocation state.
- An **instance intent** is a separately authenticated command to run a profile for
  a tenant, node, and instance. A generation fence—an increasing counter keyed by
  `(tenant_id, instance_id)`—prevents an older command from replacing newer state.

Steward grants only what all three inputs allow. A trusted publisher can authorize
a profile and its maximum capabilities, but cannot choose a tenant's schedule or
identity.

## A receipt is not an agent transcript

The receipt records evidence from controls Executor can enforce. It binds the
tenant, runtime reference, capsule and policy digests, instance generation,
lifecycle event, and outcome from a fixed vocabulary. For inference or egress, the
admission commit also stores the effective route-policy digest. The receipt does
not embed the full instance intent, state or service selection, actual Gateway
grant ID, or individual Gateway traffic decisions; Gateway records those traffic
decisions in a separate unsigned newline-delimited JSON (JSONL) audit log. Receipts
also exclude prompts, model responses, agent logs, the meaning of agent actions,
and secrets.

This gives an auditor a bounded question they can answer locally: *what did
this node accept and enforce?* It does **not** prove that a model was honest,
that an agent's explanation was true, that an upstream service behaved as
claimed, or that every semantic action inside a container was safe.

The receipt is tamper-evident only within the supplied chain and documented node
trust boundary. The host root user, host kernel, Docker, gVisor, signing-key
protection, and operator configuration remain trusted. Steward does not claim
hardware attestation (proof tied to hardware state), protection from a hostile host
administrator, cross-node anchoring, detection when all trailing records are
removed without an external checkpoint, or formal certification. Executor holds
the receipt key; a separate signing service does not isolate it.

## Capabilities require explicit grants

Steward enforces four optional, explicitly granted capabilities. A signed request
does not enable a capability by itself. If the required local components are
missing, admission fails closed:

- **State**: an executor-owned Docker volume scoped to a tenant and lineage. A
  lineage is the persistent-state identity shared across approved workload
  replacements. The volume uses a fixed profile path, is not a host bind mount or
  encrypted by Steward, and remains readable by a trusted host administrator.
  Docker's portable local volume driver has no hard byte or inode quota, so state
  is disabled by default and may be enabled only in dedicated-host compatibility
  mode.
- **Inference**: one logical route resolved by a local gateway. The gateway
  adds the upstream credential at the last hop. The workload receives neither the
  credential nor a general-purpose proxy.
- **Service**: one declared agent port reached through the paired relay and an
  authenticated local gateway. The endpoint does not provide tenant end-user
  authentication or public exposure.
- **Egress**: named HTTP(S) routes allowed by the publisher capsule, tenant policy,
  and instance intent, then mapped by the host operator to hostnames, ports,
  verified IP addresses, concurrency limits, byte limits, and time limits. The
  agent receives a standard proxy, not a raw network interface.

These contracts include lifecycle ordering, drift inspection, journaling, and
explicit state purge with a receipt. When the observed outcome of a failed mutation
is known, Executor can compensate. When the outcome is ambiguous, it retains the
prepared journal entry, degrades readiness, and blocks conflicting work instead of
claiming rollback. Steward provides no raw TCP/UDP,
transparent interception, default-allow route, TLS interception, browser
automation, interactive shell, device grant, arbitrary environment variable, or
caller-controlled host mount. Excluding these paths keeps each grant bounded and
reviewable.

## What Steward is not trying to replace

Steward is not an agent framework, workflow designer, model router, browser
service, generic sandbox API, or hosted control plane. It does not host models,
inspect prompts, calculate token costs, design multi-agent workflows, or make
semantic claims about agent behavior.

Existing sandboxes and agent platforms can complement Steward. Steward addresses a
specific question: can a customer-operated node enforce a locally authorized
deployment and produce portable evidence of that enforcement while disconnected?
See the [market analysis]({{ '/product/market-analysis/' | relative_url }}) for a
dated comparison and its limits.

## Operator responsibilities

Steward identifies the artifact, limits capabilities, verifies local policy, and
records evidence before an agent receives authority. Operators must still patch
hosts, review artifacts, protect signing keys, authenticate users at the local
service gateway, and choose an isolation level appropriate to the environment.

For the exact threat assumptions, see the [security model]({{ '/concepts/security-model/' | relative_url }}).
