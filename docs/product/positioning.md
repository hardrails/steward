---
title: Why Steward exists
description: "The V1.4 product direction: operator-owned admission, useful signed egress, secure automation, and offline-verifiable runtime receipts."
section: Product
---

# Why Steward exists

> Status: V1.4 release position, dated 2026-07-11. Shipped and planned
> capabilities are separated explicitly below.

Autonomous agents are useful because they can act: run code, retain state, call
models, and offer services. That same usefulness creates an operator problem:
before an agent starts, someone needs to know which tenant it serves, which
artifact is allowed, which authority it receives, and what the local runtime
actually enforced.

A sandbox is important, but it answers only part of that question. Steward V1.4
is designed as the local execution authority that connects an operator's
admission decision to a constrained workload and a receipt the operator can
verify without contacting a vendor.

## The operator outcome

After preparing a Docker and gVisor host and importing the required artifacts,
an operator can:

1. admit a signed, immutable agent profile for a tenant, node, and instance;
2. intersect that capsule with site-root-signed policy and local resource limits;
3. run the agent in a tenant-labelled, gVisor-sandboxed Docker workload with
   no ambient network, while narrowly granting state, inference, service, or named HTTP(S) routes; and
4. export a node-local, tamper-evident receipt of the inputs accepted and the
   enforcement decisions recorded.

This is intended to let an operator keep control of keys, policy, artifacts,
infrastructure, and evidence when external services are unavailable. It does
not ask the operator to trust an agent's own narrative about what it did.

## The V1.4 control path

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
gVisor workload + tenant lineage state + per-instance trusted relay
              |
              v
node-local signed, hash-linked enforcement receipt
```

The three inputs have different jobs:

- A **profile capsule** names an immutable image and the ceiling of a reusable
  agent profile. It contains no secret, raw upstream URL, arbitrary host path,
  Docker option, or caller-selected privilege.
- A **site policy** is rooted in the operator's local trust. It scopes allowed
  publishers, tenants, profiles, repositories or exact image digests, resource
  ceilings, inference route IDs, service IDs, egress route IDs, and publisher revocation state.
- An **instance intent** is authenticated separately. Its caller identity binds
  the tenant and node; a generation fence is keyed by `(tenant_id, instance_id)`
  so a stale request cannot replace a newer workload.

Effective authority is the intersection of those three inputs. That distinction
matters: publisher trust may authorize a profile and artifact ceiling, but it
does not choose a tenant's schedule or identity.

## A receipt is not an agent transcript

The V1.4 receipt is evidence from Steward's enforceable boundary. It binds the
capsule and policy digests, instance generation, capability grant, lifecycle
and gateway decisions, and bounded outcomes. It deliberately excludes prompts,
model responses, agent logs, semantic tool actions, and secrets.

This gives an auditor a bounded question they can answer locally: *what did
this node accept and enforce?* It does **not** prove that a model was honest,
that an agent's explanation was true, that an upstream service behaved as
claimed, or that every semantic action inside a container was safe.

The receipt is tamper-evident within the supplied chain and node trust boundary, not globally
tamper-proof. Host root, the host kernel, Docker, gVisor, the local signing-key
protection, and the operator's configuration remain trusted. V1.4 does not
claim hardware attestation, protection from a hostile host administrator,
cross-node anchoring, complete-suffix detection without an external checkpoint, or
formal certification. The v1.4 receipt key is co-located in Executor rather than
isolated behind a separate signing service.

## Useful without becoming ambient

V1.4 ships the enforcement path for four positive grants. An authenticated field
still does nothing by itself: if the complete local topology is absent, admission
fails closed. When configured, Steward grants only:

- **State**: an executor-owned, tenant-and-lineage-scoped Docker volume at a
  fixed profile path. It is not a host bind mount, is not encrypted by Steward,
  and remains readable to a trusted host administrator.
- **Inference**: one logical route resolved by a local gateway. The gateway
  injects the real upstream credential at the last hop; the workload receives
  neither that credential nor a generic proxy.
- **Service**: one declared agent port reached through the paired relay and an
  authenticated local gateway. A service endpoint is not, by itself, end-user
  authentication or public exposure.
- **Egress**: named HTTP(S) routes selected through publisher/tenant/intent
  intersection and mapped by the host operator to hostnames, ports, checked IPs,
  concurrency, byte, and time ceilings. The agent gets a standard proxy, not a raw
  network interface.

These are shipped contracts, including lifecycle ordering, drift inspection,
rollback, journaling, and explicit receipted state purge. There is no raw TCP/UDP,
transparent interception, open/default-allow route, TLS MITM, browser automation,
interactive shell, device grant, arbitrary environment variable, or
caller-controlled host mount. Those omissions keep the grants reviewable.

## What Steward is not trying to replace

Steward is not an agent framework, workflow designer, model router, browser
service, generic sandbox API, or hosted control plane. It does not host models,
inspect prompts, calculate token costs, design multi-agent workflows, or make
semantic claims about agent behavior.

Existing sandboxes and agent platforms are valuable components of the market.
The relevant product question is different: can a customer-operated node
enforce a locally authorized deployment envelope and produce portable evidence
of that enforcement while disconnected? See the [market analysis]({{ '/product/market-analysis/' | relative_url }}) for a dated comparison and its limits.

## A calm security posture

Steward is for operators who need a practical answer before granting an agent
more authority: identify the artifact, bound the capability, verify the local
policy, and keep an evidence trail. It reduces the number of decisions that
must be taken on faith. It does not remove the need to patch hosts, review
artifacts, protect signing keys, authenticate users at the local service
gateway, and select an isolation level appropriate to the environment.

For the exact threat assumptions, see the [security model]({{ '/concepts/security-model/' | relative_url }}).
