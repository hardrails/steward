---
title: Why Steward exists
description: Steward's product direction as an operator-controlled enforcement plane for untrusted AI agents.
section: Product
---

# Why Steward exists

AI agents are useful because they can act. The same property makes them dangerous:
an agent can combine hostile content, code execution, persistent state, network
access, and reusable credentials in one process.

A container limits where code runs. It does not establish:

- which tenant authorized the workload;
- which exact image and capabilities are acceptable;
- whether a delayed command belongs to an older instance;
- whether one external action was independently approved;
- whether a permit was replayed; or
- what evidence remains when the site disconnects.

Steward fills that enforcement gap on customer-controlled Linux.

## Product promise

Even when the agent is manipulated, Steward should still be able to answer:

1. **May this workload run?** Signed workload and site policy, tenant intent,
   generation fences, image identity, capacity, and live runtime facts must agree.
2. **May it perform this action?** Gateway can require exact signed authority for
   the current tenant, instance, connector operation, task, and request bytes.
3. **Can it reuse that authority?** Gateway records one-use authority as spent
   before DNS and network dispatch.
4. **Where is the reusable credential?** In Gateway's protected boundary, not the
   workload, prompt, skill, browser, control plane, or MCP output.
5. **What can an auditor verify?** Separate signed Executor and Gateway receipt
   chains plus an optional independently witnessed controller checkpoint.

This is narrower than claiming the model is safe. Steward assumes prompt injection,
malicious skills, misleading tool results, and compromised agent state are possible.

## Operator outcome

An operator can:

1. install a Docker and gVisor node interactively, unattended, through offline
   artifacts, or with Terraform bootstrap;
2. self-host Steward Control, create tenants and scoped operators, enroll nodes
   once, and use outbound node polling behind normal inbound firewalls;
3. admit an immutable agent profile for one tenant, node, instance, and generation;
4. run it with fixed unprivileged identity, no capabilities, a read-only root,
   bounded resources, and no network unless signed policy grants one;
5. expose selected inference, service, connector, or HTTP(S) routes without placing
   reusable upstream credentials inside the container;
6. require one or more distinct off-node keys to sign the same exact protected
   connector request;
7. bind approval to the current history of managed connector responses when
   context locking is required;
8. recover a service task by stable identity after a timeout instead of dispatching
   replacement authority;
9. inspect node, command, access, capacity, and attention records in an air-gapped
   React console that holds no private signing key or secret plaintext;
10. automate bounded operations through the CLI or local MCP adapter;
11. preserve node maintenance state across restart and drain only exact runtime
    references; and
12. export and verify enforcement evidence without contacting a vendor.

## The control path

```text
publisher workload profile + site policy + tenant intent
                         |
                         v
                Steward Executor
                         |
                  Docker + gVisor
                         |
                    untrusted agent
                         |
                 private fixed relay
                         |
                         v
tenant exact permit -> Steward Gateway -> approved external service
                         |
              spend-before-network state
                         |
                signed action receipts
```

Steward Control sits beside this path, not above its authority. It transports exact
signed commands, observes bounded node state, and witnesses receipt checkpoints.
It does not need tenant command, task, or action private keys and has no Docker
authority.

## What Steward builds

Steward uses the following ownership boundary:

- `in-house`: signed admission, instance and command fences, exact permits,
  durable spend, Gateway credential mediation, and signed enforcement evidence.
  These connected semantics are the moat.
- `native-platform`: Docker, gVisor, systemd, Linux users and permissions,
  filesystem durability, and Go's standard-library HTTP, TLS, JSON, and
  cryptography.
- `open-source`: operator-selected identity, secret storage, policy, provenance,
  observability, model-serving, and deployment systems connected through finite
  public contracts.
- `do-nothing`: general agent catalogs, release workflow engines, placement,
  rollout promotion, secret storage, and arbitrary computer use until a real
  enforcement requirement cannot be composed from existing systems.

## What Steward does not build

Steward is not an agent framework, model server, general container orchestrator,
secret manager, identity provider, workflow engine, software-provenance issuer,
endpoint security product, or hosted control plane.

Hermes Agent and OpenClaw remain the agent implementations. Steward's adapters
expose only a bounded service API and a tested custom-skill path inside the outer
gVisor boundary. Broader upstream plugins, channels, browser tools, MCP servers,
and future releases require separate review and qualification.

## Differentiator

Sandbox lifecycle, egress allowlists, credential injection, self-hosted control
planes, and JSON audit logs are widely available. Steward's differentiator is the
portable authorization-to-enforcement record:

- customer-owned keys and policy;
- exact request authority outside the agent;
- one-use spend before network access;
- reusable credentials outside the workload;
- tenant and instance replay fencing;
- signed enforcement receipts; and
- offline verification without a hosted dependency.

The [market analysis]({{ '/product/market-analysis/' | relative_url }}) compares
this narrower claim with current public documentation. “Not documented” does not
prove that another product lacks a feature, and Steward's design is not a security
certification.

## Success criteria

Steward is succeeding when a new operator can:

1. install and verify one node without learning every protocol;
2. run one real Hermes or OpenClaw task that changes bounded state;
3. configure one protected connector without placing its credential in the agent;
4. approve and audit one exact action;
5. understand an uncertain outcome without accidentally replaying it; and
6. reproduce the evidence check on a disconnected system.

Features that do not improve one of those outcomes should be composed from another
system, deferred, or removed.
