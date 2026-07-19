---
title: "ADR 0030: Keep Steward focused on enforceable agent authority"
description: Why Steward retains exact admission, execution, permits, credential mediation, and evidence while removing catalog, activation-workspace, rollout, and vendor-specific secret-compiler products.
section: Architecture decisions
status: accepted
---

# ADR 0030: Keep Steward focused on enforceable agent authority

## Context

Steward accumulated several adjacent product layers before it had operators:
outcome-led agent releases, curated catalogs, append-only activation workspaces,
proof-carrying fleet rollout coordination, and a compiler for one secret manager.

Those features were individually defensible but made the first successful workload
harder to understand and operate. They also blurred Steward's unique responsibility
with work already owned by artifact registries, deployment systems, workflow
engines, and secret managers.

The durable market gap is narrower: sandboxing does not establish exact external
authority, and ordinary agent gateways do not provide a portable
authorization-to-enforcement record for disconnected customer-operated sites.

## Decision

Steward's product boundary is the enforcement plane between an untrusted
containerized agent and managed authority.

Steward retains and improves:

- signed local workload and site-policy admission;
- Docker and gVisor execution;
- tenant, generation, sequence, and replay fencing;
- provider-neutral credential materialization into Gateway;
- exact service-task and connector-action permits;
- spend-before-network durability;
- bounded inference, service, connector, and egress mediation;
- signed Executor, Gateway, and controller-witness evidence;
- a customer-operated control plane, React console, CLI, and bounded MCP adapter;
- air-gapped installation and verification; and
- concrete Hermes Agent and OpenClaw adapter procedures.

Steward removes as live product surfaces:

- a generic agent release product;
- curator-signed agent catalogs;
- activation workspace orchestration;
- fleet rollout planning and promotion coordination; and
- a generated OpenBao policy, template, and systemd bundle.

A closed activation canary protocol may remain as an internal safety primitive
where Executor's current wire contract requires it. It is not presented as a
general release-management product.

## Buy-versus-build decision

- `in-house`: admission, exact permits, durable spend, credential mediation, and
  signed enforcement evidence. Their combined semantics are Steward's
  differentiator and cannot be delegated without losing the product boundary.
- `native-platform`: Docker, gVisor, systemd, Linux permissions, filesystem
  durability, and Go standard-library HTTP, JSON, TLS, and cryptography.
- `open-source`: secret managers, identity providers, policy engines,
  provenance systems, telemetry backends, model serving, and deployment
  automation integrated through finite public contracts when customers need them.
- `do-nothing`: general catalogs, workflow engines, scheduling, rollout
  promotion, and secret storage until a demonstrated enforcement requirement
  cannot be composed from existing systems.

## Consequences

The common operator path becomes smaller and the documentation can explain one
clear outcome: a compromised agent still lacks ambient authority to perform a
protected external action.

Operators must use an existing deployment system for release selection and rollout
policy. Steward continues to enforce signed workload identity and action authority
at each node.

Secret-manager instructions become provider-neutral. Steward validates the
Gateway-only file boundary and rotation epoch but no longer owns one provider's
configuration lifecycle.

Historical ADRs describing the removed products remain in the repository as
decision history. This ADR supersedes their product status; active documentation
must not teach removed commands.

## Revisit criteria

Reconsider a removed layer only with evidence from real operators that:

1. the missing behavior prevents use of Steward's enforcement boundary;
2. an existing open-source or native-platform component cannot satisfy it through a
   finite public contract;
3. the proposed code does not move private signing keys, reusable credentials, or
   arbitrary execution into Control or the browser; and
4. the feature can be explained as enforcement rather than a general workflow
   product.
