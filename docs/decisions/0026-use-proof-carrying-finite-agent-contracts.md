---
title: Use proof-carrying finite agent contracts
description: Why Steward activates Hermes and OpenClaw through compiled-in release contracts instead of trusting generic agent success responses.
section: Architecture decision
---

# Use proof-carrying finite agent contracts

- Status: Accepted
- Date: 2026-07-17
- Rung: small in-house contract table over existing Steward authority and evidence primitives

## Context

A working adapter is not yet a safe deployment product. A container can start and
an agent can report success without proving which qualified task ran, which tenant
authorized it, or whether the result belongs to the admitted runtime. A generic
`agent_type`, prompt, callback, or success JSON field would let untrusted release
configuration redefine the security test it must pass.

The external security direction reinforces this gap. NIST's 2026 work on agent
identity and authorization asks how an agent proves authority for a specific
action and how auditing can bind agent activity back to human authorization. Its
[May 2026 RFI response analysis](https://www.nist.gov/publications/summary-analysis-responses-request-information-regarding-security-considerations-ai)
reports broad agreement that agent security is a barrier to adoption and that
existing cybersecurity controls need adaptation. OpenClaw's own
[security guidance](https://docs.openclaw.ai/gateway/security) treats the model as
untrusted and states that mutually untrusted users need separate Gateway and
credential boundaries. These sources do not evaluate Steward. They support keeping
identity, authority, isolation, and evidence outside model interpretation.

## Decision

Represent every qualified activation recipe as a compiled-in finite contract. A
contract fixes:

- the agent profile, private service ID, and lifecycle operation;
- the exact request recipe and activation-scoped session identity;
- the qualification fixture and expected workspace-manifest digest; and
- one strict terminal verifier for that agent's canonical result.

The publisher-signed release must duplicate those values exactly. The signed
capsule selects the contract through its profile and service; a CLI flag cannot
override it. Site policy, instance intent, live admission, and a tenant task permit
still authorize deployment and the exact request.

Hermes and OpenClaw both use Gateway's bounded lifecycle transport, signed receipt
chain, Executor activation markers, controller witness, offline activation proof,
and canary-first fleet promotion. Their terminal parsers remain separate. Hermes
must return its canonical empty-workspace audit. OpenClaw must return the qualified
fixture and workspace digest, the activation session, one sanitized success
payload, exactly one `exec` call, no media or tool failure, and a recomputed digest
of the canonical sanitized result. Neither parser accepts extension fields,
alternate success text, or a release-supplied schema.

For operator ergonomics, `gateway service set -agent hermes|openclaw` expands to
the corresponding fixed service, operation, path, lifecycle prefix, and hardened
limits. It rejects simultaneous manual identity or lifecycle flags. Lower-level
service configuration remains available for workloads outside proof-carrying agent
activation.

## Rejected alternatives

- **One generic success schema for every agent.** This would erase material
  agent-specific evidence and make the weakest adapter response the common trust
  boundary.
- **A release-supplied verifier or hook.** Images and release configuration are
  untrusted. Letting them define success would execute or interpret attacker-owned
  policy inside the trusted coordinator.
- **Separate activation and rollout implementations per agent.** Duplicating
  authority, recovery, and evidence logic increases drift. Only request and terminal
  semantics differ; the signed enforcement path should remain shared.
- **Infer behavior from image names or tags.** Mutable, descriptive names are not
  authenticated qualification identities.

## Consequences

Operators can issue, activate, resume, verify, and roll out either qualified agent
through one workflow. OpenClaw gains the same offline-verifiable evidence path as
Hermes without exposing its full Gateway or turning Steward into a generic workflow
engine.

Adding another agent is deliberate work: Steward must add a finite contract,
agent-specific terminal verifier, adversarial substitution tests, real gVisor
qualification, retained metadata-only evidence, documentation, and a release
review. Unsupported agents can still run as ordinary admitted workloads, but they
cannot claim Steward's proof-carrying qualified-agent result.
