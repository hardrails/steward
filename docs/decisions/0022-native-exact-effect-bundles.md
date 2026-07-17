---
title: Approve bounded exact effect sets outside the agent
description: Why Steward extends Authorized Effects with one signed bundle of independently one-use exact connector requests instead of trusting prompt screening or a broad session grant.
section: Architecture decision
---

# Approve bounded exact effect sets outside the agent

- Status: Accepted
- Date: 2026-07-17
- Rung: native extension of Steward's existing signed permit and Gateway enforcement boundary

## Context

Authorized Effects assumes an agent can be manipulated by direct or indirect prompt
injection. A tenant authority signs one exact connector request, and Gateway spends
that permit before DNS. This is a strong boundary, but signing every step separately
creates approval fatigue for useful multi-step work. Replacing exact permits with a
broad time-limited session would make one compromised agent able to choose new
request bodies during the session.

Current evidence argues against treating a prompt classifier as the authorization
boundary. NIST describes indirect prompt injection as the failure to separate
trusted instructions from untrusted external data and recommends assuming attacks
remain possible when models process untrusted sources. Its 2026 agent identity
concept paper asks how an agent proves authority for a specific action and how that
action binds back to human authorization. The CaMeL research prototype similarly
separates trusted control and data flow from untrusted model-visible data. Anthropic
describes plan-level review as a way to reduce repeated approval prompts, while also
stating that layered prompt-injection defenses are not a guarantee.

The required increment must work without a public service, keep tenant private keys
off-node, preserve multi-party approval, add no dependency, and remain enforceable
when the agent process is fully compromised.

## Decision

**Decision:** build a bounded exact-effect bundle as a new version of Steward's
existing action-permit contract.

**Why:** one DSSE-signed artifact can authorize up to eight already reviewed exact
connector requests, while every request remains independently bound to its method,
configured operation, immutable bytes, task identity, tenant, node, workload
generation, policy, and expiry. Gateway continues to spend each task durably before
DNS. The artifact reduces signing friction without converting a plan into ambient
connector authority.

**Rejected:** model-based prompt screening, a destination-level session approval,
or a new workflow service. Screening cannot establish authorization after a model
sees adversarial content; a broad session lets the compromised workload invent
effects; and an external workflow service cannot replace Gateway's existing
node-local replay and evidence boundary in a disconnected installation.

**Revisit if:** operators require data-dependent or ordered workflows that cannot be
expressed as a small set of exact requests. That feature needs a separate signed
intermediate representation, explicit provenance rules, a durable workflow cursor,
and failure semantics for skipped, reordered, and outcome-unknown steps.

## Contract

The bundle is an authority artifact, not agent advice:

- it uses one canonical DSSE payload and the action keys already pinned by signed
  site policy and immutable runtime state;
- the signed common binding identifies the exact tenant, node, instance,
  generation, capsule, site policy, route policy, validity window, bundle ID, and
  approval threshold;
- each signed step identifies one connector, configured operation-policy digest,
  task ID, request digest, byte count, and content type;
- a bundle contains one through eight steps, with unique step and task identities;
- every signer must be authorized for every connector named by the bundle;
- the policy-derived multi-party threshold applies to the whole unchanged bundle;
- Gateway accepts the bundle only for an active `authorized` effect-mode grant and
  selects a step through the request's existing `X-Steward-Task-ID`;
- the request must match the selected step exactly, and the existing connector
  ledger makes that task one-use before DNS; and
- receipts bind the digest of the complete bundle, the selected task and request,
  the signer set and threshold, the operation policy, and the observed terminal
  result.

The steps are an exact set, not an ordered workflow. A compromised agent can spend
any unspent step in any order, omit steps, or stop. It cannot alter a request, add a
step, change connector policy, reuse a task, cross a tenant or workload generation,
or exceed the signed expiry. Operators must sign a bundle only when every permitted
subset and ordering is acceptable.

## Options considered

| Option | Security and functional fit | Ownership | Decision |
|---|---|---|---|
| Keep one signature per effect | Preserves the current exact boundary but makes repeated approval the dominant operator cost for a multi-step task. | No new code; high human friction. | Remains supported |
| Prompt scanner or second model | Can reduce common attacks but asks probabilistic components to decide authority after processing attacker-controlled content. Adaptive attacks and model changes require continuous retesting. | New model, policy, evaluation, and false-positive ownership. | Reject as an authorization boundary |
| Time-limited connector session | Simple for agents, but authorizes request bytes that no tenant authority reviewed. A stolen session becomes broad ambient authority. | Small implementation; unacceptable blast radius. | Reject |
| External workflow engine | Mature engines can coordinate steps, but they do not natively verify Steward's offline tenant signatures or participate in its node-local spend-before-DNS ledger. | Another service, identity, state store, recovery plan, and network boundary. | Reject for this increment |
| Native exact-effect bundle | Reuses existing keys, DSSE, trust inventory, Gateway, connector configuration, replay ledger, and receipts. It lowers signing friction while preserving exact request authority. | Core protocol work and compatibility tests remain Steward-owned. | Selected |

## Evidence and limitations

- [NIST AI 100-2e2025](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf)
  says current prompt-injection mitigations do not provide complete protection and
  recommends designing systems on the assumption that attacks remain possible.
- [NIST's agent identity and authorization concept paper](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf)
  identifies specific-action authority, human binding, tamper-verifiable audit, and
  post-injection impact limits as open implementation questions.
- [CaMeL](https://arxiv.org/abs/2503.18813) demonstrates the value of moving trusted
  control and data-flow decisions outside model interpretation; its reported 67%
  task completion also shows the usability cost of a strict boundary.
- [Anthropic's trustworthy-agents discussion](https://www.anthropic.com/research/trustworthy-agents)
  describes plan-level review as an answer to repeated confirmation fatigue and
  says no single prompt-injection defense guarantees protection.

These sources motivate the architecture; they do not certify Steward or prove that
an exact-effect bundle captures user intent. Signatures authenticate the supplied
bytes and policy bindings. They do not prove that an approver understood the
business meaning of every request, that an upstream service behaved correctly, or
that the host was uncompromised.
