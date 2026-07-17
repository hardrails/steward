---
title: Enforce multi-party approval for authorized effects
description: Why Steward implements policy-bound Ed25519 approval thresholds instead of a hosted approval service or generic workflow engine.
section: Architecture decision
---

# Enforce multi-party approval for authorized effects

- Status: Accepted
- Date: 2026-07-17
- Rung: in-house

## Context

An agent can encounter hostile instructions in email, web pages, issues, calendar
events, or tool output. A single approval prompt reduces accidental autonomy, but
it still leaves one operator account, signing key, or manipulated review surface
able to authorize an external write.

[NIST's software and AI agent identity concept
paper](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd)
calls out agent identification, authorization, audit, non-repudiation, and prompt
injection as connected problems. [NIST SP
800-171r3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/800-171r3/NIST.SP.800-171r3.html#section-3.1.4)
defines separation of duties as a control against abuse of authorized privilege
without collusion. The [OWASP AI Agent Security Cheat
Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html#high-impact-action-integrity-controls)
recommends separating decisions from execution, binding approval to the exact
action, using short-lived artifacts and replay protection, and failing closed.

Steward already has the unusual parts needed to enforce those controls: a
site-root-signed tenant policy, tenant-scoped Ed25519 action authorities, exact
request-byte permits, a network enforcement point, one-use replay state, and
signed receipts. A hosted approval product or general workflow engine would add
another identity, availability, and supply-chain boundary and would not work in a
fully disconnected installation.

## Decision

Add a signed `min_approvals` threshold to each tenant's authorized-effects
policy. Omission retains the existing one-approver behavior. Every connector
selected by the tenant must have at least that many distinct admitted keys.

For thresholds greater than one, `stewardctl permit issue` creates a partial
version-3 DSSE permit and `stewardctl permit approve` adds another Ed25519
signature without changing the signed payload. Each signer independently uses
the exact admission, instance intent, action-trust inventory, connector
operation, request bytes, and validity interval. The artifact is canonical: key
IDs are distinct and sorted, every signature must be trusted and valid, and the
number of signatures must exactly equal the signed threshold before use.

Gateway enforces the threshold before DNS resolution or an upstream connection.
It binds the threshold into the immutable runtime grant, route-policy digest,
durable state, permit, one-use reservation, and signed authorization and terminal
receipts. Receipt format 6 records the canonical signer set and threshold so an
offline auditor can prove which independent authorities approved the exact
effect. Private approval keys remain outside Steward services and agent
containers.

**Tradeoff:** this is an `in-house` policy and artifact extension because the
security property spans Steward's existing signed policy, offline CLI, Gateway,
and evidence formats. Reusing a separate approval server would create a second
source of truth and weaken disconnected operation. The cost is another durable
format and an operator handoff ceremony that must remain carefully tested.

**Rejected:** a generic workflow or ticket system, because it would be much
larger than the exact authorization problem and would make air-gapped operation
depend on another service. Browser-held signing keys were rejected because the
console processes fleet metadata and shares risk with browser extensions and
page content. Controller-held private keys were rejected because compromise of
the enforcement service would then also satisfy its own approval condition.
Host-level “allow this endpoint” prompts, such as [NemoClaw's session-scoped
network approval](https://docs.nvidia.com/nemoclaw/0.0.32/network-policy/approve-network-requests.html),
were not reused because they authorize a network destination, not one exact
tenant action and request body.

## Consequences

Two-person approval reduces single-operator and single-key risk; it does not
eliminate collusion, compromised operator endpoints, or a misleading out-of-band
review. Operators must separate private keys and review the CLI's concrete action
summary before signing.

The threshold is a minimum policy requirement, but each permit intentionally
contains exactly that number of signatures. This keeps the final artifact and
receipt identity deterministic. To replace an approver or change the threshold,
sign and admit a new site policy instead of mutating an in-flight permit.

Revisit the implementation if a standard offline authorization artifact can bind
the same tenant, runtime generation, operation policy, exact request bytes,
threshold, signer set, expiry, and replay identity without adding a runtime or
private dependency. Revisit the operator ceremony when hardware-backed Ed25519
signing can be added while preserving non-interactive and air-gapped use.
