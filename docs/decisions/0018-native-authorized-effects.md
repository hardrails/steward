---
title: Enforce authorized effects outside the agent
description: Why Steward assumes an agent can be manipulated and requires signed, single-use authority for each managed external effect.
section: Architecture decision
---

# Enforce authorized effects outside the agent

- Status: Accepted
- Date: 2026-07-16
- Rung: in-house

## Context

An agent can treat attacker-controlled content as instructions. A calendar event,
web page, email, tool result, or retained memory can therefore cause a capable
agent to misuse credentials even when its model and tools behave as designed. A
[demonstrated calendar-invite attack](https://labs.zenity.io/p/perplexedbrowser-how-attackers-can-weaponize-comet-to-takeover-your-1password-vault)
used ordinary browser behavior to enter an authenticated 1Password session, reveal
secrets, change account settings, and send recovery material to an attacker.
[1Password describes this as an ecosystem risk](https://1password.com/blog/security-advisory-for-ai-assisted-browsing-with-the-1password-browser),
not a break in its cryptography or authentication model.

Prompt classifiers and model-based reviewers can reduce risk, but they cannot be
the authority that protects a sensitive external action. Research on
[contextual-integrity attacks](https://arxiv.org/abs/2605.17634) explains a deeper
limit: an attacker can make a prohibited flow appear contextually legitimate, while
a tighter defense can also block legitimate work.

Steward already keeps connector credentials outside the workload, binds an action
permit to one exact request, and spends that permit durably before network access.
The remaining gap is policy continuity. Signed tenant policy cannot currently
require that boundary or pin the public keys allowed to authorize effects. A
modified node configuration could consequently select a broader connector or
substitute another same-tenant approval key.

The solution must remain framework-independent, usable without an Internet
connection, and enforceable against unmodified Hermes, OpenClaw, and other agent
images. Images and node configuration remain untrusted inputs.

## Decision

Steward adds an opt-in **Authorized Effects** mode. It assumes the agent may be
fully manipulated and controls what the manipulated agent can do through Steward's
managed external-effect boundary.

Signed tenant policy states whether Authorized Effects is optional or required and
pins tenant-owned Ed25519 action-authority public keys to connector IDs. An
authenticated instance intent explicitly selects the mode. Executor carries that
signed-policy-derived mode and key set through its immutable runtime record to
Gateway. Gateway intersects the grant with its validated connector configuration;
it rejects a missing, additional, or substituted same-tenant key.

An authorized-effects grant cannot include generic egress. Every selected
connector must require an action permit. The permit binds the exact tenant,
instance generation, admitted artifact and policy, connector operation, credential
epoch, request bytes, content type, validity window, and effective route policy.
Gateway records the one-use spend before DNS or any upstream connection and keeps
credentials outside the workload.

Steward records accepted effects with the effect mode and exact operation-policy
digest in its signed connector evidence. Stable pre-effect denials may be recorded
only under a strict bounded policy; denial logging must never let an untrusted
workload exhaust another tenant's evidence capacity or poison a legitimate task
identity. The retained marker is necessarily a first-observed, attacker-selectable
sample rather than an exhaustive denial history.

**Tradeoff:** operators must manage a separate action-signing key and approve exact
request bytes for protected operations. In return, authorization does not depend
on the agent recognizing hostile content or honestly reporting its intent.

**Complementary, not substitutes:**
[NVIDIA OpenShell](https://docs.nvidia.com/openshell/reference/policy-schema)
documents sandbox, network, application-protocol, and credential-routing policy;
[Google Agent Origin Sets](https://blog.google/security/architecting-security-for-agentic/)
separate readable and writable browser origins;
[CaMeL](https://arxiv.org/abs/2503.18813) and
[Fides](https://arxiv.org/abs/2505.23643) enforce control/data-flow or
information-flow rules in integrated planners; and
[Open Agent Passport](https://arxiv.org/abs/2603.20953) proposes deterministic
pre-tool authorization and signed audit records. Steward can operate alongside
these controls. It does not use any of them as its enforcement source because none
supplies the required combination of signed tenant-key continuity, exact one-use
request authority, durable spend before DNS, framework independence, and portable
offline evidence on a disconnected node.

## Consequences

Authorized Effects covers only external actions that Steward completely mediates.
It does not prove that an approver understood the request, make an upstream
operation exactly once after an ambiguous failure, control local filesystem or
computer-use effects, secure inference confidentiality, constrain unmanaged
credentials or network channels, or protect a compromised host root, Gateway, or
signing key.

Revisit the in-house permit format if a stable, independently implementable
standard provides the same exact request bindings, signed tenant-key continuity,
durable one-use consumption before I/O, and portable offline evidence without a
mandatory online dependency.
