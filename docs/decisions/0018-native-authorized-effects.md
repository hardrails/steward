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
agent to misuse credentials even when its model and tools behave as designed.
Prompt classifiers and model-based reviewers can reduce risk, but they cannot be
the authority that protects a sensitive external action.

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
identity.

**Tradeoff:** operators must manage a separate action-signing key and approve exact
request bytes for protected operations. In return, authorization does not depend
on the agent recognizing hostile content or honestly reporting its intent.

**Rejected:** NVIDIA OpenShell standing network policy, Google Agent Origin Sets,
CaMeL/FIDES-style framework integration, a hosted authorization service, and a
prompt-injection classifier as the enforcement source. Those approaches can
complement Steward, but none supplies its required combination of exact one-use
authority, durable spend-before-network, offline verification, framework
independence, and tenant-isolated sovereign operation.

## Consequences

Authorized Effects covers only external actions that Steward completely mediates.
It does not prove that an approver understood the request, make an upstream
operation exactly once after an ambiguous failure, control local filesystem or
computer-use effects, secure inference, or protect a compromised host root,
Gateway, or signing key.

Revisit the in-house permit format if a stable, independently implementable
standard provides the same exact request bindings, signed tenant-key continuity,
durable one-use consumption before I/O, and portable offline evidence without a
mandatory online dependency.
