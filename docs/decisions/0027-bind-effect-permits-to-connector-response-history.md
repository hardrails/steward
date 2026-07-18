---
title: Bind exact effect permits to connector response history
status: accepted
date: 2026-07-17
---

# Bind exact effect permits to connector response history

## Context

Authorized Effects binds an operator's signature to one exact connector request,
but an ordinary permit remains usable until it expires even if the agent receives
new external information after approval. Hostile or simply changed tool output can
alter why the agent wants to perform the action without altering the request
bytes. A short validity window reduces this exposure but does not close it.

The enforcement point must remain outside the untrusted image and model. Steward
also needs a result that can be reconstructed from signed, portable evidence
without retaining response content.

## Decision

Signed tenant policy may set `authorized_effects.context_binding` to `required`.
For that grant, Gateway serializes connector calls, maintains a deterministic
grant-specific influence head, and binds the current head to authorization and
terminal receipts. A terminal receipt commits the exact released-response digest;
its signed receipt hash advances the head. Retained Gateway state preserves the
requirement, and the signed receipt ledger reconstructs the history after restart.

`stewardctl permit context` verifies the connector ledger and emits the current
head. Version-5 action permits bind that sequence and hash in both single- and
multi-party policies. Gateway rejects any permit whose context is no longer
current. Exact-effect bundles are rejected because a completed step changes the
context against which later steps would need approval.

This contract covers only responses that pass completely through Steward named
connectors. It is a history-identity control, not semantic prompt-injection
detection.

## Consequences

- A permit approved before a later connector response cannot authorize an effect
  after that response completes.
- Offline operators can reconstruct the same bounded context without response
  plaintext, provided they authenticate the ledger and preferably retain its head
  independently.
- A context-required grant permits only one in-flight connector call. Incomplete
  calls block new context derivation until Gateway records a terminal outcome.
- Gateway state and connector receipt formats advance to 7. Rollback must preserve
  both the policy bit and the signed history fields.
- Task input, inference, local memory, files, browser data, generic egress, and
  unmanaged channels remain outside this context.

## Rejected alternatives

- **Ask the model or a classifier whether context changed materially.** The
  potentially manipulated component would decide whether its own authority stays
  valid, and semantically equivalent bypasses remain possible.
- **Use one host-global history head.** Unrelated tenants and grants would
  invalidate each other's approvals and create an availability coupling across
  isolation boundaries.
- **Bind only response-body hashes supplied by the workload.** The untrusted agent
  could omit, reorder, or substitute observations. Gateway must hash the bytes it
  actually releases and sign the record itself.
- **Allow bundles against one starting context.** Later bundled steps would retain
  authority after earlier responses changed the agent's history. Per-step review
  is the clearer contract.

## Evidence

- [NIST SP 800-228A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-228A.ipd.pdf)
  discusses indirect prompt injection, scoped authorization, and tamper-resistant
  logging.
- [PAuth](https://www.microsoft.com/en-us/research/publication/pauth-precise-task-scoped-authorization-for-agents/)
  motivates precise task-scoped authority and provenance binding.
- [AI Agents May Always Fall for Prompt Injections](https://arxiv.org/abs/2605.17634)
  analyzes the limits of model-only defenses against contextually plausible flows.

