---
title: Use the browser as a signed-command courier
description: Why the operator console may submit exact offline-signed command bytes without signing, editing, or retaining authority in the browser.
section: Architecture decision
---

# Use the browser as a signed-command courier

- Status: Accepted
- Date: 2026-07-17
- Rung: native platform

## Context

Operators can already issue Executor commands on a disconnected signing station
and submit the resulting DSSE envelope with `stewardctl`. The embedded React
console can inspect command inventory, but it cannot complete that existing
workflow. This forces routine operators back to a command line even when the
authority decision and signature have already happened elsewhere.

Turning the console into a general mutation or signing surface would create a
larger security boundary. A compromised browser, extension, or injected document
could choose new command bytes, retain private keys, or silently widen policy.
That is especially dangerous for agents because untrusted content can contain
prompt-injection instructions. [NIST's software-agent identity and authorization
concept paper](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf)
calls for explicit authorization, auditing, and non-repudiation, while current
agent sandboxes commonly handle blocked actions by adding a new rule to the
running session's policy. A policy change authorizes a class of future requests;
it does not authorize one immutable command.

The existing controller already accepts one exact, signed Executor command at
`POST /v1/tenants/{tenant_id}/nodes/{node_id}/commands`. It authenticates the
operator transport, verifies the DSSE envelope against signed site policy,
checks tenant and node scope, enforces bounded input and command validity, stores
an audit record, and gives the node the same bytes for independent verification.

## Decision

Add a signed-command courier to the React console. The browser may load one local
DSSE JSON file, decode it for an explicitly unverified preview, calculate the
SHA-256 digest of the exact file bytes, and send those unchanged bytes to the
existing command endpoint.

The courier uses browser-native `File`, `TextDecoder`, standard Base64 handling,
and Web Crypto. It adds no JavaScript package, server endpoint, signing protocol,
or controller authority. The browser must never create or edit a command, hold a
private signing key, or claim that the preview verifies a signature. The
controller remains the authority for acceptance.

Submission requires all of the following:

- one canonical DSSE envelope no larger than the controller's one-mebibyte body
  boundary;
- the expected Executor command payload type and schema in the local preview;
- a tenant and node that match the command's signed statement and the active
  console projection;
- an exact confirmation phrase containing the signed command identifier;
- re-entry of the operator bearer credential immediately before submission; and
- a preview loaded within the short review window.

The re-entered credential is used for that request and cleared from the input
immediately. Requests omit cookies and referrers, reject redirects, and remain on
the controller's origin. Existing controller authorization, DSSE verification,
idempotency, audit retention, and node-side verification still apply.

**Tradeoff:** this closes a meaningful operator workflow without making browser
state a source of execution authority. It does not protect against a browser or
extension that can replace the displayed bytes and the submitted bytes together.
Operators must compare the displayed SHA-256 digest with the value from the
offline signing workflow and use a hardened operator browser profile.

**Rejected:** browser-side signing or key storage, a new approval service, a
generic mutation client, and a custom policy prover. Each would create new
authority or long-term ownership without improving verification of this exact
signed command. Automatically adding network rules from an agent proposal was
also rejected: [OpenShell's Policy Advisor](https://docs.nvidia.com/openshell/sandboxes/policy-advisor)
already explores that design, and it widens session policy rather than preserving
request-bound authority.

## Consequences

The console is observation-first, not observation-only. Command submission is
the single mutation exposed in the browser, and only for an already signed,
immutable command. Private keys, command construction, policy changes, secret
retrieval, enrollment, operator administration, and every other mutation remain
outside the console.

The local preview is a safety aid, not a signature verifier. A malformed or
unauthorized envelope can pass part of the preview but will fail closed at the
controller. The UI must preserve the original file bytes, label verification
state plainly, and refresh inventory only after the controller accepts them.

Revisit this decision if operators need a durable inbox for agent-originated
exact-effect proposals or hardware-backed browser signing. Either feature needs
its own authority, replay, expiry, recovery, and audit threat model rather than
an expansion of this courier.
