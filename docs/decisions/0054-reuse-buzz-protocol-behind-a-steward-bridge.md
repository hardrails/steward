---
title: Reuse Buzz protocol code behind a Steward-owned bridge
description: Why Steward integrates Buzz through a narrow, pinned bridge instead of embedding Buzz or exposing its CLI to an agent.
section: Architecture decision
---

# Reuse Buzz protocol code behind a Steward-owned bridge

- Status: Accepted
- Date: 2026-07-21
- Rung: open-source

## Context

Buzz provides signed collaboration events, channel and thread semantics, relay
authentication, and agent-oriented command-line tools. Reimplementing its Nostr,
NIP-42, and NIP-98 behavior would create security-sensitive cryptographic and
network code that is unrelated to Steward's main job.

Running Buzz's `buzz-acp` harness unchanged is also unsafe for Steward's threat
model. Its child agent inherits the harness environment, including the Buzz
private key. Its broad author modes and in-memory queues do not provide Steward's
exact tenant authorization or durable delivery guarantees. Exposing `buzz-cli`
inside Hermes would let hostile prompt content address operations outside the one
verified conversation that triggered the task.

## Decision

Reuse the Apache-2.0 Buzz protocol and cryptography crates at an exact source
commit, behind a separate tenant-specific `steward-buzz-bridge`. Apply a small,
reviewed compatibility and isolation patch during the reproducible bridge build.
The bridge verifies events locally, applies exact author and channel gates,
persists inbox and outbox transitions, issues one existing Steward signed service
task, and publishes one reply whose destination comes from the verified event.

Hermes receives a reference and bounded untrusted conversation text through fixed
connector operations. It never receives Buzz or Steward signing keys, a raw Buzz
CLI, arbitrary relay access, or authority to choose a channel, thread, event kind,
service, instance, or operation.

**Tradeoff:** Steward owns a narrow bridge and must requalify its upstream patch
when Buzz changes. It avoids owning Nostr cryptography, operating Buzz's data
plane, or weakening Steward's task and secret boundaries.

**Rejected:** Embedding a Buzz relay would make Steward responsible for Buzz,
PostgreSQL, Redis, object storage, and their upgrades. Implementing Nostr inside
Steward would expand the stdlib-only enforcement core. Running `buzz-acp`
unchanged or mounting `buzz-cli` into Hermes would expose the signing identity to
untrusted agent execution.

## Consequences

Buzz remains separately deployed. Each tenant/integration uses a separate bridge
process, state directory, Buzz identity, exact author/channel policy, and Steward
task authority. The first supported operation is a signed kind-9 exact mention to
one bounded Hermes task and one plain-text reply. DMs, forum-wide subscriptions,
uploads, administration, workflows, Git operations, arbitrary ACP/MCP commands,
and open-to-anyone dispatch are excluded.

The source pin advances only through a scheduled, reviewable pull request. It
records an immutable commit and exact input hashes; it never treats Buzz's
independent desktop, relay, chart, or rolling Sprig labels as interchangeable.
Qualification evidence must be regenerated for the proposed bytes before merge.

Revisit the patch when Buzz provides a stable structured dispatch sink, a
secretless signer interface, local verification for every delivered event, and
durable lossless delivery. Revisit the separately operated relay boundary only if
users consistently need Steward to own the complete Buzz data plane.
