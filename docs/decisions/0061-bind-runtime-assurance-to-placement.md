---
title: Bind runtime assurance to signed placement and elastic membership
description: Why Steward uses a small digest-bound runtime contract instead of trusting node labels or building remote attestation.
section: Architecture decision
---

# Bind runtime assurance to signed placement and elastic membership

- Status: Accepted
- Date: 2026-07-22
- Rung: in-house contract over existing native runtime controls

## Context

Executor already refuses to start without Docker and gVisor, and it reports
resource policy, isolation, labels, and taints to Control. Those reports are
authenticated node observations, not independent proof. A compromised node can
lie, and an arbitrary label such as `secure=true` has no defined relationship to
the startup settings that actually affect tenant isolation.

Elastic pools add a second boundary. Their independent membership authority binds
one node's boot identity and resource-policy digest, but previously did not bind
the security-relevant runtime configuration. Control could therefore project a
weaker node configuration without invalidating pool eligibility.

## Decision

**Decision:** define a small, fixed-schema runtime-assurance statement derived by
Executor from its effective startup configuration. Bind its SHA-256 digest into
new independently signed pool memberships and allow tenant-signed placement to
require an exact assurance profile.

The first statement records the runtime, isolation boundary, network topology,
state-isolation mode, credential boundary, and whether host-admin intent is
enabled. `shared-host-hardened` rejects unquotaed state and host-admin intent.
`dedicated-host-hardened` describes the explicitly weaker dedicated-host profile.

**Why:** Steward needs a stable contract that scheduling, enrollment, audit, and
future backend conformance can share. Reusing the existing scheduling observation
and pool-membership signature avoids a new daemon, trust root, or attestation
protocol.

**Rejected:** treating labels as assurance, because labels are operator metadata
with no enforced semantics. Also rejected: implementing remote attestation,
measured boot, or a hardware verifier inside Steward. Those systems are specialized
infrastructure and a valid measurement still does not prove that a running host is
uncompromised.

**Revisit if:** a supported SPIRE, TPM, confidential-computing, Incus, or
Kubernetes Agent Sandbox integration can supply independently verified evidence.
That evidence should extend this contract and its freshness metadata rather than
silently upgrading a node's assurance claim.

## Compatibility and failure behavior

Older Executor observations may omit assurance during a rolling upgrade. They
cannot satisfy a signed `required_assurance` constraint. Pool memberships issued
before this decision may omit the digest until their existing expiry, which is at
most 24 hours; new CLI-issued memberships require it. A mismatch makes the node
ineligible and never falls back to a label or weaker profile.

The report remains an authenticated claim by the node. Documentation, receipts,
and the console must not call it remote attestation or proof of host integrity.
