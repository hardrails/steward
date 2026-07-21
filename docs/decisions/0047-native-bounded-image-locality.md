---
title: Use Docker's bounded image inventory for soft placement locality
description: Why Steward reads exact local image config identities from Docker without turning cache state into admission authority.
---

# Use Docker's bounded image inventory for soft placement locality

- Status: Accepted
- Date: 2026-07-20
- Rung: native-platform plus in-house

## Context

An air-gapped or bandwidth-limited fleet should avoid transferring an agent image
to a node that already has the exact image. The controller previously treated
otherwise equivalent nodes as equal even when one already held the signed
application's image. Docker already owns the local image inventory, while Steward
owns the agent-specific placement explanation and authority boundary.

Repository tags and manifest aliases are not strong enough for this decision.
Executor admission binds a workload to the image config digest discovered during
signed OCI inspection, so locality must use the same identity. Image inventory is
also untrusted operational input: it can become large, malformed, stale, or
unavailable and must not decide whether a workload is authorized.

## Decision

Decision: use `native-platform` for Docker's local images API and `in-house` for a
small, deterministic scheduling preference. Executor reads at most 1 MiB, accepts
only canonical SHA-256 config identities, sorts and removes duplicates, and
publishes at most 128 entries. Control prefers an eligible node that reports the
exact config digest only after topology spread and tenant-signed label preferences.
It records the digest, match, and whether locality was reported in the durable
placement explanation.

The inventory is never admission evidence. A missing, empty, stale, or truncated
cache report cannot make an ineligible node eligible or widen signed authority.
Executor still inspects the exact signed image immediately before it changes
runtime state.

Rejected: adding an OCI registry SDK, pulling images from Control, or requiring
Kubernetes or Nomad for this optimization. Those choices add supply-chain or
operational ownership without strengthening Steward's authority model. Revisit
the native inventory adapter when another qualified execution backend passes the
backend conformance contract.

## Consequences

- Repeated deployments can avoid unnecessary image transfer on small fleets.
- Operators can distinguish “not reported,” “reported but absent,” and “selected
  from the local cache” in the API; the console shows each node's reported cache
  count.
- Large caches degrade only the optimization: a deterministic bounded subset is
  reported, so scheduling and command delivery remain available.
- A dishonest or stale report can cause a slower placement, but it cannot approve
  an image or bypass Executor admission.
