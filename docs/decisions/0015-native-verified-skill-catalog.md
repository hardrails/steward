# 0015. Build a native verified skill catalog

- Status: Accepted
- Date: 2026-07-16
- Rung: in-house

## Context

Agent skills combine model-facing instructions, executable files, and access to
the agent's granted tools. A publisher signature proves origin, not safety, and
Steward's current site policy cannot constrain the artifact digests carried by a
signed capsule. Operators also have no offline catalog for discovering and
comparing the signed agent releases they have chosen to trust.

A hosted registry would add an online trust and availability dependency. A
natural-language malware scanner would add a heuristic security boundary that
cannot reliably detect dormant or context-dependent behavior.

## Decision

Extend Steward's finite signed policy so publisher and tenant rules approve
artifact kinds and digests exactly. Build a standard-library-only, curator-signed
offline catalog that embeds already verified agent-release envelopes and their
pinned publisher identities. Catalog entries bind the external archive, skill
manifest, and qualification-evidence digests, and expose bounded outcome,
capability, qualification, status, and limitation metadata for offline search
and comparison.

The catalog remains descriptive. It cannot authorize a tenant, node, image
import, workload, task, connector call, or rollout.

**Tradeoff:** Steward owns a small public catalog schema and additional policy
validation, but operators gain a portable, air-gapped release-discovery surface
without a new service or dependency.

**Rejected:** a hosted registry, mutable catalog aliases, a general package
manager, and a heuristic malicious-skill scanner because they either add external
authority or cannot provide the enforcement guarantee Steward needs.

## Consequences

Changing a skill requires a new immutable artifact digest and a new signed
release or catalog revision. Existing site policies must explicitly allow every
capsule artifact they accept. Qualification remains evidence about one exact
test; it does not prove that later agent behavior is benign.

Revisit if a stable, offline-verifiable skill-attestation standard can represent
the same finite artifact, authority, and qualification bindings without widening
Steward's trusted core.
