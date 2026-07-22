---
title: ADR 0063 — Publish a binary-derived support contract
description: Why Steward owns a small deterministic support matrix and qualifies it from shipped release binaries instead of adopting another framework.
section: Architecture decision
---

# ADR 0063: Publish a binary-derived support contract

**Status:** accepted

## Context

Documentation can describe work that has not reached an installed release. A
version number also does not tell an operator whether a host role, architecture,
agent runtime, isolation profile, or compatibility path is supported. This gap is
especially costly in disconnected environments, where an operator cannot consult
a hosted compatibility service and must distinguish a tested contract from a
container that merely happens to start.

Generic feature-flag, package-metadata, and policy frameworks can encode arbitrary
fields, but none knows Steward's release-specific boundary. Adding one would
increase the build and supply-chain surface without providing the product truth or
the qualification evidence needed to trust it.

## Decision

Steward owns a closed, standard-library-only support contract exposed by:

```console
stewardctl support matrix -output json
```

The contract records the exact binary version, supported host roles and
architectures, qualified and explicitly unsupported agent runtimes, production
isolation requirements, interfaces, authority modes, disconnected capabilities,
compatibility paths, and known limits. Its JSON schema is stable and deterministic.
Human output is a concise projection of the same data.

The release build emits the stamped binary's JSON as
`steward-support_<version>.json` and includes it in `checksums.txt`. A separate
read-only qualification job extracts the combined release archive, verifies every
checksum and binary version, regenerates the contract from the shipped
`stewardctl`, requires a byte-for-byte match, and runs the Control acceptance
workflow with extracted binaries. Only the later code-free publish job receives
release-write authority.

The support contract does not replace the per-node `release.json`, host preflight,
runtime acceptance, provenance verification, or an authenticated release channel.
It can narrow the support claim, never widen enforcement or make an unqualified
environment supported.

## Consequences

Operators and automation can ask the installed artifact what it claims without an
Internet connection or documentation-version guess. Release publication now fails
if the advertised contract, stamped binaries, checksums, or shipped Control path
disagree.

Adding a supported backend, runtime, host role, or compatibility path requires a
code review, tests, documentation, and qualification change. This deliberate
friction keeps "supported" from becoming an unverified marketing label.

The contract is self-asserted metadata covered by the release checksum. It is not
an independent signature, host attestation, or proof that the operating system and
sandbox combination passed site-specific acceptance. High-assurance operators
must authenticate the release manifest and retain qualification evidence for the
exact production environment.
