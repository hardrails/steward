---
title: Preserve release history after an unreleased baseline
description: Why Steward does not create a retroactive tag for code that reached main without a published release.
section: Architecture decision
---

# Preserve release history after an unreleased baseline

## Status

Accepted.

## Context

The source tree reports a newer fallback version than the latest public release.
The intervening work reached `main` without a matching tag or release artifact set.
Creating a tag later would make that historical point look like a release that went
through the current acceptance, packaging, and review gates when it did not.

Release tags are evidence. Operators use a tag to connect source, binaries, package
manifests, checksums, upgrade compatibility, and acceptance results. A convenient
version sequence is less important than an accurate chain of published evidence.

## Decision

Treat that fallback version as an unreleased development baseline. Do not create or
publish a retroactive tag for it. The next release may be published only from the
new delivery branch after its complete release gates pass and the operator
separately authorizes the release action.

Until then:

- `main` and development binaries may identify their exact source revision;
- documentation must describe current behavior, not imply that a development
  version is available as a supported release;
- packages and archives must be produced only by the normal release workflow; and
- a future tag must bind one source commit to its checksums, manifests, packages,
  offline acceptance evidence, and release notes.

## Consequences

The public version sequence may skip a minor number. That is intentional and more
truthful than manufacturing an artifact history. Automation must never infer that
every semantic version below the next release exists. Upgrade checks use declared
state-format compatibility and signed release manifests instead of assuming that
adjacent version numbers were published.

No tag, GitHub release, or package publication is authorized by this decision.
Those actions remain separate, explicit release steps.
