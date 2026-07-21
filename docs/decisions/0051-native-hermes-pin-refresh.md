---
title: Refresh the Hermes pin with native repository automation
description: Why Steward proposes Hermes source updates with a narrow GitHub workflow instead of a dependency bot.
section: Architecture decision
---

# Refresh the Hermes pin with native repository automation

## Status

Accepted.

## Context

Steward builds Hermes from an exact upstream commit and separately records the
release tag, package version, source license digest, and hashes of every consumed
build input. This pin is not a Go module, container tag, Git submodule, or other
dependency format understood by Dependabot. A stale pin misses upstream fixes, but
an automatic merge would falsely carry qualification evidence from different bytes.

## Decision

Use a small scheduled GitHub Actions workflow and a standard-library Python updater.
The workflow reads GitHub's latest stable Hermes release, fetches that exact tag,
resolves it to a commit, recalculates the bounded source-input hashes, and opens a
pull request. Existing CI must fail that pull request until a maintainer regenerates
the gVisor feasibility and signed-integration evidence for the proposed bytes.

**Tradeoff:** Steward owns a narrow updater, but its complete authority and behavior
remain visible in this repository and it adds no runtime or build dependency.

**Rejected:** Dependabot cannot update this custom manifest. Renovate could be taught
the format, but adopting a broad external automation system for one pin would add
configuration, supply-chain surface, and operator knowledge without removing the
qualification step.

## Consequences

The pin is checked weekly and can also be refreshed manually. Updates remain
reviewable and never merge merely because upstream published a release. Revisit this
decision if Hermes publishes a signed, standard dependency artifact that can express
all source and qualification bindings, or Steward accumulates enough custom pins to
justify one vetted dependency automation service.
