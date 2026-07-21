---
title: "Decision 0050: Field failures become executable release gates"
description: Require boundary-specific diagnostics, patch-safe configuration, CLI/documentation parity, runtime-profile preflight, and narrow reconciliation recovery.
section: Architecture decision
---

# Decision 0050: Field failures become executable release gates

## Status

Accepted.

## Context

A clean-node signed-admission exercise proved Steward's network isolation and
receipt chain, but exposed failures that unit-level happy paths did not make
operable. Durable policy mismatch looked like network unavailability; different
upstream HTTP failures looked like permit reuse; reconfiguration silently reset
security-sensitive options; current-source docs named commands absent from an
older binary; a proven-missing container could not be tombstoned; and named
runtime profile values existed in multiple code and documentation locations.

These are release-quality failures even when the underlying isolation control
holds. An operator must be able to identify the failed trust boundary and take a
safe next action without reading Go source, decoding raw receipt bytes, or
purging the node.

## Decision

- Preserve safe diagnostic evidence in stable error codes and messages. Never
  copy an untrusted upstream body, credential, request, or agent output into an
  error.
- Treat signed-admission reconfiguration as a patch. Omitted compatibility
  choices persist; disabling them is explicit and tested.
- Build `stewardctl` during documentation checks and reject documented top-level
  command paths missing from that binary. Run the check in CI and again before a
  release build. The public site identifies itself as current-source docs and
  directs operators to the matching tag.
- Keep named runtime command, identity, state, and service contracts in the
  admission registry. Publisher tooling and capsule preflight consume the same
  values. A test requires the reference table to match the registry exactly.
- Permit destroy to recover a container proven missing by reconciliation only
  under the narrow conditions recorded in `AGENTS.md`. Recovery removes
  residual authority and tombstones the fence; it does not recreate or adopt.

## Rejected alternatives

A general `--force` switch was rejected because it would erase the distinction
between proven absence and ambiguous or foreign state. Logging more detail only
to the service journal was rejected because the remote operator still lacks an
actionable response. Provider SDKs and a general API gateway were not needed for
these gates and would violate Steward's dependency and offline-build goals.

## Consequences

Error-code changes are public behavior and require regression tests for initial
failure, replay, and durable evidence. Profile changes require code, docs, and
publisher tests in one commit. Documentation drift now fails pull requests and
release builds. Recovery remains intentionally incomplete for pending journals,
multiple degraded objects, or identity mismatch; those conditions require a
specific future recovery design rather than a broader bypass.
