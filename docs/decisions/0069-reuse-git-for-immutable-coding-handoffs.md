---
title: "ADR 0069: Reuse Git for immutable coding-worker handoffs"
description: Why coding workers return a bounded base-and-patch package instead of sharing mutable workspaces or adding an artifact service.
section: Architecture decision
---

# ADR 0069: Reuse Git for immutable coding-worker handoffs

- Status: Accepted
- Date: 2026-07-28
- Rung: native-platform

## Context

Steward's optional coding worker already runs the official Codex or Claude Code
CLI in a separately isolated container. A write task currently returns changed
paths and untrusted engine output. That is enough to tell an operator where to
look, but not enough to give a separately authorized reviewer the exact result
without mounting the same mutable checkout.

A trustworthy handoff must bind the repository state accepted before execution,
the exact version-controlled change bytes, and the tree obtained after applying
them. It must remain bounded by the existing connector response, work without a
hosted service, preserve the worker's no-commit/no-push boundary, and avoid adding
another signing key to an engine that already sits behind Steward Gateway.

Git already defines commit, tree, binary patch, file-mode, symlink, and apply
semantics. A new patch or archive format would create a second repository model,
while a shared worktree would let the producer change what the reviewer sees.
Steward's qualified storage snapshots serve persistent agent-state forks; they do
not provide a portable, repository-aware code-review artifact.

## Decision

Add an opt-in `steward.coding-task.v2` contract. The caller binds one expected Git
base commit. After the engine exits, the coding worker returns
`steward.coding-result.v2` with a bounded `steward.git-handoff.v1`:

- Git object format, base commit, and base tree;
- one binary, full-index, no-rename patch;
- patch SHA-256 digest and byte length;
- a result tree independently reproduced by applying that patch to the base
  through a temporary index and temporary object directory; and
- a sorted, unique changed-path inventory.

The worker captures the patch twice and requires byte-for-byte stability. Fixed
Git commands disable external diffs, text conversion, hooks, filesystem monitors,
system and user configuration, prompts, and pagers. The temporary verification
store may read the checkout's existing objects but cannot write its index, refs,
or object database.

Version 1 requests and results remain available. The signed Hermes developer
helper requires a caller-selected, one-use connector task ID and forwards it
through the already required `X-Steward-Task-ID` header. An expected base selects
version 2; omission selects version 1.

Version 2 excludes ignored files and rejects submodules and special files. Those
states need separate nested-repository or device semantics and must not be
silently flattened into an apparently complete handoff.

The handoff is application output, not a correctness verdict or a new signature.
Gateway still mediates the call and records its bounded connector evidence. A
future receipt contract may correlate and sign the exact nested response digest;
this decision does not overstate the current receipt as proof of the worker
response bytes.

**Tradeoff:** Bounded patches do not cover arbitrarily large repositories or
generated artifacts, and SHA-1 repositories retain Git's SHA-1 object identity
alongside the independent SHA-256 patch digest. In return, reviewers receive a
small, offline-reproducible package with no new service, dependency, or mutable
workspace coupling.

**Rejected:** A shared checkout permits time-of-check/time-of-use substitution. A
custom tar or JSON file format would duplicate Git modes, links, deletions, and
binary semantics. A new object store would add credentials, retention, recovery,
and availability ownership. Having the worker sign its own report would add a key
inside the same trust boundary without proving correctness.

## Consequences

- An independent reviewer can materialize the exact result tree from the named
  base and returned patch without accessing the producer's checkout.
- A mismatched base, changed history, unstable capture, non-reproducible patch,
  unsupported repository shape, or exceeded bound fails closed.
- The coding worker still never commits, pushes, merges, publishes, or declares a
  patch correct.
- Operators should mount a disposable clone and make its Git metadata read-only.
  A host worktree whose `.git` file points outside the mount is not a portable
  container input.
- Steward retains zero private Go dependencies and adds no provider SDK, workflow
  engine, signing service, or artifact database.

Revisit when a stable portable standard can express the same base/result identity
and bounded binary changes, when qualified storage supports a portable
repository-aware snapshot, or when measured patch sizes require an independently
authorized artifact store.
