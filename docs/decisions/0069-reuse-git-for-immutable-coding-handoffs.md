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

A bounded reproducible handoff must bind the repository state accepted before
execution, the exact version-controlled change bytes, and the tree obtained after
applying them. It must remain bounded by the existing connector response, work
without a hosted service, avoid having the supervisor publish repository state,
and avoid adding another signing key to an engine that already sits behind
Steward Gateway.

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
system and user configuration, prompts, and pagers. The capture and verification
stores write only their own temporary indexes and object directories; they read
the checkout object database as an alternate and never write the checkout's
index, refs, or objects.

Version 1 requests and results remain available. The signed Hermes developer
helper requires a caller-selected, one-use connector task ID and forwards it
through the already required `X-Steward-Task-ID` header. An expected base selects
version 2; omission selects version 1.

Version 2 rejects ignored files present at startup and ignored output created by
the engine, along with submodules and special files. Those states need separate
nested-repository or device semantics and must not be silently flattened into an
apparently complete handoff. It also requires a clean standalone checkout at the
exact expected commit, regardless of the version 1 development escape hatch. The
supported service runtime is Linux because version 2 depends on Linux
child-process containment before it captures the final tree.

The finite contract permits at most 512 changed paths, 48 KiB of path bytes, a
256 KiB patch, and a 448 KiB canonical result. One 45-second aggregate handoff
deadline covers both captures and independent application. The coding connector
preset allows 990 seconds so a maximum 900-second engine task can finish that
bounded post-processing.

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
- The supervisor does not invoke commit, push, merge, or publish, and it rejects a
  changed final `HEAD`. That does not prove an engine never committed and reset or
  attempted a push. Operators must mount the clone's Git metadata read-only,
  remove remote credentials, and restrict egress so those effects are unavailable.
- Operators must mount a disposable standalone clone. A linked host worktree whose
  `.git` file points outside the mount is not a portable container input.
- Steward retains zero private Go dependencies and adds no provider SDK, workflow
  engine, signing service, or artifact database.

Revisit when a stable portable standard can express the same base/result identity
and bounded binary changes, when qualified storage supports a portable
repository-aware snapshot, or when measured patch sizes require an independently
authorized artifact store.
