---
title: ADR 0062 — Use a native bounded archive for Control checkpoints
description: Why Steward owns Control checkpoint semantics while leaving encryption, replication, and high availability to established external systems.
section: Architecture decision
---

# ADR 0062: Use a native bounded archive for Control checkpoints

**Status:** accepted

## Context

Steward Control keeps a hash-chained snapshot and write-ahead log beside the
authentication, controller, and evidence-witness identities that give the state
meaning. The previous instruction to stop Control and copy the directory was
directionally correct but not enforceable. Operators could omit one identity,
copy during a write, restore one file from a different generation, extract an
unsafe archive, or discover corruption only after replacing the live directory.

Generic backup products can encrypt, replicate, retain, and schedule bytes well.
They do not know which Steward files form one authority checkpoint, how to acquire
the writer lock, or how to validate the restored state machine and separate
signing identities.

## Decision

Steward provides a standard-library-only `stewardctl control backup` command with
create, verify, and restore operations.

- Creation requires the stopped store's exclusive lock and the complete default
  identity set. It writes a new owner-only uncompressed tar archive with a strict
  first-entry manifest and SHA-256 digest for every declared file.
- Verification streams bounded content and accepts only the exact canonical
  inventory. Links, paths, special files, ambiguous JSON, trailing entries, and
  digest mismatches fail closed.
- Restore previews by default. With explicit `-apply`, it atomically reserves an
  absent owner-only destination, extracts into that reservation, validates the
  store and identities with their normal readers, and removes the directory on
  every failed path. Success is reported only after validation and durable
  writes.
- The archive excludes `LOCK`; the validated restored store creates its own lock.
  It never merges with or overwrites an existing state directory.

Steward does not add compression, encryption, remote storage, scheduling,
retention, replication, or consensus. Operators use a vetted backup or storage
system around the resulting file. Those systems remain replaceable and outside
the controller's trust boundary.

## Consequences

The recovery unit is now machine-verifiable and testable under hostile input.
Operators can prove that an archive matches a specific generation and sequence
before cutover. The format remains portable across Linux and macOS without a new
runtime dependency.

The archive contains high-impact private material and is not encrypted by
Steward. Custody, encryption at rest, off-site retention, restore drills, and an
independently protected archive digest remain operator responsibilities.

Sites that configure authentication or signing identities outside the default
state directory cannot use this checkpoint command. Failing clearly is safer than
claiming atomic recovery across unrelated paths. A future external-secret or
hardware-key recovery contract should be designed with that provider rather than
smuggling arbitrary paths into this archive.
