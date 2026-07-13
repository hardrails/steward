---
title: Pin opaque storage backends with Go rooted descriptors
description: Why storage-handle resolution uses the standard library rooted filesystem API instead of returning host paths.
section: Architecture decision
---

# Pin opaque storage backends with Go rooted descriptors

- Status: Accepted
- Date: 2026-07-12
- Rung: built-in

## Context

An opaque state or secret handle must resolve beneath one operator-selected root.
A lexical path check does not prevent the root or a child from being replaced with
a symbolic link after validation. Returning the checked path also lets revocation
race later use.

Steward must keep its zero-dependency build and must not add a general filesystem
abstraction for this narrow contract.

## Decision

Use Go's standard-library `os.Root` API to open and pin the configured root, open
kind and backend directories relative to that descriptor, and return a
descriptor-bound lease instead of a host path. Reject symbolic links and
non-directory objects at the root-owned kind and backend entries. Revocation closes
all outstanding leases before the handle can be resolved again.

**Tradeoff:** the built-in API prevents escape and root-path replacement with less
privileged code and no new module. Linux-specific mount, device, owner, and project
quota identity still require explicit checks in the later storage service.

**Rejected:** raw `filepath.Join` plus `EvalSymlinks` retains check-then-use races.
A custom `openat2` wrapper would duplicate standard-library descriptor management
and add platform-specific ownership before the production quota contract needs it.

## Consequences

Callers cannot serialize or retain a resolved backend path. A lease proves only
that its descriptor is still open; stopping an already-mounted workload remains a
separate containment action. Revisit this choice if the production storage service
must prohibit filesystem-boundary crossings or expose Linux mount descriptors that
`os.Root` cannot represent.
