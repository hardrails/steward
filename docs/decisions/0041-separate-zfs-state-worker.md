---
title: Separate ZFS state worker
description: Why Steward reuses OpenZFS behind a narrow local protocol instead of implementing storage or giving Control filesystem authority.
---

# 0041. Separate ZFS state worker

- Status: Accepted
- Date: 2026-07-20
- Rung: native-platform

## Context

Multi-tenant persistent agent state needs hard byte and object-count limits,
immutable cold snapshots, copy-on-write clones, durable metadata, and deletion
that survives process restart. Docker named volumes do not provide that contract.
Control must not gain host filesystem or Docker authority, and Executor should not
become a filesystem implementation.

## Decision

Use OpenZFS for the first qualified local state backend. Put its narrow dataset,
quota, snapshot, clone, and deletion authority in a separate local worker. Executor
talks to that worker through a bounded provider-neutral protocol and receives an
opaque Docker volume handle, never a tenant-selected dataset or host path. Steward
owns tenant scope, lineage, generations, retention, authorization, and evidence;
OpenZFS owns storage bytes, hard space and object quotas, snapshots, and clones.

The worker must run with delegated authority limited to one operator-selected ZFS
dataset root. It must persist idempotency and object identity in dataset properties,
reject rebinding after restart, and pass the same hostile-path conformance suite as
future CSI or other backends.

**Tradeoff:** Operators who select the local multi-tenant profile must install and
operate OpenZFS, but Steward avoids a new storage engine and keeps privileged
storage authority outside Control and the agent process.

**Rejected:** Unquotaed Docker volumes, because they cannot isolate hostile tenants;
an in-process filesystem or snapshot implementation, because storage is commodity
infrastructure with a much larger failure surface; and a mandatory Kubernetes/CSI
deployment, because one ordinary Linux server remains a supported production
profile.

## Consequences

The existing unquotaed Docker-volume path remains an explicit dedicated-host-only
opt-in. A provider capability claim is not enough for production qualification:
hard quotas, immutable snapshots, clone identity, crash recovery, cross-tenant
denial, and deletion safety must be exercised against the real backend.

Revisit if another portable local substrate provides hard byte and object quotas,
atomic snapshots, and copy-on-write clones with a smaller operational footprint,
or if all supported production sites already provide a conformant CSI backend.
