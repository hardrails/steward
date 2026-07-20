---
title: Native tenant-wide resource quotas
description: Why Steward Control owns atomic cross-node quota reservations while Executor and external schedulers retain local enforcement.
---

# 0040. Native tenant-wide resource quotas

- Status: Accepted
- Date: 2026-07-20
- Rung: in-house

## Context

Executor already enforces per-workload, host, and per-node tenant limits. Those
limits cannot stop one tenant from consuming its full allowance on every node in
a fleet. Steward supports ordinary Linux servers as well as future cluster
backends, so a Kubernetes-only `ResourceQuota` would leave the portable control
contract incomplete.

## Decision

Steward Control owns one durable tenant-wide ceiling over the raw CPU, memory,
process, and workload-slot requests in signed admission intent. The same locked
transaction that queues admission reserves quota. Work that has not won admission
owns no reservation; later and ambiguous lifecycle phases retain one until removal
or confirmed absence. Site administrators set the ceiling with optimistic
revisions. Lowering it blocks new admission but never pretends to evict existing
work.

**Tradeoff:** This adds quota accounting to Steward's bounded single-writer state,
but keeps the decision atomic with generation fencing, placement, and signed
command creation on every supported fleet substrate.

**Rejected:** Relying only on Docker limits, because they are node-local; relying
only on Kubernetes `ResourceQuota`, because ordinary Linux fleets remain a
supported product profile; and adding a general scheduler dependency, because
the required operation is one narrow reservation transaction.

## Consequences

Executor still independently enforces node-local limits and runtime overhead.
Kubernetes, Nomad, or another backend may enforce a stricter local ceiling but
cannot widen Steward's tenant decision. Disk bytes, inodes, and persistent-state
quotas remain a storage-backend responsibility.

Revisit if Steward adopts an external control store or scheduler whose transaction
can prove the same tenant, generation, reservation, and command-enqueue invariant
across every supported backend.
