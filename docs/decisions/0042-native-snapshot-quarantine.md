---
title: Keep snapshot quarantine in Steward Control
description: Why Steward owns fork-admission quarantine while the storage backend continues to own snapshot bytes.
---

# 0042. Keep snapshot quarantine in Steward Control

- Status: Accepted
- Date: 2026-07-20
- Rung: in-house

## Context

An immutable agent-state snapshot can preserve attacker-controlled instructions,
compromised configuration, or other unsafe state. Responders need to prevent a
known snapshot from creating more agents without deleting forensic evidence or
quarantining an otherwise healthy node. This decision must survive controller
restart and concurrent operators.

The qualified local storage backend is OpenZFS, but future deployments may use
CSI or another conformant provider. A ZFS property alone would make the
admission decision backend-specific and would not give Control a portable,
revisioned gate before desired state is accepted.

## Decision

Steward Control retains the quarantine decision for one exact tenant, source
node, and snapshot identity. The record has a bounded reason, monotonic revision,
and durable timestamp. Tenant-scoped operators can inspect and change only their
tenant's records. Applying a new fork from an actively quarantined snapshot fails
closed before desired state is created.

Storage remains `native-platform`: OpenZFS or another conformant provider owns
snapshot bytes, immutability, clone mechanics, quotas, and deletion. Steward does
not inspect or modify storage when the quarantine changes.

**Tradeoff:** The controller retains cleared records and a finite per-tenant
history, increasing durable metadata. In return, restart or identity reuse cannot
reset the optimistic revision and let a stale operator overwrite a newer incident
decision.

**Rejected:** Deleting the snapshot on quarantine, because that destroys evidence
and may fail while dependent clones exist; storing only a ZFS property, because it
is not portable and places an admission decision behind storage-specific
authority; and quarantining the whole node, because it unnecessarily removes
healthy workloads and unrelated snapshots from service.

## Consequences

Snapshot quarantine blocks new forks only. It does not revoke already-created
forks, stop workloads, delete bytes, validate content, or replace credential
revocation and node quarantine. Operators must compose the narrow controls that
match the incident.

Revisit when Steward supports replicated snapshot identities across nodes. The
current key deliberately includes the source node because snapshots are
node-local and cannot be assumed equivalent across storage providers.
