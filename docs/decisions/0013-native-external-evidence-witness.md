# 0013. Build a native external witness for node evidence

- Status: Accepted
- Date: 2026-07-16
- Rung: in-house

## Context

Steward needs to detect when a managed node later removes or replaces signed
Executor evidence that an independent control host has already observed. The
witness must work in an air gap, keep controller storage bounded, preserve the
zero-dependency build, and remain outside the workload-enforcement availability
path.

## Decision

Extend Steward's existing Ed25519-signed, hash-linked evidence chain with a thin
controller witness. Enrollment pins the node's evidence public identity. The
node then sends bounded contiguous signed deltas, and the controller retains
only the latest verified coordinate plus bounded divergence findings.

**Tradeoff:** This detects rollback or a fork relative to one controller without
adding a database, transparency service, or second audit-log format. It does not
detect split views between independent controllers unless their checkpoints are
compared.

**Rejected:** Rekor, a hosted transparency service, or a separate SCITT service,
because each adds another state authority and operational dependency without
replacing Steward's node-specific identity, tenant-membership, and receipt
validation.

## Consequences

Witness upload is asynchronous and never gates local enforcement. Full signed
records remain on the node; the controller does not become an evidence
warehouse. Revisit this decision if customers require public transparency,
cross-controller gossip, or third-party inclusion and consistency proofs.

The controller uses a dedicated Ed25519 witness identity, separate from TLS and
bearer authentication. Fresh initialization creates an owner-only private key and
matching public key. Existing controllers use an explicit idempotent migration
that creates the pair only when both files are absent. Normal startup validates
the pair and fails on partial state, unsafe permissions, symlinks, or mismatch.
The installer preserves the identity across upgrades and exposes one stable
public-key path for offline verifiers.
