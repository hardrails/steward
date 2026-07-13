# 0010. Build exact tenant-signed service-task authorization in Gateway

- Status: Accepted
- Date: 2026-07-13
- Rung: in-house

This decision defines the original exact-request authorization boundary. Decision
[0011](0011-portable-task-lifecycle-evidence.md) extends it with the current
authorization, dispatch, and terminal lifecycle chain and generic task commands.

## Context

A gVisor sandbox limits what an untrusted agent process can reach, but it does not
prove that a tenant authorized a particular side effect. A reusable bearer token or
broad service grant would let a manipulated agent submit different task content
within the same outer grant. Steward also has to work without a hosted policy
service, preserve its zero-dependency build, keep private signing keys off the node,
and retain evidence that an offline auditor can verify.

## Decision

Build a small standard-library authorization path in `steward-gateway`. Signed site
policy assigns each tenant one or more Ed25519 task keys scoped to exact service
IDs. An off-node key signs a short-lived DSSE statement that binds the node, tenant,
logical instance, runtime and grant, generation, admitted artifact and policies,
exact service operation, request digest and byte length, content type, and validity
window.
Gateway checks the statement against the active grant and exact request, records the
authorization durably, then dispatches only the configured `POST` operation.

The durable replay identity is `(tenant_id, instance_id, task_id)`, so replacing a
workload does not make the same logical task spendable again. A successful replay
returns only the previously recorded run ID. A missing or ambiguous terminal outcome
is never retried automatically. This is node-local at-most-once dispatch within one
retained receipt-ledger epoch, not distributed exactly-once execution.

**Tradeoff:** The implementation is narrow and requires Steward to own a signed
statement, policy digest, replay ledger, and offline verifier. In return, the full
authorization-to-receipt path remains auditable, air-gap capable, and dependency
free.

**Rejected:** JSON Web Tokens (JWTs), because a generic token format would not supply
the exact Steward request, runtime, route-policy, replay, and receipt semantics and
would add another parser or dependency surface. Open Policy Agent (OPA), because it
would add a separate policy language, binary, upgrade boundary, and availability
dependency without replacing Steward's durable dispatch ledger. A generic reverse
proxy was also rejected because it would broaden methods, paths, headers, and
responses while still leaving task identity, spend-before-effect behavior, and
offline evidence unspecified.

## Consequences

The task private key remains outside the node. Gateway and Executor retain only the
public key, and the owner-only task bundle carries the exact request and permit for
controlled transfer. Receipts record digests and bounded enforcement metadata, not
the raw prompt or request body. The agent service supplies the run ID, so that value
is untrusted application output; the receipt records what Gateway observed, not that
the agent completed useful work or reported truthfully.

Revisit the standard-library implementation if a stable, independently specified
authorization format can express every current binding, node-local replay behavior,
unknown-outcome handling, and offline receipt correlation without adding a mandatory
online service or weakening the zero-dependency contract. Revisit node-local replay
scope if Steward gains a separately specified, durable multi-node authority service.
