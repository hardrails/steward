---
title: Scope node-local credentials by role
description: Why Executor uses three static loopback roles instead of one shared administrator token or a new identity service.
section: Architecture decision
---

# Scope node-local credentials by role

- Status: Accepted
- Date: 2026-07-17
- Rung: small in-house authorization layer over owner-only files and the existing loopback API

## Context

Executor's local bearer was a host-administrator credential for every authenticated
endpoint. A monitoring process that needed readiness or workload status therefore
needed the same credential used for admission, state purge, and activation
authorization. File ownership and loopback binding reduced exposure, but compromise
of a legitimate read-only consumer still inherited unnecessary authority.

Current standards work points in the same direction. NIST's
[agent identity and authorization concept paper](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf)
asks how agents and supporting software can receive least privilege and prove
authority for specific actions. The draft
[Cybersecurity Framework Profile for Artificial Intelligence](https://nvlpubs.nist.gov/nistpubs/ir/2025/NIST.IR.8596.iprd.pdf)
prioritizes distinguishing agents as entities and assigning their own permissions.
These sources do not evaluate Steward. They support reducing inherited authority at
each service boundary.

## Decision

Executor accepts up to three packaged node-local credentials:

- `observer` reads identity, readiness, maintenance state, workload state, bounded
  logs, and egress statistics;
- `operator` adds start, stop, destroy, and maintenance changes; and
- `host-admin` adds admission, legacy provisioning, state purge, activation
  preflight, and activation checkpoints.

Every server requires exactly one host administrator. Optional role tokens must be
unique, owner-only files. Executor retains only SHA-256 verifiers in memory and
compares every configured verifier before selecting a match. A caller can use
`GET /v1/local-principal` or `stewardctl node whoami` to confirm the presented
credential's fixed ID and role.

Roles limit host-local API operations only. They do not identify a tenant, bypass
site policy, or create an uplink principal. Signed lifecycle calls still require
the authenticated tenant/node/generation context or the separately configured
host-administrator compatibility mode.

Fresh configuration creates all three credentials. Existing nodes with only the
host-administrator token remain valid; reconfiguration creates the narrower tokens
without replacing the administrator value.

## Rejected alternatives

- **Keep one shared token.** This makes dashboards, diagnostics, and maintenance
  automation equivalent to admission authority.
- **Build a dynamic identity database and token-issuance API in Executor.** That
  adds mutable security state, recovery, rotation, and audit machinery to every
  node. Steward Control already owns fleet identity; the local surface needs only
  a small offline-capable boundary.
- **Use Unix peer credentials as the only identity.** Peer credential APIs are
  operating-system-specific, supplementary-group semantics are awkward, and the
  current HTTP clients and MCP bridge need a portable loopback contract.
- **Treat a local role as tenant identity.** A host-wide file cannot prove which
  tenant authorized one generation. Steward keeps that authority in signed intent
  and authenticated uplink context.

## Consequences

Operators can give monitoring and lifecycle automation less authority than
admission tooling. Role changes require replacing the relevant owner-only token and
restarting Executor; local credentials have no automatic expiry or tenant scope.
Host root remains trusted and can read every packaged token. The listener remains
loopback-only by default, and remote fleet operations should continue through the
outbound authenticated control path.
