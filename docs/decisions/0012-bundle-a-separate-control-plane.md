---
title: Bundle a separate, authority-minimized control plane
description: Why Steward ships an optional fleet controller while keeping tenant signing keys and Docker authority on opposite sides of its public protocol.
section: Architecture decision
---

# Bundle a separate, authority-minimized control plane

- Status: Accepted
- Date: 2026-07-13
- Rung: in-house

## Context

Steward already provides hardened node execution, outbound uplinks, signed
multi-tenant commands, and offline evidence. Operators still need a working way to
enroll nodes, retain fleet inventory, queue commands, reclaim interrupted
deliveries, and inspect outcomes. Requiring every operator to build that service
leaves the open-source product incomplete. Requiring a vendor-hosted service would
break disconnected operation, data-sovereignty, and independent auditability.

Combining fleet coordination with `steward-executor` would be worse. Executor holds
the Docker socket and admits untrusted workloads. A fleet service accepts remote
traffic and retains credentials for many nodes and tenants. Putting both in one
process would turn a controller vulnerability into direct host execution authority.

The controller also cannot be trusted to select a tenant merely because it
authenticated a node. A shared node can run isolated workloads for several tenants.
The durable node credential therefore identifies one node and its allowed tenant
set; every executable command remains an exact DSSE envelope signed by a tenant
command key or a narrowly scoped site cleanup key. DSSE (Dead Simple Signing
Envelope) is a standard wrapper for a typed, signed payload.

## Decision

Ship `steward-control` as an optional open-source Steward binary. It is a separate
service with a separate Unix identity, state directory, authentication key, and
network policy. A production site should run it on a dedicated management host.
The packaged controller and Executor node installations must use separate hosts:
their immutable-release selectors intentionally own different trust roots, and
both installers reject co-location instead of allowing independent upgrades to
replace one another's command links.

The first complete controller provides:

1. site-admin and tenant-operator bearer credentials with tenant-scoped
   authorization;
2. tenant creation and bounded inventory;
3. one-time, expiring node enrollment that binds a node to an explicit set of
   tenants;
4. durable node credential verifiers without stored plaintext secrets; exact
   idempotent exchange retries reproduce the same bearer;
5. bounded, idempotent storage for exact tenant-signed Executor command bytes;
6. outbound node polling, delivery leases, fenced reclaim, and terminal reports;
7. operator command status plus health and readiness endpoints; and
8. deterministic local installation and an end-to-end acceptance test that works
   without a public network service.

The delivery wrapper is unsigned transport metadata. It carries a delivery ID and
generation beside the digest and exact bytes of the signed command. Reclaim may
advance the delivery generation, but it cannot change the tenant-signed command.
The node verifies the signature, tenant policy, node identity, command identity,
digest, lifecycle generation, and sequence before execution. It also recomputes a
domain-separated delivery ID from the verified tenant, node, and command, rather
than trusting the wrapper's ID. It durably records accepted, executing, and
terminal delivery states and reserves the largest possible terminal encoding
before handler entry. After a crash or error during a mutating handler, an
unprovable outcome becomes `outcome_unknown`; Steward does not automatically repeat
a possibly completed external effect. Per-tenant record and byte reservations keep
one tenant's ambiguous history from consuming the entire shared-node ledger.

The controller is a bounded single-writer service. It uses Go's standard-library
HTTP, TLS, cryptography, JSON, and filesystem primitives plus Steward's existing
strict decoders. State changes are recovered from durable records and flushed
before success is reported. Every collection, request body, response body, lease,
identifier, and retained command has a fixed limit. Cross-tenant lookups are
reported as not found so one tenant cannot use status differences to enumerate
another tenant's resources.

Remote listeners require TLS. Plain HTTP is permitted only on a literal loopback
address for local development or a host-local reverse proxy. The service does not
inherit ambient proxy settings, follow redirects with credentials, load tenant
private keys, connect to Docker, run agent code, or execute shell commands.

The controller's public protocol remains independently implementable. Nodes do not
call a private API or import a private package, and an operator may replace
`steward-control` with another compatible controller.

**Buy vs build:** **in-house**: own the thin Steward-specific layer for tenant-bound
enrollment, exact signed-command delivery, fencing, and offline recovery. Reuse
`net/http`, `crypto/tls`, `crypto/hmac`, `crypto/rand`, atomic filesystem operations,
and Steward's existing strict JSON and DSSE code for the commodity substrate. A
Kubernetes control plane would require Kubernetes and would not cover ordinary
Docker-plus-gVisor hosts. A PostgreSQL-backed service would add a database to every
disconnected deployment before the initial single-writer workload needs one. A
message broker would add another credential, persistence, and recovery boundary for
a bounded pull queue. Revisit an external database when measured inventory size,
write rate, or high-availability requirements exceed the documented
single-controller limits. Revisit a broker only if bidirectional latency or fan-out
requirements no longer fit bounded node polling.

## Consequences

Steward gains a working self-hosted enrollment and signed-command fleet path without
acquiring a private dependency. Operators can install the controller and nodes from
the same verified release, keep all management traffic inside their network, and
continue to issue and verify commands across an air gap.

The controller is security-critical but authority-minimized. Its compromise can
expose fleet metadata, deny service, replay delivery attempts within node-enforced
fences, and submit any already valid signed command it possesses. It cannot create
a new tenant signature, weaken signed node admission, add a privileged Docker
option, or bypass Executor's durable replay checks. Host root, controller TLS keys,
the controller authentication key, tenant private keys, site policy, node host
integrity, Docker, and gVisor remain trusted according to their documented roles.

At adoption, this decision did not add a web interface, SSO or OIDC, approval
workflows, automatic placement, desired-state reconciliation, active-active
failover, model hosting, or a general workflow engine. A later decision added a
bounded observation-first operator console, and a subsequent decision allowed it
to courier one exact command signed outside the browser without adding signing or
general mutation authority; see [Embed an observation-first React operator console]({{ '/decisions/0020-embedded-react-operator-console/' | relative_url }})
and [Use the browser as a signed-command courier]({{ '/decisions/0023-native-signed-command-console-courier/' | relative_url }}).
The other capabilities remain separate.
