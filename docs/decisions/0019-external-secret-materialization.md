---
title: Keep secret storage outside Steward and validate materialization into Gateway
description: Why OpenBao Agent or another trusted materializer supplies owner-only Gateway files instead of Steward becoming a vault.
section: Architecture decision
---

# Keep secret storage outside Steward and validate materialization into Gateway

- Status: Accepted
- Date: 2026-07-16
- Rung: external open-source service behind an existing filesystem contract

## Context

Inference routes and authenticated connectors need API keys, tokens, and similar
credentials. Giving those values to an agent container would turn prompt injection,
a malicious skill, or an image compromise into credential theft. Steward Gateway
already solves the use-time boundary: it reads a bounded owner-only file, retains
the credential outside the workload, and adds it only to an admitted upstream
request.

The missing function is lifecycle management: encrypted storage, distribution to
nodes, rotation, revocation, recovery, and audit. Those are mature secret-manager
responsibilities, not Steward's differentiating authorization boundary. Building a
partial vault would add cryptographic key custody, bootstrap authentication,
leases, high availability, backup, unsealing, and disaster recovery to Steward's
trusted code.

The solution must work on one disconnected Linux host or across an air-gapped
fleet, preserve tenant isolation from untrusted workloads, and add no build-time or
runtime dependency to a default Steward installation.

## Decision

**Decision:** use Steward's owner-only Gateway credential files as a
provider-neutral handoff, with OpenBao Agent as the recommended optional
materializer.

**Why:** OpenBao supplies mature storage, ACL, lease, rotation, and audit behavior,
while Gateway keeps the smaller enforcement boundary that agents actually need.
The two products remain independently deployable and Steward still works with
manually installed files, Vault Agent, or another materializer.

**Rejected:** embedding an OpenBao/Vault provider in Gateway or implementing a
native general-purpose vault now, because both add provider credentials and
unfinished key-management and recovery semantics to Steward's trusted computing
base.

**Revisit if:** operators need secret delivery across intermittently connected
nodes without any separately operated secret manager, and a reviewed per-node
envelope protocol can define key recovery, rotation, anti-rollback, quotas, and
offline audit before code is shipped.

Steward adds a bounded, provider-neutral materialization check. A strict non-secret
preflight manifest maps each `(tenant_id, secret_id)` to the deterministic path
`<root>/<tenant_id>/<secret_id>`. The check requires caller-owned mode-`0700` root
and tenant directories; stable, caller-owned, single-link mode-`0600` regular
files; bounded visible-ASCII values; and no path, inode, or filesystem aliasing. Its
JSON report contains identity and purpose only. It does not return, hash, measure,
authorize, or durably bind secret values. This is point-in-time readiness preflight;
Gateway independently performs the authoritative stable file load.

Agents never receive this directory, the materializer identity, an OpenBao token,
or the rendered values. One trusted Gateway process necessarily holds the values
for the routes it mediates. On a shared host, this preserves isolation between
untrusted tenant workloads but does not claim isolation from compromised host root,
Gateway, or the materializer.

## Options considered

| Option | Security and functional fit | Operational ownership | Reversibility | Decision |
|---|---|---|---|---|
| Manual owner-only files | Uses the existing Gateway boundary with no new service, but leaves distribution, rotation, revocation, central audit, and recovery as manual procedures. | Every node credential lifecycle belongs to the operator. | High. | Supported baseline, insufficient for fleets |
| Owner-only files rendered by OpenBao Agent | Reuses Gateway's hardened read and mediation boundary. OpenBao can store versioned KV secrets, apply exact ACLs, renew leases, re-render values, and audit requests. On each Steward node, plaintext exists only in the trusted materializer and Gateway processes and the protected destination; OpenBao is a separate trusted service and transport boundary. | Operators run and recover OpenBao. Steward owns only a strict filesystem handoff. | High: manual files, Vault Agent, and other materializers use the same interface. | Selected |
| Native OpenBao/Vault HTTP provider in Steward | Could avoid a plaintext destination file, but moves provider authentication, TLS, retries, token renewal, lease expiry, failover, and API compatibility into Gateway. A provider token compromise can exceed one routed secret unless every policy is exact. | Steward would own a second secret-manager client and every supported auth method. | Medium: provider-specific configuration becomes a public Steward contract. | Deferred |
| Native per-node sealed envelopes | Can keep the control plane ciphertext-only and support disconnected delivery. It still requires recipient-key enrollment, authenticated metadata, anti-rollback, recovery, rewrapping, revocation, secure deletion, backup, and external review. Node plaintext remains necessary at use time. | Steward becomes responsible for a new cryptographic and recovery protocol. | Low: ciphertext and key-lifecycle formats are long-lived one-way doors. | Future only after a separate threat model and review |

OpenBao is the preferred documented implementation because it is an independent,
[MPL-2.0 open-source secrets manager](https://github.com/openbao/openbao). Its
[KV version 2 engine](https://openbao.org/docs/2.3.x/secrets/kv/kv-v2/) supports
versioned storage and separate ACL paths, and
[Agent templates](https://openbao.org/docs/agent-and-proxy/agent/template/) support
automatic renewal or retrieval and file rendering. OpenBao is not downloaded,
linked, called, or required by Steward.

## Phased implementation

1. **Validated materialization:** keep credentials in Gateway-only files; document
   a hardened OpenBao Agent template; validate deterministic tenant paths and file
   metadata with `stewardctl secret materialization check`; then run Gateway's
   complete configuration validation.
2. **Automated lifecycle:** package an opt-in materializer unit and installer
   profile, add secret-free readiness/rotation status to the operator surface, and
   coordinate drain, provider rotation, connector epoch increment where applicable,
   validation, and Gateway reload. Keep secret values and provider tokens out of
   Steward APIs and evidence.
3. **Provider-neutral references:** allow signed policy and node configuration to
   name non-secret references and expected epochs while a local trusted
   materializer resolves them. Specify failure and stale-value behavior before
   enabling automatic rollout.
4. **Disconnected envelopes, if justified:** define a client-side encrypted,
   per-node envelope with tenant, node, purpose, secret identity, and monotonic
   epoch as authenticated data. Require published test vectors, independent
   cryptographic review, bounded ciphertext storage, key backup/recovery, hardware
   key support, and rollback evidence before production use.

## Consequences

The first phase gives operators real secret storage and distribution by composing
with a mature service, but Steward does not install or operate that service. A node
must initially materialize every required value before Gateway becomes ready.
OpenBao unavailability after that point leaves the last rendered value on disk;
operators must choose persistent storage for disconnected availability or tmpfs
for less plaintext persistence and boot-time fail-closed behavior.

Rotation remains an authority change, not a background file edit. Drain affected
grants, update the provider value, wait for materialization, increment the connector
credential epoch where applicable, validate, and reload Gateway.
Gateway's retained grant bindings reject a silent credential change beneath an
active workload.

Provider storage does not make host compromise safe. Use encrypted disks, verified
TLS, exact node/tenant read policies, OpenBao audit devices, protected bootstrap
authentication, tested backups, and a documented unseal and recovery process.
