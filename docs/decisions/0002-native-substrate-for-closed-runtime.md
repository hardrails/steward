---
title: Use Docker and systemd for the fixed runtime boundary
description: Why Steward reuses Docker and systemd controls while owning its signed authorization, reconciliation, and evidence contract.
section: Architecture decision
---

# Use Docker and systemd for the fixed runtime boundary

## Status

Accepted.

## Context

Steward must ensure that signed admission matches the running Docker objects. This
requires exact offline-image identity, internal networks that cannot reach host
services, bounded logs and swap, and restart recovery limited to grants still
authorized by durable signed state.

These controls mix two kinds of work:

- established host mechanisms: image loading, network isolation, log rotation,
  process ordering, and package activation;
- Steward-specific controls: tenant-scoped authority, anti-replay fences,
  enforcement inspection, deterministic desired state, and portable receipts.

Reimplementing established host mechanisms would add privileged code and
dependencies. Delegating Steward-specific controls would weaken the local,
offline authorization-to-enforcement boundary.

## Decision

Steward reuses platform mechanisms when they meet the requirement. It implements
controls that belong to Steward's trust contract:

| Requirement | Decision |
| --- | --- |
| Load an approved offline image | Use Docker Engine's ImageLoad API, then inspect the result. |
| Prevent host-gateway reachability | Require and inspect isolated gateway mode on an internal Docker bridge. Never fall back silently. |
| Allocate per-instance network addresses | Let Docker select a non-conflicting subnet from the daemon's address pools. An isolated network normally has no Docker-reported gateway. If Docker reports one, accept it only when it is a private host address inside the subnet, not the network or broadcast address; Steward then excludes it from the relay and agent addresses. Bind the observed subnet, optional gateway, relay IP, and agent IP into the workload fingerprint and fence. Do not derive addresses from tenant text or maintain a second IP address management (IPAM) database. |
| Bound container logs and swap | Configure Docker's `local` log driver and Linux control-group (cgroup) memory/swap fields, then inspect for drift—differences from the required settings. |
| Reserve aggregate host and tenant resources | Reconstruct memory, CPU, PID, and workload reservations from labels on every managed Docker container, including stopped containers, and add fixed relay overhead. Keep Docker as the restart-persistent inventory instead of trusting process-local counters. |
| Bound persistent state | Keep Docker local-volume state disabled on shared hosts because it has no portable hard byte or inode quota. Do not emulate a kernel or filesystem quota with userspace accounting. |
| Start services in dependency order | Use systemd relationships and readiness checks, not a resident updater or init system. |
| Verify archive integrity | Parse one bounded Open Container Initiative (OCI)/Docker archive in-process with Go's tar, gzip, SHA-256, and strict JSON libraries. Never extract it. |
| Authorize a tenant command | Keep site-root policy, tenant command keys, DSSE (Dead Simple Signing Envelope) statements, complete identity, expiry, and anti-replay fences in Steward. |
| Recover a runtime | Reconstruct a Relay or Gateway grant only from its signed fence and exact hardened Docker state. |
| Sign and verify enforcement evidence | Keep fixed receipt types and offline verification in Steward. External transparency, hardware security modules (HSMs), Sigstore, in-toto, Supply Chain Integrity, Transparency and Trust (SCITT), and attestation (signed proof of system state) require exact, tested profiles. |

The zero-dependency and offline-build requirements rule out a general OCI software
development kit (SDK). The verifier accepts one size-bounded, single-platform image
and checks exact descriptor sizes and SHA-256 digests. It does not extract, contact
a registry, use non-standard decompression, verify general signatures, or build
images.

## Consequences

- Nodes with optional capabilities require Docker isolated internal gateway mode.
  Older engines fail preflight; Steward does not install a more privileged firewall
  workaround.
- Docker address-pool configuration limits how many capability networks the host
  can create. Steward detects allocation and identity drift but does not replace
  Docker's collision handling.
- An absent Docker gateway is the normal result for an isolated bridge and does not
  weaken host-gateway isolation. If Docker reports a gateway, Steward validates and
  records it as network metadata; it does not enable a host route.
- Aggregate reservations are admission ceilings, not usage meters. They exclude
  trusted host services, disk, inodes, and I/O bandwidth, so operators must retain
  explicit headroom.
- Docker remains trusted. Inspecting the state it reports can detect drift and
  misconfiguration, but cannot prove that a hostile Docker daemon is truthful.
- The image importer can work fully offline and creates no third-party Go module.
- Sigstore/cosign, Supply-chain Levels for Software Artifacts (SLSA)/in-toto,
  vulnerability scanners, software bills of materials (SBOMs), key management
  systems (KMSs), hardware security modules (HSMs), Trusted Platform Modules (TPMs),
  confidential VMs, and Supply Chain Integrity, Transparency and Trust (SCITT)
  services can add evidence without becoming mandatory dependencies.
- A future backend may replace Docker, but it must reproduce the same signed input,
  exact observed enforcement, reconciliation, and receipt semantics rather than
  weakening the contract to a generic sandbox call.

## Rejected alternatives

### Build a host firewall manager

Rejected while Docker provides inspectable isolated-gateway mode. An
nftables/iptables reconciler would require more privilege, distribution-specific
coordination, crash cleanup, and ownership rules without a stronger guarantee.

### Build a custom network allocator or portable volume quota

Rejected. Docker already coordinates network allocations across its daemon, while
a second allocator would require crash recovery and collision reconciliation.
Portable Docker local volumes expose no enforceable byte-and-inode contract, so
userspace accounting would report consumption without preventing writes after a
crash or compromise. A future state backend must expose quotas that Steward can
configure, inspect, and test.

### Import an OCI, policy, or web framework SDK

Rejected. The repository must build with only the Go standard library, and Steward
accepts much smaller data shapes than general OCI, policy, and web libraries.

### Shell out to Docker, cosign, or an archive utility from the daemon

Rejected. Steward uses the Docker API and parses size-bounded media. Operators may
verify provenance externally before import; untrusted requests cannot select a
command or arbitrary host path.

### Build a Terraform provider or updater daemon in this repository

Rejected. Terraform fits host bootstrap, and a separate provider can use public
contracts. Packaged scripts and systemd activate releases as an operator action.
Neither component belongs inside the zero-dependency node authority.
