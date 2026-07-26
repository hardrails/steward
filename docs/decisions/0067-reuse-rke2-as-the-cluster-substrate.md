---
title: Reuse RKE2 as the cluster substrate
description: Why Steward pins and hardens RKE2 for management infrastructure without making Kubernetes the agent-authority boundary.
section: Architecture decision
---

# Reuse RKE2 as the cluster substrate

- Status: Accepted
- Date: 2026-07-25
- Rung: open-source

## Context

Steward needs a repeatable way to form a multi-node management cluster from
ordinary systemd Linux servers. Building consensus, service discovery, rolling
placement, health recovery, and container networking in this repository would
duplicate mature infrastructure and create a large unaudited failure surface.

The cluster must work on `amd64` and `arm64`, install from authenticated local
artifacts, survive loss of one server in a three-server topology, and remain
replaceable. It must not turn the cluster administrator into a tenant signing
authority or create a second, weaker path around Executor admission.

The strongest control-compromise claim also requires two control planes to be
distinguished:

- Steward Control carries desired state and signed commands. Executor can reject
  it because tenant authority remains outside Control.
- The RKE2 control plane administers Kubernetes. A Kubernetes administrator can
  normally schedule privileged code on its worker nodes and is therefore inside
  the trusted computing base for workloads placed directly on those nodes.

Calling both simply "the control plane" would hide a material security
difference.

## Decision

Reuse a narrowly pinned RKE2 release as Steward's optional management-cluster
substrate. Steward owns the deterministic configuration, artifact lock,
installation checks, join workflow, namespace baseline, gVisor runtime
registration, and qualification evidence. RKE2 owns Kubernetes, etcd, networking,
and node membership.

The shipped cluster installer:

- accepts only the exact release bundle and image archive recorded in the
  dependency-free Steward binary;
- verifies size, SHA-256, archive inventory, file types, and reported version
  before installation;
- enables the RKE2 CIS profile, secrets encryption, Canal networking, and
  scheduled etcd snapshots;
- disables bundled ingress controllers;
- creates restricted namespaces, disables default service-account token mounts,
  and installs default-deny network policy and the `runsc` RuntimeClass;
- supports connected and fail-closed air-gapped installation;
- issues secure, expiring bootstrap credentials for cluster worker joins; and
- refuses unmanaged Kubernetes state and reviewed-configuration drift.

Existing Steward agent workloads continue through the Docker and gVisor Executor.
The Kubernetes namespaces and RuntimeClass are a hardened substrate baseline, not
a declaration that the Kubernetes workload backend is supported. A future backend
must pass the same admission, isolation, egress, secret, replay, recovery, and
evidence conformance gates before it can run agents.

RKE2 may host replaceable management services. It must not receive tenant private
keys. In strict-sovereign mode, compromising RKE2 and Steward Control can disrupt
or misreport operations but cannot create tenant-signed workload authority. In
bounded-autonomous mode, the attacker can exercise only authority still present
in the controller's signed delegation. Placing agents directly under Kubernetes
would make the RKE2 administrator part of their runtime trust boundary and is
therefore deferred.

**Decision: use open-source RKE2 behind a Steward-owned, pinned integration.
Tradeoff: Steward gains mature clustering and offline installation while accepting
RKE2, containerd, etcd, and the cluster host as trusted management infrastructure.
Rejected: an in-house orchestrator because consensus and Kubernetes-compatible
operations are not Steward's moat. Rejected: treating RKE2 as an immediate agent
backend because that would weaken the existing Control-compromise boundary before
conformance exists. Revisit the workload boundary only with hostile-control-plane
tests and an architecture in which Kubernetes cannot bypass node-local Steward
authority.**

## Alternatives

- **K3s:** smaller and convenient, but RKE2 has the stronger hardened-distribution
  focus and CIS operating path needed for the intended sites.
- **k0s:** credible and portable, but adopting it would add a second qualification
  target without a demonstrated requirement.
- **Talos Linux:** a strong future node-appliance model with immutable,
  API-managed hosts. It is an operating system rather than a drop-in cluster
  dependency, so Steward can borrow its no-SSH, declarative, replace-not-repair
  approach without requiring it on existing Linux servers.
- **Nomad:** a mature scheduler with a smaller conceptual surface, but it would
  not provide the Kubernetes ecosystem expected for management services and
  would still require a separate policy for agent authority.
- **Managed cloud Kubernetes:** useful deployment targets later, but not a
  sovereign or air-gapped default and not portable across bare metal.

## Consequences

RKE2 is a reviewed third-party trusted component even though the Steward Go
module remains dependency-free. Its license, source, release metadata, artifact
digests, operating guidance, and security notices require ongoing review. A
scheduled workflow may propose pin changes, but CI never auto-merges them.

Server join credentials are full cluster-administrator secrets and also protect
RKE2 bootstrap data. They must be backed up with etcd state. Worker joins use
short-lived bootstrap credentials instead.

Compromised or ambiguously removed cluster nodes are rebuilt from a known-good
image. An upstream uninstall script is not treated as proof that old processes,
mounts, network state, or credentials are gone.

The cluster interface remains optional. A single Steward Executor and an
externally managed fleet remain supported without RKE2.

## Evidence

The integration was exercised on disposable AWS VMs on 2026-07-26:

- connected Ubuntu `amd64` server and worker joins;
- a three-server etcd cluster that accepted a write with the first server
  stopped, then recovered all three members;
- connected Amazon Linux 2023 `amd64`;
- connected Ubuntu `arm64` with a real gVisor pod;
- a fresh network-closed Ubuntu `amd64` air-gap install and reboot; and
- restricted namespace, service-account, default-deny, CIS, secret-encryption,
  credential-permission, and `runsc` assertions.

Every temporary VM, key pair, security group, and local transfer credential was
removed after qualification.

Primary upstream references:

- [RKE2 requirements](https://docs.rke2.io/install/requirements)
- [RKE2 token management](https://docs.rke2.io/security/token)
- [RKE2 CIS hardening guide](https://docs.rke2.io/security/hardening_guide)
- [RKE2 air-gap installation](https://docs.rke2.io/install/airgap)
- [gVisor containerd configuration](https://gvisor.dev/docs/user_guide/containerd/quick_start/)
