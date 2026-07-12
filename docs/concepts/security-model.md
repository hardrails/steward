---
title: Security model and tenant isolation
description: Evaluate Steward's trust assumptions, Docker and gVisor workload controls, tenant isolation properties, fail-closed behavior, and residual host risks.
section: Explanation
---

# Security model and tenant isolation

Steward treats the agent image, command, tenant-supplied identifiers, and control-plane
workload payload as untrusted. The Linux host, kernel, Docker daemon, gVisor runtime,
Steward binaries, systemd, operator PKI, and node enrollment process remain trusted.

## Isolation controls

Every Executor v1.4 workload is forced into one fixed policy:

| Layer | Enforced property |
| --- | --- |
| Supply chain | Image must be a repository reference pinned by SHA-256 digest; Executor never pulls it. |
| Signed authority (opt-in) | Publisher capsule is intersected with site-root policy and tenant/node/instance intent; policy and generation rollback are fenced. |
| Sandbox | Docker must advertise `runsc`; every workload uses gVisor. |
| Identity | Container runs as fixed UID/GID `65532`; no caller-selected user. |
| Privilege | All Linux capabilities dropped and `no-new-privileges` set. |
| Filesystem | Read-only root; bounded tmpfs, or one Executor-derived `/state` volume; no host mounts or devices. |
| Network | `none` by default; positive grants get one internal per-instance network containing only the agent and trusted relay. Signed egress uses a host Gateway proxy, never raw container routing. |
| Inference/service | Gateway selects exact operator route and injects credentials; relay has fixed destinations; service is loopback-only and bearer protected. |
| HTTP(S) egress | Capsule ceiling + tenant route IDs + intent are intersected; Gateway enforces host/port, pinned resolved IP, explicit private CIDRs, concurrency, bytes, time, lifecycle, and bounded audit. |
| Resources | Mandatory memory, CPU, and PID limits plus host-wide and per-tenant workload caps. |
| Integrity | Complete admitted definition is fingerprinted; observed setting drift returns a conflict. |
| Interface | Bounded bodies, bounded log output, uniform errors, authenticated mutation; signed envelopes/payloads also reject duplicate and unknown JSON members. |
| Receipts (opt-in) | Fsynced, length-framed, Ed25519-signed hash chain binds admission and mutation decisions for offline verification. |

These controls isolate tenants through separate sandboxed containers and prevent one
tenant from raising its own resource ceiling. They do not turn one Linux host into
physically separate hardware.

## What “full tenant isolation” means here

Within Steward's current scope, tenant isolation means no shared writable host path,
no cross-tenant network, no Docker socket, no caller-selected device or kernel
capability, a separate gVisor sandbox for every workload, and per-tenant admission
limits. Control-plane identity binds a workload to its tenant before execution.

Residual shared-host risks remain: host kernel or gVisor vulnerabilities, CPU cache
and other microarchitectural side channels, storage or memory exhaustion outside
configured limits, operator misconfiguration, compromised Docker/host software, and
denial of service against shared hardware. High-assurance threat models may require
dedicated hosts, VMs, measured boot, encrypted disks, network enforcement, or
facility controls in addition to Steward.

## Fail-closed behavior

Executor refuses startup if `runsc` is absent, credentials are unsafe, host policy
is invalid, or the uplink fence is missing. It rejects tags, unbounded resources,
network requests, and drift instead of silently weakening policy. Packages remain
disabled until enrollment and preflight succeed.

When signed admission is configured, incomplete trust inputs, a bad policy
signature, policy rollback, receipt-key replacement, receipt corruption, or an
unreconciled prepared journal operation also fails closed. v1.4 refuses signed
state, inference, service, or egress capability requests when their complete enforcement
paths are not configured or cannot be verified.

Node-local receipts are not hostile-host attestation. Host root can replace keys,
logs, and software together; prompts, model output, semantic tool actions, and
agent explanations are not part of the receipt contract.

Egress does not make the agent a network peer. Proxy-aware HTTP/SSE and HTTPS/WSS
work; raw TCP, UDP, ICMP, SOCKS, and proxy-unaware programs do not. HTTPS CONNECT is
bound to the visible TLS ClientHello server name but is not decrypted, so path/method
policy applies only where the Gateway sees HTTP. Grant deactivation closes in-flight
HTTP requests and CONNECT streams instead of waiting for their route lifetime.

## Security boundary exclusions

- The control plane is not trusted with Docker access.
- Agent containers are not trusted with host paths or Docker access.
- `steward -enable-process-exec` is for trusted operator-authored local processes;
  it is not a tenant sandbox.
- Computer-use or browser automation must run as a separate sandboxed workload, not
  in the Steward process.
- Model serving and semantic inference-data controls remain outside Steward;
  Steward brokers only the approved transport route and credential boundary.

## Operator responsibilities

Patch the host, Docker, gVisor, and Steward; authenticate imported artifacts; protect
enrollment keys; keep management listeners on loopback or disabled; monitor capacity
and audit output; and preserve anti-replay state during backup and rollback.

On public cloud, require private subnets, no public management listener, encrypted
disks, IMDSv2 or the provider equivalent, and secret-free user data. These controls
protect against hostile networks and ordinary metadata theft. They do not exclude a
malicious cloud administrator or hypervisor; that requires confidential VMs,
measured boot, remote attestation, and attestation-bound enrollment.

Do not place exploit details or sensitive environment data in a public issue.
Use the repository owner's private security-contact channel for vulnerability reports.
