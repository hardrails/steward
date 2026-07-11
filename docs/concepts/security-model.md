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

Every Executor v1.2 workload is forced into one fixed policy:

| Layer | Enforced property |
| --- | --- |
| Supply chain | Image must be a repository reference pinned by SHA-256 digest; Executor never pulls it. |
| Signed authority (opt-in) | Publisher capsule is intersected with site-root policy and tenant/node/instance intent; policy and generation rollback are fenced. |
| Sandbox | Docker must advertise `runsc`; every workload uses gVisor. |
| Identity | Container runs as fixed UID/GID `65532`; no caller-selected user. |
| Privilege | All Linux capabilities dropped and `no-new-privileges` set. |
| Filesystem | Read-only root; bounded tmpfs at `/workspace` and `/tmp`; no host mounts or devices. |
| Network | Docker network mode `none`; non-empty egress requests are rejected. |
| Resources | Mandatory memory, CPU, and PID limits plus host-wide and per-tenant workload caps. |
| Integrity | Complete admitted definition is fingerprinted; observed setting drift returns a conflict. |
| Interface | Bounded bodies, bounded log output, uniform errors, authenticated mutation; signed envelopes/payloads also reject duplicate and unknown JSON members. |
| Receipts (opt-in) | Fsynced, length-framed, Ed25519-signed hash chain binds admission and mutation decisions for offline verification. |

These controls isolate tenants through separate sandboxed containers and prevent one
tenant from raising its own resource ceiling. They do not turn one Linux host into
physically separate hardware.

## What “full tenant isolation” means here

Within Steward's current scope, tenant isolation means no shared writable host path,
no shared network namespace, no Docker socket, no caller-selected device or kernel
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
unreconciled prepared journal operation also fails closed. v1.2 refuses signed
state, inference, or service capability requests until those enforcement paths
exist.

Node-local receipts are not hostile-host attestation. Host root can replace keys,
logs, and software together; prompts, model output, semantic tool actions, and
agent explanations are not part of the receipt contract.

## Security boundary exclusions

- The control plane is not trusted with Docker access.
- Agent containers are not trusted with host paths or Docker access.
- `steward -enable-process-exec` is for trusted operator-authored local processes;
  it is not a tenant sandbox.
- Computer-use or browser automation must run as a separate sandboxed workload, not
  in the Steward process.
- Inference and its data controls are outside Steward.

## Operator responsibilities

Patch the host, Docker, gVisor, and Steward; authenticate imported artifacts; protect
enrollment keys; keep management listeners on loopback or disabled; monitor capacity
and audit output; and preserve anti-replay state during backup and rollback.

Do not place exploit details or sensitive environment data in a public issue.
Use the repository owner's private security-contact channel for vulnerability reports.
