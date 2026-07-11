---
title: Steward v1.2 boundaries
description: Exact Steward v1.2 guarantees, signed-admission capabilities, residual risks, and deliberately unavailable runtime grants.
section: Release boundary
---

# Steward v1.2 boundaries

v1.2 adds the sovereign authorization core: strict DSSE/Ed25519 profile capsules,
site-root-signed policy, tenant/node/instance intent, policy and generation fences,
a fsynced host-mutation journal, signed hash-linked receipts, and offline
`stewardctl` verification. It retains the fixed Docker+gVisor workload boundary.

## What a receipt means

A valid receipt chain shows that the configured node key signed the supplied
sequence of bounded Steward enforcement records with no internal gap, reorder,
altered frame, or partial trailing frame.
Records bind capsule digest, policy digest, tenant, runtime reference, generation,
decision type, and outcome.

It does not prove prompt meaning, model output, agent intent, semantic tool calls,
or upstream behavior. A self-contained chain also cannot prove that a complete
signed suffix was removed; retain the last verified sequence independently when
that matters. Without a TPM/TEE or external anchor, a hostile host root can replace
the key, log, and software together. Receipts are tamper-evident inside the
documented node trust boundary, not globally non-repudiable.

In v1.2 the receipt key is loaded by the Docker-authorized Executor process; there
is no separate signer service or Unix identity. Compromise of Executor can therefore
forge node-local receipts. Separating Docker authority from receipt-signing authority
is future hardening, not a property claimed by this release.

## Signed admission is opt-in

Existing host-control `/v1/workloads` admission remains available only when signed
admission is not configured. Enabling signed admission disables unsigned
provisioning, including legacy outbound `provision` commands. The `/v1/admissions`
endpoint is enabled only when Executor receives a complete
signed policy, site-root public key, node identity, durable fence/journal paths,
and evidence private key. Partial configuration fails startup. A fence must be
initialized explicitly once; a missing fence is never recreated during startup.

The packaged service remains outbound-only. An independent control plane can send
the `admit` command through the authenticated Executor uplink, or an operator can
enable the loopback API plus the explicit host-admin-intent flag. The local bearer
token is a host-administrator credential, not tenant end-user authentication.

## Not available in v1.2

- Outbound network or hostname allowlists
- Persistent tenant volumes or state resume
- Inference credential brokering
- Published container ports or service ingress
- Secret, arbitrary environment-variable, or file injection
- Per-workload UID/GID selection
- GPU or other device assignment
- Writable image root filesystems
- Interactive terminal/exec sessions
- Image pulling or registry authentication
- Automatic OCI-layout import and manifest-to-local-image mapping
- Automatic recovery of an ambiguous prepared journal operation
- Container checkpoint/restore, Kubernetes, or multi-host placement

The signed capsule format contains `state`, `inference`, and `service` ceilings so
future releases can preserve authorization compatibility. v1.2 returns HTTP 501
when an intent requests any of them. It does not pretend a signed boolean is an
implemented isolation control.

## Runtime roadmap

The next capability work must preserve deny-by-default operation:

1. tenant-and-lineage-scoped state volumes with explicit new/resume/purge intent;
2. a credential-hiding local inference gateway and per-instance relay with no
   generic proxy or direct egress;
3. authenticated local service ingress through the same paired relay, never a raw
   Docker host-port binding; and
4. verified OCI-layout import that binds manifest, platform, config digest, local
   Docker image identity, profile adapter, and receipt.

Each capability ships only with crash recovery, drift inspection, cross-tenant
tests, and real Docker+gVisor acceptance. Host mounts, Docker socket exposure,
`CONNECT`, wildcard destinations, and caller-selected container privileges are not
acceptable shortcuts.

## Trusted substrate

Host root, the Linux kernel, Docker, gVisor, the node's signing-key protection, and
operator configuration are trusted. Steward does not provide bare-metal bootstrap,
disk encryption, hardware attestation, vulnerability management, model inference,
or formal air-gap accreditation.
