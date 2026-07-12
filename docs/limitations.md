---
title: Steward v1.3 boundaries
description: Exact Steward v1.3 guarantees, positive capability controls, residual risks, and deliberately unavailable authority.
section: Release boundary
---

# Steward v1.3 boundaries

v1.3 combines the sovereign authorization core—strict DSSE/Ed25519 profile capsules,
site-root-signed policy, tenant/node/instance intent, policy and generation fences,
a fsynced host-mutation journal, signed hash-linked receipts, and offline
verification—with useful state, inference, service, direct CLI, and MCP operations.

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

In v1.3 the receipt key is loaded by the Docker-authorized Executor process; there
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

The packaged Executor also exposes a bearer-protected loopback API for
`stewardctl node` and `steward-mcp`. An independent control plane can send
the `admit` command through the authenticated Executor uplink, or an operator can
enable the loopback API plus the explicit host-admin-intent flag. The local bearer
token is a host-administrator credential, not tenant end-user authentication.

## Not available in v1.3

- Outbound network or hostname allowlists
- Arbitrary outbound network or arbitrary inference destinations
- Arbitrary state paths, host bind mounts, or automatic state deletion
- Raw published agent ports, public ingress, or tenant end-user authentication
- Secret, arbitrary environment-variable, or file injection
- Per-workload UID/GID selection
- GPU or other device assignment
- Writable image root filesystems
- Interactive terminal/exec sessions
- Image pulling or registry authentication
- Automatic OCI-layout import and manifest-to-local-image mapping
- Automatic recovery of an ambiguous prepared journal operation
- Container checkpoint/restore, Kubernetes, or multi-host placement

The signed capsule format contains `state`, `inference`, and `service` ceilings.
v1.3 enforces them only when the complete Docker volume or gateway/relay topology
is configured. Otherwise it returns HTTP 501; a signed boolean is never treated
as an implemented isolation control.

## Runtime hardening still ahead

The next capability work must preserve deny-by-default operation:

1. encrypted or externally managed state backends without caller-selected host paths;
2. stronger receipt-key isolation and optional external evidence anchoring;
3. finer authenticated service principals beyond the host-wide local token; and
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
