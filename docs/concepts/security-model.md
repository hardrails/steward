---
title: Security model and tenant isolation
description: Evaluate Steward's trust assumptions, Docker and gVisor workload controls, tenant isolation properties, fail-closed behavior, and residual host risks.
section: Explanation
---

# Security model and tenant isolation

Steward treats agent images, commands, tenant-supplied identifiers, and
control-plane workload payloads as untrusted. It trusts the Linux host and kernel,
Docker daemon, gVisor runtime, Steward binaries, systemd, operator public-key
infrastructure (PKI), and node enrollment process.

This is a shared-host isolation model, not a claim that software isolation equals
separate physical hardware.

## Isolation controls

Every admitted agent container receives one fixed policy:

| Layer | Enforced property |
| --- | --- |
| Supply chain | Offline import accepts one bounded Docker or Open Container Initiative (OCI) archive, verifies each descriptor and blob, and requires the signed manifest, config, and platform identity. Executor never pulls an image, runs the exact local config ID, and rejects image-declared volumes. |
| Signed authority (opt-in) | Executor intersects a publisher-signed workload profile, operator-signed site policy, and tenant/node/instance request. Durable policy and generation records reject rollback. A generation record is a high-water mark that prevents older authority from acting on newer state. |
| Sandbox | Docker must advertise `runsc`, the gVisor runtime. Every untrusted agent runs in its own gVisor sandbox. |
| Identity | The container runs as fixed UID/GID `65532:65532`; the caller cannot select a user. |
| Privilege and namespaces | Executor drops every Linux capability and sets `no-new-privileges`. Interprocess communication (IPC) and control-group (cgroup) namespaces are private; process ID (PID) and hostname/domain-name (UTS) namespaces use Docker's private modes. Host, peer-container, shareable namespace, and custom cgroup-parent settings are rejected. |
| Filesystem | The root filesystem is read-only. Executor adds fixed bounded temporary filesystems. Persistent state uses one fixed-path Steward-owned Docker volume, but Docker's portable local volume driver has no hard byte or inode quota. State is therefore disabled by default and must remain disabled on a shared host. The exact mount set is inspected; host mounts, extra volumes, devices, and caller-selected files are unavailable. |
| Network | The default is `network=none`. A workload with inference, service, connector, or egress authority receives one internal per-instance Docker network containing only the agent and its trusted relay. Docker allocates the subnet from its daemon-wide address pools, and its bridge host gateway is disabled. Gateway performs approved connections; the container receives no raw host or Internet route. |
| Inference | Site policy selects one route and model alias. Gateway injects the upstream credential, rejects any other model, and synthesizes `/v1/models` from the allowed alias. |
| Agent service | Gateway exposes a bearer-protected loopback endpoint. It reaches only the declared port through the grant's Unix socket and fixed relay; Docker publishes no container port. |
| Authenticated connector | The signed capsule, tenant policy, and intent select connector IDs. Node configuration maps each connector operation to one exact method, path, origin, address policy, and owner-only credential. Gateway strips agent credentials, spends a durable task claim and call budget, pins the resolved address, injects only the configured Bearer or API-key value, denies redirects, and bounds concurrency, bodies, response, and time. |
| HTTP(S) egress | Executor intersects the publisher profile, tenant route IDs, and instance request. Gateway enforces host and port, a pinned resolved IP, explicit private Classless Inter-Domain Routing (CIDR) ranges, concurrency, byte and time limits, lifecycle, and bounded audit output. |
| Resources | Per-workload memory, swap, CPU, PID, and shared-memory limits are mandatory. Docker's bounded `local` log rotation is fixed and the out-of-memory (OOM) killer remains enabled. Executor reconstructs host and tenant aggregate memory, CPU, PID, and workload reservations from Docker, including stopped containers and fixed relay overhead. Disk, inode, and I/O quotas remain outside this portable contract. |
| Lifecycle | Docker restart and automatic-removal policies are disabled. Executor, not Docker, owns lifecycle. It inspects restart, log, port, device, mount, network, namespace, and image settings after creation. |
| Integrity and recovery | A SHA-256 fingerprint covers the admitted definition. Reconciliation—comparison of durable signed state with actual runtime objects—runs before normal mutations are accepted and every 30 seconds. It may repair limited lifecycle drift, but never recreates or adopts missing or structurally changed objects. A degraded scan can only narrow authority. |
| Route integrity | Gateway persists a non-secret digest of each retained route policy and a private credential-content binding. Executor stores the route-policy digest in the admission fence and receipt. Reload, restart, start, and reconciliation refuse a mismatch while the grant remains retained. |
| Interface | Request bodies and log output are bounded, and every error has the same JSON shape. Executor mutation and both uplinks require authentication. Signed envelopes and payloads reject duplicate and unknown JSON members. The generic supervisor REST API has no built-in authentication and must stay on loopback or behind operator authentication. |
| Receipts (opt-in) | Executor writes length-framed, Ed25519-signed lifecycle records. Gateway writes a separate signed newline-delimited JSON chain for connector authorizations and terminal outcomes. Both chains are hash-linked and flushed with `fsync`; an auditor can verify a copied chain and an independently retained exact head without network access. |

The trusted per-instance relay uses `runc`, not gVisor, because it mounts one
host-owned, per-grant socket directory. It connects to Gateway's inference,
connector, and egress sockets and creates the service socket that Gateway uses to
reach the agent's declared port. It receives the same closed namespace, lifecycle, resource,
mount, port, device, and logging checks except for that fixed directory and
runtime. It has no raw Internet route or caller-selected destination.

Positive-capability networks require Docker Engine 28 or newer because Steward
depends on Docker's isolated bridge gateway mode. Preflight rejects an older Engine
before enabling inference, service, connector, or egress. A `network=none` workload does not
depend on this feature.

## Tenant isolation within the host trust model

Within this trust model, Steward's shared-host tenant isolation means:

- no shared writable host path or cross-tenant network;
- no Docker socket, host device, caller-selected kernel capability, or host
  namespace inside an agent;
- one gVisor sandbox per untrusted workload;
- tenant-bound signed authority and anti-replay state keyed by tenant and instance;
- per-workload resource ceilings and host-wide and per-tenant aggregate memory,
  CPU, PID, and workload-count ceilings;
- one private network and finite Gateway grant per positive-capability instance;
  and
- site-owned cleanup keys that, while Executor is serving, can stop, destroy, or
  purge a workload after its tenant key or policy rule has been revoked.

Cleanup keys cannot admit, start, or read a workload. Tenant and cleanup key IDs
cannot collide. A replacement site policy may remove every tenant rule while
retaining cleanup authority, allowing remote containment during an admission
lockdown. If startup reconciliation finds persistent structural drift, Executor
keeps its listener and uplink active with readiness at 503. Admission, start,
destroy, and state purge remain blocked. An authenticated stop can still deactivate
the deterministic grant and stop only an agent and relay whose retained identity
is exact.

These controls prevent a tenant from expanding its own authority through Steward.
They apply only to workloads with `state=false`. The compatibility flag
`-allow-unquotaed-state-on-dedicated-host` enables a Docker volume without enforced
byte or inode quotas and is limited to a dedicated single-tenant host; using it on a
shared host leaves storage exhaustion outside Steward's tenant-isolation boundary.

They do not remove risks shared by any multi-tenant host: vulnerabilities in the
host kernel, Docker, or gVisor; CPU-cache and other microarchitectural side
channels; disk, inode, or I/O exhaustion outside the configured limits; host
capacity consumed by trusted services; operator error; compromised host software; and
denial of service against shared hardware. Higher-assurance deployments may require
dedicated hosts or virtual machines (VMs), confidential computing, measured boot,
encrypted disks, separate network enforcement, or physical facility controls.

## Fail-closed behavior

Fail closed means refusing to start or act when a required control cannot be
verified, rather than silently weakening that control.

Executor refuses startup when `runsc` is missing, credentials have unsafe file
permissions, host policy is invalid, or, when its uplink is enabled, the uplink fence
is absent. It rejects
mutable tags, unbounded resources, ambient network requests, unsafe namespace or
restart settings, and observed drift. Packaged services remain disabled until
enrollment and preflight succeed.

With signed admission, incomplete trust inputs, a bad policy signature, policy
rollback, receipt-key replacement, or receipt corruption stop startup. An
unresolved prepared journal operation allows degraded startup but blocks normal
mutations. A requested state, inference, service, connector, or egress capability is rejected
when any part of its enforcement path is missing or cannot be inspected.

Policy rotation revokes the ability to start an instance admitted under stale
policy while preserving cleanup authorization. While Executor is serving, the bound
tenant principal or an authorized site cleanup key may stop, destroy, or purge it
while Executor is ready. Reconciliation deactivates Gateway before stopping the
agent and relay when installed policy no longer authorizes a present instance. In
degraded mode, only the narrower stop containment path remains available; destroy
and purge wait for a complete reconciliation.

## Network capability limits

Inference is restricted to fixed OpenAI-compatible endpoints. Every model-bearing
POST must contain exactly one top-level string `model` equal to the grant's alias.
A missing, duplicate, malformed, or different value is rejected before any
upstream request. Request bodies are limited to 4 MiB and responses to 32 MiB.
Known-length oversized responses fail before body forwarding. Unknown-length
responses keep streaming and advertise an `X-Steward-Stream-Status` trailer. A
clean stream ends with `completed`; a read failure or byte beyond the limit aborts
the HTTP stream so the client receives a framing or body-read error instead of a
clean truncated response.

Service traffic supports bounded HTTP and RFC 6455 WebSockets. Gateway removes
outer authorization, proxy authorization, cookies, and upstream `Set-Cookie`
headers. Each grant permits at most 16 concurrent requests or streams, lasts at
most two minutes per request or stream, allows 4 MiB from client to service, and
32 MiB from service to client. Application-level authentication inside the agent
service remains the adapter's responsibility.

Egress supports proxy-aware HTTP with Server-Sent Events (SSE) and HTTPS with
secure WebSockets (WSS). It does not support raw TCP,
UDP, ICMP, SOCKS, proxy-unaware programs, or arbitrary DNS. Gateway binds HTTPS
CONNECT to the visible TLS ClientHello server name but does not decrypt TLS, so
path and method policy apply only to HTTP that Gateway can inspect. Deactivating or
removing a grant closes active HTTP requests, CONNECT tunnels, and WebSocket
streams immediately.

## Evidence boundary

Executor receipts record admission and lifecycle decisions and effects that
Executor can observe. Gateway's separate connector chain records authorization and
terminal outcomes that Gateway can observe. Offline verification checks each
format's signatures and framing, plus sequence, hash links, node ID, key epoch, and
an optional exact externally retained head. An expected sequence and chain hash
identify one exact final head; they are not lower bounds. This detects a truncated
or advanced copy relative to that checkpoint.

Node-local receipts are not hostile-host attestation. Host root can replace the
binary, keys, and logs together. The chain does not include prompts, model output,
semantic tool actions, agent explanations, or arbitrary application logs. Protect
the receipt key and retain checkpoints outside the node when rollback detection
matters.

## Security boundary exclusions

- The control plane does not receive Docker access.
- Agent containers do not receive host paths or Docker access.
- `steward -enable-process-exec` runs trusted operator-authored local processes. It
  is not a tenant sandbox and has no resource isolation.
- Computer-use and browser automation must run in a separate sandboxed workload,
  not inside the Steward process.
- Model serving and semantic inference-data policy remain outside Steward. Steward
  enforces only the approved transport route, model alias, and credential boundary.

## Operator responsibilities

Patch the host, Docker, gVisor, and Steward. Authenticate imported artifacts,
protect enrollment and receipt keys, keep management listeners on loopback or
disabled, monitor capacity and audit output, and preserve anti-replay state during
backup and rollback.

On Amazon Web Services (AWS), use private subnets, no public management listener,
encrypted disks, Instance Metadata Service v2 (IMDSv2), and non-secret user data;
use equivalent controls on another cloud. These measures reduce exposure to hostile
networks and ordinary metadata theft. They do not exclude a malicious cloud
administrator or hypervisor. That threat requires controls such as confidential
VMs, measured boot, remote attestation, and enrollment that issues credentials only
after verifying the attestation. Steward does not currently implement that
attestation-bound enrollment.

Do not place exploit details, secrets, or sensitive environment data in a public
issue. This repository does not currently publish a private vulnerability-reporting
channel. Report non-sensitive defects through the
[GitHub issue tracker](https://github.com/hardrails/steward/issues).
