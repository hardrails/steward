---
title: Security model and tenant isolation
description: Evaluate Steward's trust assumptions, proof-carrying activation, Docker and gVisor workload controls, tenant isolation, fail-closed behavior, and residual host risks.
section: Explanation
---

# Security model and tenant isolation

Steward treats agent images, commands, tenant-supplied identifiers, and
control-plane workload payloads as untrusted. It trusts the Linux host and kernel,
Docker daemon, gVisor runtime, Steward binaries, systemd, operator public-key
infrastructure (PKI), and node enrollment process.

This is a shared-host isolation model, not a claim that software isolation equals
separate physical hardware.

Steward Control is security-critical but does not sit inside the node's Docker
trust boundary. Its separate unprivileged service account has no Docker socket,
shell runner, agent runtime, or tenant and site private signing keys. A compromised
controller can expose fleet metadata, create or revoke credentials within the
compromised operator's scope, deny service, and repeatedly offer valid signed
commands it already has. It cannot mint the tenant signature that Executor requires
or add container authority outside the signed command schema. Operators still
trust the controller host, TLS key, authentication key, evidence-witness private
key, and durable state for fleet confidentiality, availability, correct credential
enforcement, and authentic controller witness exports.

A sandbox reduces the ways untrusted code can attack the host. It does not prove
that a tenant authorized a particular task or stop a manipulated agent from changing
request content inside a reusable service grant. Tenant-signed service tasks address
that separate authorization problem; they do not strengthen the gVisor boundary.

Steward treats stored and indirect prompt injection as a full agent compromise.
Hostile instructions can arrive in calendar invitations, email, web pages,
documents, tool results, or retained memory and can drive legitimate tools toward
account mutation or secret exfiltration. Detection and model self-review are useful
additional signals, not enforcement authority. Authorized Effects places a
deterministic check outside the workload for managed connector calls.

## Isolation controls

Every admitted agent container receives one fixed policy:

| Layer | Enforced property |
| --- | --- |
| Supply chain | Offline import accepts one bounded Docker or Open Container Initiative (OCI) archive, verifies each descriptor and blob, and requires the signed manifest, config, and platform identity. Executor never pulls an image, runs the exact local config ID, and rejects image-declared volumes. |
| Signed authority (opt-in) | Executor intersects a publisher-signed workload profile, operator-signed site policy, and tenant/node/instance request. Durable policy and generation records reject rollback. A generation record is a high-water mark that prevents older authority from acting on newer state. |
| Proof-carrying activation | A publisher-signed agent release binds outcome text, the embedded capsule, exact archive, fixed Hermes canary, qualification-evidence digest, and limitations without granting runtime authority. A fixed node-local state machine derives its canary challenge from real admission, keeps the default task key off-node, retains generated artifacts and sequential checkpoints in an owner-only append-only workspace, and correlates the deterministic result with signed receipt and controller-witness evidence. The current recipe requires a dedicated host with exactly one policy tenant, host-administrator local admission, and explicitly enabled unquotaed persistent state. The plan, challenge, state, and proof are not signatures or hostile-host attestation. |
| Proof-carrying fleet rollout | An operator-side coordinator fixes one release, tenant, explicit target order, first-node canary, and later batch boundaries. One common policy-authorized command key signs the exact plan, each evidence-bound promotion into a later batch, and commands that bind the applicable authorization-envelope digest. Deterministic command IDs prevent aliases across target positions. The final aggregate digest commits the exact plan authorization, ordered promotions, and each target's raw signed admit, start, and canary command envelopes. The plan file, checkpoints, status, and aggregate proof remain unsigned correlation records; their signed authorization and evidence companions provide authenticity. The coordinator keeps command and task private keys outside Steward Control, requires every target proof before promotion, and does not import images remotely, choose nodes, retry ambiguous effects, or roll back workloads. |
| Sandbox | Docker must advertise `runsc`, the gVisor runtime. Every untrusted agent runs in its own gVisor sandbox. |
| Identity | The container runs as fixed UID/GID `65532:65532`; the caller cannot select a user. |
| Privilege and namespaces | Executor drops every Linux capability and sets `no-new-privileges`. Interprocess communication (IPC) and control-group (cgroup) namespaces are private; process ID (PID) and hostname/domain-name (UTS) namespaces use Docker's private modes. Host, peer-container, shareable namespace, and custom cgroup-parent settings are rejected. |
| Filesystem | The root filesystem is read-only. Executor adds fixed bounded temporary filesystems. Persistent state uses one fixed-path Steward-owned Docker volume, but Docker's portable local volume driver has no hard byte or inode quota. State is therefore disabled by default and must remain disabled on a shared host. The exact mount set is inspected; host mounts, extra volumes, devices, and caller-selected files are unavailable. |
| Network | The default is `network=none`. A workload with inference, service, connector, or egress authority receives one internal per-instance Docker network containing only the agent and its trusted relay. Docker allocates the subnet from its daemon-wide address pools, and its bridge host gateway is disabled. Gateway performs approved connections; the container receives no raw host or Internet route. |
| Inference | Site policy selects one route and model alias. Gateway injects the upstream credential, rejects any other model, and synthesizes `/v1/models` from the allowed alias. |
| Agent service | Gateway exposes a bearer-protected loopback endpoint. It reaches only the declared port through the grant's Unix socket and fixed relay; Docker publishes no container port. The bearer is host-administrator transport authority, not a tenant approval. |
| Tenant-signed service task | Signed site policy scopes each tenant Ed25519 public key to exact service IDs. The private key stays off-node. Gateway accepts only configured exact JSON `POST` operations, verifies one short-lived permit against the active tenant, instance, generation, artifact, policies, task, operation, and request bytes, fsyncs authorization before dispatch, and never automatically retries an ambiguous outcome. |
| Authenticated connector | The signed capsule, tenant policy, and intent select connector IDs. Node configuration maps each connector operation to one exact method, path, origin, address policy, and owner-only credential. Gateway strips agent credentials, spends a durable task claim and call budget, pins the resolved address, injects only the configured Bearer or API-key value, denies redirects, and bounds concurrency, bodies, response, and time. In Authorized Effects mode, site-root-signed tenant policy pins action keys and an approval threshold to connector IDs, intent explicitly selects `authorized`, generic egress is prohibited, and Gateway requires a complete one-use permit that matches the live grant and exact request. It spends that permit before DNS. |
| HTTP(S) egress | Executor intersects the publisher profile, tenant route IDs, and instance request. Gateway enforces host and port, a pinned resolved IP, explicit private Classless Inter-Domain Routing (CIDR) ranges, concurrency, byte and time limits, lifecycle, and bounded audit output. Synchronous denial work is limited to 30 per grant, 120 per tenant, and 480 per host per minute; exhaustion suppresses further denial writes while allowed traffic continues. |
| Resources | Per-workload memory, swap, CPU, PID, and shared-memory limits are mandatory. Docker's bounded `local` log rotation is fixed and the out-of-memory (OOM) killer remains enabled. Executor reconstructs host and tenant aggregate memory, CPU, PID, and workload reservations from Docker, including stopped containers and fixed relay overhead. Disk, inode, and I/O quotas remain outside this portable contract. |
| Lifecycle | Docker restart and automatic-removal policies are disabled. Executor, not Docker, owns lifecycle. It inspects restart, log, port, device, mount, network, namespace, and image settings after creation. |
| Integrity and recovery | A SHA-256 fingerprint covers the admitted definition. Reconciliation—comparison of durable signed state with actual runtime objects—runs before normal mutations are accepted and every 30 seconds. It may repair limited lifecycle drift, but never recreates or adopts missing or structurally changed objects. A degraded scan can only narrow authority. |
| Route integrity | Gateway persists a non-secret digest of each retained route policy and a private credential-content binding. Executor stores the route-policy digest in the admission fence and receipt. Reload, restart, start, and reconciliation refuse a mismatch while the grant remains retained. |
| Interface | Request bodies and log output are bounded, and every error has the same JSON shape. Executor mutation and both uplinks require authentication. Signed envelopes and payloads reject duplicate and unknown JSON members. The generic supervisor REST API has no built-in authentication and must stay on loopback or behind operator authentication. |
| Receipts (opt-in) | Executor writes length-framed, Ed25519-signed lifecycle records. Gateway writes a separate signed newline-delimited JSON chain for connector and service-task authorizations and terminal outcomes. One-approver authorized connector records use format 5 and include the effect mode, operation-policy digest, authority key ID, exact permit-envelope digest, and exact request digest. Multi-party records use format 6 and add the canonical signer set and threshold. A stable invalid-permit condition can add only one denial marker per retained grant, without claiming a verified permit or key. Service-task records use format 4 and add the service, bounded status, and observed run ID but never the raw prompt. Both chains are hash-linked and flushed with `fsync`; an auditor can verify a copied chain and an independently retained exact head without network access. |

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
- service-scoped public task authority with node-local spend-before-dispatch replay
  control;
- per-workload resource ceilings and host-wide and per-tenant aggregate memory,
  CPU, PID, and workload-count ceilings;
- layered grant, tenant, and host limits on egress denial-audit work;
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
mutations. A requested state, inference, service, connector, or egress capability is
rejected when any part of its enforcement path is missing or cannot be inspected.

A task-authorized service grant also fails closed when Gateway lacks a configured
exact operation, signed receipt identity, explicit tenant receipt budget, retained
public task authority, or compatible state. A request with a missing, duplicate,
expired, malformed, or mismatched task permit is rejected before dispatch. Receipt
quota exhaustion is also pre-dispatch. If authorization is durable but the service
result is ambiguous, Gateway writes `outcome_unknown` and refuses automatic retry.

An authorized-effects grant also fails closed when intent omits the explicit mode,
policy does not cover every selected connector, signed key scope differs from
Gateway configuration, generic egress is present, the required exact-request permit
is absent, or the tenant lacks receipt capacity. Gateway records at most one stable
`action_permit_denied` marker per retained grant. Failure to persist that bounded
marker returns HTTP 503 rather than allowing the connector request. The compromised
workload chooses the task ID and request bytes accompanying the first invalid
permit; later denials are not enumerated, so the marker is not an exhaustive audit
log.

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

Task-enabled service mutations use a narrower path. Node configuration allows only
exact `POST` operations with `application/json`, at most 64 KiB of request data,
1 MiB of response data, a 120-second dispatch, and a 15-minute permit. The request
has no query, alternate encoded path, transfer coding, WebSocket upgrade, or
caller-selected upstream headers. Gateway accepts only HTTP 200, 201, or 202 with a
bounded run ID as success and returns its own canonical response.

Replay prevention is scoped to one node and one retained Gateway receipt-ledger
epoch. The spend key omits generation, so replacing the same logical instance does
not make a task ID spendable again. A second node, a replaced ledger, or a new epoch
is a different replay domain. Steward therefore claims node-local at-most-once
dispatch, never exactly-once execution. The run ID comes from the untrusted agent
service and can be fabricated.

Egress supports proxy-aware HTTP with Server-Sent Events (SSE) and HTTPS with
secure WebSockets (WSS). It does not support raw TCP,
UDP, ICMP, SOCKS, proxy-unaware programs, or arbitrary DNS. Gateway binds HTTPS
CONNECT to the visible TLS ClientHello server name but does not decrypt TLS, so
path and method policy apply only to HTTP that Gateway can inspect. Deactivating or
removing a grant closes active HTTP requests, CONNECT tunnels, and WebSocket
streams immediately.

The egress denial limiter bounds synchronous audit pressure, not all Gateway work.
After 30 denials for one grant, 120 for one tenant, or 480 across the host in a
one-minute fixed window, the next request that fails egress policy returns
`egress_rate_limited` without another denial-audit write. Requests that satisfy
policy remain allowed. Lifecycle transitions keep the more specific
`grant_inactive` or `grant_revoked` response even when their denial record is
suppressed. The limiter does not provide tenant scheduling or isolate shared CPU,
memory, disk latency, or the host-wide audit file.

## Evidence boundary

Executor receipts record admission and lifecycle decisions and effects that
Executor can observe. Gateway's separate mixed-format chain records connector and
service-task authorization and terminal outcomes that Gateway can observe. For permit-backed calls, offline audit
can correlate the signed permit with the authority key, exact request, stable task
call digest, authorization time, and terminal record. Offline verification checks each
format's signatures and framing, plus sequence, hash links, node ID, key epoch, and
an optional exact externally retained head. An expected sequence and chain hash
identify one exact final head; they are not lower bounds. This detects a truncated
or advanced copy relative to that checkpoint.

For an authorized connector, format-5 authorization and terminal records also bind
the explicit authorized mode and exact operation-policy digest. Format 6 adds a
multi-party signer set and threshold. They show that Gateway accepted and durably
spent one complete exact-request permit before attempting the network call. They do
not show that each approver understood the request or that the upstream applied it
exactly once.

For service tasks, verification can establish that the configured node key signed
an authorization before dispatch and later signed a status and run ID. It does not
establish that the agent performed useful work, that its output was true, or that an
upstream effect occurred exactly once. A missing terminal remains an unknown
outcome. Raw request bytes and prompts are deliberately excluded.

The built-in activation canary narrows that statement for one qualified fixture:
it additionally checks the activation-scoped Hermes session and the canonical
empty-workspace audit result. The activation proof then correlates that bounded
result with exact task, permit, receipt, and witness coordinates. Executor signs
an activation-begin marker after read-only admission preflights and before the
admission-allow receipt or host mutation. After Gateway signs authorization,
dispatch, and terminal evidence, Executor signs a checkpoint that binds that
exact evidence. Live collection requires the final controller witness to cover
the begin, admission, start, and checkpoint sequence; allows unrelated tenant
suffix receipts; and rejects later receipts for the same activation or
lifecycle-invalidating events. The proof manifest is unsigned, and the canary
does not establish the safety or correctness of arbitrary models, prompts,
plugins, skills, workspaces, or later behavior.

Fleet rollout preserves that same evidence boundary. The common command signer
first authorizes the exact plan. Before entering each later batch, it signs a
chained promotion that binds the immediately preceding batch's ordered passed
state, activation proofs, controller captures, and the exact next boundary. Every
rollout command binds the plan-authorization or current-promotion envelope digest,
and its issue time cannot precede that authorization. Offline verification checks
the complete chain.

This proves a signer-attested authorization sequence over the retained evidence.
It does not independently attest wall-clock or host execution order, capture a
human reason or external approval workflow, turn the canary into general agent
evaluation, or make execution exactly once across nodes. Controller captures can
include interleaved metadata from unrelated tenants, so the coordinator requires
site-administrator authority and the copied workspace must be handled as sensitive
site-wide evidence.

Node-local receipts are not hostile-host attestation. Host root can replace the
binary, keys, and logs together. The chain does not include prompts, model output,
semantic tool actions, agent explanations, or arbitrary application logs. Protect
the receipt key and retain checkpoints outside the node when rollback detection
matters.

## Security boundary exclusions

- Steward Control receives no Docker access or tenant and site private signing
  keys.
- Agent containers do not receive host paths or Docker access.
- `steward -enable-process-exec` runs trusted operator-authored local processes. It
  is not a tenant sandbox and has no resource isolation.
- Computer-use and browser automation must run in a separate sandboxed workload,
  not inside the Steward process.
- Model serving and semantic inference-data policy remain outside Steward. Steward
  enforces only the approved transport route, model alias, and credential boundary.
- Authorized Effects covers only Steward-mediated connectors. Unmanaged
  credentials, browser sessions, plugins, application channels, local filesystem
  effects, and external computer-use systems remain outside its mediation.
- Host root, the kernel, Docker, Gateway, receipt keys, and action-signing keys stay
  trusted. An approver can authorize harmful exact bytes, and an ambiguous upstream
  result cannot be converted into exactly-once execution by retrying.

## Operator responsibilities

Patch the controller and node hosts, Docker, gVisor, and Steward. Authenticate
imported artifacts; protect controller TLS, authentication, and evidence-witness
private keys, controller backups, enrollment, receipt, off-node action-authority,
and tenant task keys; keep
management listeners on loopback or disabled; monitor capacity and audit output;
and preserve anti-replay state during backup and rollback. An exported
action-trust inventory is
unsigned and non-secret: authenticate it as operator input. It is a signing
preflight, not authority; Gateway's live configuration makes the final decision.
The same rule applies to an exported service-trust inventory. Keep Gateway on
loopback and use SSH or another authenticated private management channel for remote
operation. Do not expose its host bearer as tenant authentication.

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
