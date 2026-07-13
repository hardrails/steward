---
title: Steward capability boundaries
description: Exact Steward guarantees, signed HTTP(S) egress controls, residual risks, and deliberately unavailable authority.
section: Capability boundary
---

# Steward capability boundaries

Steward verifies profile capsules and site policy as Ed25519-signed DSSE (Dead
Simple Signing Envelope) documents. It binds commands to a tenant, node, and
instance; rejects stale policy and generations; durably journals host changes; and
creates signed, hash-linked receipts for offline verification. Optional capabilities
include inference, a private service, deny-by-default HTTP(S) egress, command-line
and Model Context Protocol (MCP) operations, and Terraform bootstrap. Persistent
state is available only through the dedicated-host compatibility mode described
below.

## What a receipt means

A valid chain shows that the node key signed the supplied Steward enforcement
records. Verification detects internal gaps, reordering, changes, and an incomplete
final record. Each record binds capsule and policy digests, tenant, runtime
reference, generation, decision type, and outcome.

It does not prove prompt meaning, model output, agent intent, tool meaning, or
upstream behavior. The chain also cannot reveal when someone removes every record
after an older valid point. To detect that rollback, store the last verified
sequence and chain hash separately. Without a Trusted Platform Module (TPM),
trusted execution environment (TEE), or external checkpoint, a hostile host root
user can replace the key, log, and software together. Receipts are tamper-evident
only within the documented node trust boundary.

Executor holds both Docker authority and the receipt key. There is no separate
signing service or Unix identity, so an Executor compromise can forge node-local
receipts.

## Signed admission is opt-in

The host-control `/v1/workloads` endpoint is available only without signed
admission. Enabling signed admission disables all unsigned provisioning, including
legacy outbound `provision` commands. Executor enables `/v1/admissions` only with
complete signed policy, site-root public key, node identity, durable fence and
journal paths, and an evidence private key. Partial configuration stops startup.
An operator must initialize a fence once; startup never recreates a missing fence.

The packaged Executor exposes a bearer-protected loopback API for `stewardctl node`
and `steward-mcp`. A control plane can send `admit` through the authenticated
Executor uplink. Local admission also requires the explicit host-admin-intent flag.
The local token grants host-administrator authority, not tenant authentication.

## Durable control stores have fixed lifetime limits

Executor bounds every durable control file so a corrupt or attacker-controlled
input cannot force unbounded startup work or memory use. These bounds also limit
how many mutations and distinct instance identities one node can retain over its
lifetime:

| Store | Limit | What consumes it |
| --- | ---: | --- |
| `evidence.bin` | 64 MiB | Signed pre-effect, commit, compensation, recovery, and lifecycle receipts |
| `operation-journal.bin` | 16 MiB | Prepared and terminal host-mutation records |
| `admission-fences.bin` | 4 MiB and 65,535 records | One retained record for each tenant and instance pair, including destroyed tombstones |
| `uplink-state.json` | 1 MiB encoded | One retained anti-replay position for each tenant and instance pair seen through Executor uplink |

These are retention limits, not live-workload limits. Destroying a workload does
not remove the history needed to reject replay. The evidence log and operation
journal are append-only, while the fence and uplink files rewrite bounded
snapshots without discarding old identities.

Steward currently has no supported command to compact, prune, or roll over these
stores. Monitor their file sizes and the number of tenant/instance identities
before they approach a limit. When a store cannot safely accept the next record,
the affected signed mutation fails closed. Do not truncate, replace, or restore
one file independently: doing so can remove evidence or replay protection. A
long-lived deployment must include these limits in node-lifecycle and capacity
planning.

## Egress boundary

Signed workloads can request 1–32 named routes. The publisher capsule must allow
egress, and tenant site policy must allow every route. Gateway maps each route to
hostname patterns, ports, and concurrency, byte, and time limits. The agent receives
an HTTP/HTTPS proxy, not raw Docker networking. Gateway connects to the exact
verified IP. It always rejects unspecified, multicast, and limited-broadcast
addresses. Private and IANA-designated special-purpose unicast ranges—including
loopback, link-local, benchmarking, documentation, and shared carrier-grade NAT
space—are denied by default. An explicit Classless Inter-Domain Routing (CIDR)
range may allow special-purpose unicast when that private destination is intentional.
Agent DNS is disabled.

HTTPS uses `CONNECT`. Steward requires the TLS ClientHello server name to match the
approved CONNECT hostname and enforces address, port, byte, time, and concurrency
limits. It does not intercept TLS, so it cannot enforce paths or methods inside an
HTTPS tunnel. JSON Lines (JSONL) audit omits paths, queries, headers, bodies, and
credentials. Steward has no generic credential-injection path. If an approved agent
already stores a credential in its state, Steward does not hide that credential from
the agent; only the inference broker keeps its upstream token outside the workload.

For an unknown-length inference, service, or HTTP egress response, Gateway starts
forwarding before it can know the final size. It advertises an
`X-Steward-Stream-Status` trailer and aborts the HTTP stream if an upstream read
fails or another byte exists after the configured limit. Standard HTTP clients
surface that abort as a framing or body-read error. A clean stream ends with the
`completed` trailer. This mechanism proves that Gateway reached a clean protocol
boundary; it cannot prove that an upstream close-delimited application response was
semantically complete before the upstream chose to end it.

Route concurrency limits apply to allowed traffic. Gateway fails closed if it cannot
persist an allow decision before opening the route. It attempts synchronous audit
writes for denied requests and terminal outcomes, but those writes are best-effort:
a denial still returns and an existing stream still ends if the write fails. Denied
requests currently have no separate per-grant request-rate limit. A tenant can
therefore create shared Gateway disk-I/O pressure by repeatedly requesting denied
destinations. Host monitoring and external resource controls remain necessary until
denial accounting is rate-bounded.

Docker selects each capability network from its daemon-wide default address pools.
Steward currently does not request a fixed prefix size. Docker commonly allocates
larger subnets than a two-container agent/relay network needs, so address-pool
exhaustion can occur before Steward reaches its workload-count cap. Configure and
capacity-test Docker's default address pools for the node's maximum network count.

Executor treats only Docker's `created` and `exited` states as exactly stopped.
`paused`, `restarting`, `removing`, `dead`, unknown, and unrecognized states are
ambiguous. A stop request attempts a bounded stop and then requires reinspection
to prove `created` or `exited`; otherwise the operation remains degraded and
requires reconciliation. Reconciliation applies the same classifier to the agent
and its relay.

Gateway configuration requires an explicit loopback service address with a numeric
port from 1 through 65535. Missing, zero, out-of-range, and named service ports fail
both `-check-config` and startup.

## Hermes adapter qualification boundary

Steward's Hermes qualification applies only to upstream commit
`095b9eed3801c251796df93f48a8f2a527ff6e70`, the checked-in adapter definition, and
the documented runtime contract. The proof ran a source-built, non-root image under
gVisor, submitted useful work through Hermes's run API, verified the signed
`steward.workspace-audit` result, restarted the container with its retained state,
and ran the skill again.

This does not qualify the official upstream image, another Hermes commit, arbitrary
plugins, channels, skills, MCP servers, or run event streams. The service bridge
allows only negotiation, health, `POST /v1/runs`, and `GET /v1/runs/{run_id}` on
port `8766`. Inference is fixed through
`http://steward-relay:8080/v1`.

Steward distributes the pinned build definition and builder, not a prebuilt Hermes
OCI archive. Dependency and base-image notices are incomplete, so redistribution
remains blocked. A locally produced archive and its metadata attestation still
require operator authentication, inspection, policy authorization, and signing.
The attestation records build inputs and output digests; it is not a signature or a
new runtime proof.

Hermes state uses the same unquotaed Docker volume as any other persistent Steward
workload. It requires the explicit dedicated single-tenant host mode and does not
extend Steward's shared-host isolation claim to persistent state.

## Release transitions require a drained node

Steward does not upgrade or roll back in place while workloads or grants remain.
Before a release transition, destroy all managed agent and relay containers and
capability networks; stopped containers also count. No live admission fence,
pending journal entry, or retained Gateway grant may remain. Steward-managed state
volumes may remain. This interruption lets activation bind one relay image to the
release, inspect every durable format with services stopped, and avoid changing the
execution boundary beneath a retained workload.

## Not available

- Raw outbound TCP, UDP, ICMP, SOCKS, or arbitrary inference destinations
- Transparent interception for software that ignores `HTTP_PROXY`/`HTTPS_PROXY`
- TLS interception or application-layer (L7) path/method policy inside HTTPS tunnels
- Interactive dynamic approval of previously unlisted destinations
- Arbitrary state paths, host bind mounts, or automatic state deletion
- Raw published agent ports, public ingress, or tenant end-user authentication
- Secret, arbitrary environment-variable, or file injection
- Per-workload UID/GID selection
- GPU or other device assignment
- Writable image root filesystems
- Interactive terminal/exec sessions
- Image pulling or registry authentication
- A prebuilt, Steward-redistributed Hermes adapter image
- A qualified OpenClaw adapter; OpenClaw remains a layout contract
- Hermes run event streams or unqualified Hermes plugins, channels, skills, or MCP
  servers
- Multi-image archive selection, remote OCI descriptors, or mutable-tag admission
- Automatic recovery or a decision that marks an ambiguous journal operation
  committed or compensated. Degraded stop can narrow local authority, but the
  original operation still requires explicit operator recovery.
- A supported config-only purge or node-retirement workflow that preserves the
  receipt key and evidence chain as one identity
- Container checkpoint/restore, Kubernetes, or multi-host placement

The capsule contains maximum `state`, `inference`, `service`, and `egress`
capabilities. State requires a Steward-owned Docker volume and the explicit
dedicated-host-only compatibility setting for volumes without enforced byte or inode
quotas. Inference, service, and egress require the complete Gateway and relay
configuration. If a requested enforcement path is missing, Executor returns HTTP
501; a signed boolean alone is not an isolation control.

Steward reserves aggregate memory, CPU, PIDs, and workload counts for the host and
each tenant. It reconstructs those reservations from Docker after restart and
includes fixed relay overhead. These admission ceilings do not reserve disk bytes,
inodes, I/O bandwidth, or capacity used by trusted host services. Operators must
leave explicit headroom for Docker, gVisor, Gateway, the operating system, logs,
and bursts.

Persistent local Docker volumes have no portable hard byte or inode quota, so they
remain disabled on a shared host. Enabling
`-allow-unquotaed-state-on-dedicated-host` requires complete signed admission with a
verified policy containing exactly one tenant and moves storage exhaustion outside
Steward's isolation claim.

## Runtime hardening still ahead

Future hardening must preserve deny-by-default operation:

1. encrypted or externally managed state backends without caller-selected host paths;
2. stronger receipt-key isolation and optional external evidence anchoring;
3. finer authenticated service principals beyond the host-wide local token;
4. optional external signature, software bill of materials (SBOM), and provenance
   verification before the bounded local OCI import; and
5. a verified node-retirement and control-store rollover procedure that preserves
   receipt continuity and replay protection.

Each capability requires crash recovery, drift inspection, cross-tenant tests, and
Docker/gVisor acceptance. Host mounts, Docker socket exposure, default-allow routes,
implicit private-address access, and caller-selected privileges are not acceptable
substitutes.

## Trusted substrate

Host root, the Linux kernel, Docker, gVisor, the node's signing-key protection, and
operator configuration are trusted. Steward does not provide bare-metal bootstrap,
disk encryption, hardware attestation, vulnerability management, model inference,
or formal air-gap accreditation.
