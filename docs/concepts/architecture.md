---
title: Steward architecture
description: Understand Steward's service separation, proof-carrying agent activation and fleet rollout, signed local admission, Docker and gVisor isolation, and offline receipts.
section: Explanation
---

# Steward architecture

Steward is an open-source agent orchestration system with an optional fleet
controller and independently installable node services. It splits node authority
among three long-running services with separate Unix identities. A fixed relay
runs for each instance that receives a network capability; the relay has no host
authority.

Docker and gVisor answer where untrusted code executes. They do not identify the
tenant that authorized a workload or constrain a manipulated agent to one approved
external effect. Steward keeps those decisions outside the agent and connects them
to durable node state and offline-verifiable evidence.

```text
Operator and tenant-controlled signers
  keep tenant and site private keys outside the controller
  sign exact Executor commands, connector requests, and service tasks
       |
       | submit exact signed command bytes
       v
steward-control on a management host
  tenants + node enrollment + bounded inventory
  opaque command queue + delivery leases + terminal outcomes
  no tenant private keys, Docker socket, shell, or agent execution
       ^
       | node-initiated HTTPS poll and report
       v
Linux node
  steward                 steward-executor             steward-gateway
  lifecycle + uplink      OCI admission + Docker       finite route grants
  no Docker authority     journal, fences, receipts    no Docker authority
       |                           |                           |
       v                           v                           v
  independent lifecycle    tenant agent container <--> steward-relay <--> per-grant sockets
  state and API             Docker runtime: runsc                         Gateway-owned

Outbound data: agent -> relay -> Gateway -> approved inference or HTTP(S)
Service ingress: authenticated host caller -> Gateway -> relay -> agent
Signed task: owner-only bundle -> loopback Gateway -> exact service POST

Management/node steward-mcp: bounded stdio adapter for Control, Executor, and optional task tools
Mostly offline stewardctl: keys, signed releases/capsules/policy, task permits, receipts;
                         image import uses Docker; task lifecycle uses loopback Gateway
Operator-side rollout: signed exact plan + evidence-bound promotions + append-only proof workspace
Inference system: separately selected and operated
```

## Why Steward uses separate services

The Docker socket provides authority that is effectively equivalent to host root.
Only the long-running `steward-executor` service receives Docker-group membership.
The lifecycle supervisor and the agent cannot open the socket, so unrelated
supervisor features remain outside the Docker compromise boundary. The root-run,
one-shot `stewardctl image import` command is a separate bounded Docker client: it
verifies and sanitizes one archive before loading it.

`steward-gateway` holds upstream route credentials and enforces bounded,
per-instance inference, service, exact tenant-signed task, connector, and egress
grants, but it cannot open the Docker
socket. Executor creates, activates, deactivates, and removes grants over Gateway's
local control socket without receiving upstream credentials. The per-instance relay
runs in the workload network and receives only its matching per-grant Unix-socket
directory. Fixed socket names carry inference, service, connector, and egress traffic; Docker
publishes no agent or relay port to the host.

Systemd hardening reduces each service's host access, but it cannot make Docker
socket access safe. Executor's closed request shape is the primary control. A
caller can select an immutable Open Container Initiative (OCI) image, explicit
command, tenant and profile identity, and bounded resources. The API has no fields
for privileged mode, host mounts, devices, host networking, or other Docker escape
hatches.

## Direct and outbound control

The supervisor and Executor use different management contracts. With bundled
Steward Control, Executor polls remotely while the generic supervisor stays on
`127.0.0.1:8080` with durable local state and process execution disabled. A
compatible external controller may instead supply the supervisor's separate
tenant-scoped uplink credential. Executor keeps its bearer-protected API on
`127.0.0.1:8090` for `stewardctl` and MCP clients while also polling its uplink.
Neither service binds a non-loopback management listener.
Executor uplink commands invoke the same HTTP handlers as direct requests. The
generic supervisor uplink has a bounded dispatcher, but it calls the same tracker
methods and applies the same instance-spec validation as the direct API.

Multi-tenant Executor commands use DSSE (Dead Simple Signing Envelope), a standard
format that signs a typed payload. A tenant key in site-root-signed policy may sign
only its allowed operations. A separate site-owned cleanup key may sign only
`stop`, `destroy`, and `purge`, so the site can contain a workload after tenant
authority is removed. The node bearer authenticates transport but cannot select a
tenant.

The signed command binds the tenant, node, instance, runtime reference,
generations, sequence, validity window, operation, and payload. Executor stores the
highest accepted position for each `(tenant_id, instance_id)` before reporting
completion. This generation fence—a durable high-water mark—prevents a delayed or
replayed command from crossing tenants or resurrecting a destroyed workload after
a restart. A `read` command checks the existing fence but does not advance the
lifecycle sequence, so read-only authority cannot block a later mutation.

## Signed local admission

Signed admission separates three authorities. A publisher signs a reusable profile
capsule. The site root signs local policy. An authenticated caller supplies intent
bound to one tenant, node, instance, lineage, and generation. Executor admits only
the intersection of those inputs.

Executor imports a bounded single-image OCI archive through an offline verification
path, then runs the exact signed local config digest. Before a Docker change, it
fsyncs (flushes to durable storage) an operation journal and a pre-effect receipt.
After creating and inspecting the workload, it appends a commit receipt and
advances its durable fences. Receipts use Ed25519 public-key signatures and hash
links.

Reconciliation means comparing durable signed records with the objects that
actually exist. Executor runs a bounded reconciliation before accepting normal
mutations and every 30 seconds. A failed scan leaves the process, listener, and
uplink available with readiness at 503, but only an authenticated safety-only stop
may mutate the host. Reconciliation may repair limited lifecycle drift, but it
never recreates or adopts a missing or structurally changed workload.

For inference, task-authorized service, connector, and egress policy, Gateway
durably pins a non-secret digest of the effective route policy and a private binding
to each loaded credential. Executor stores the
public policy digest in its admission fence and evidence. A restart, reload, start,
or reconciliation refuses mismatched route semantics. Inference requests must use
the exact authorized model alias; a route credential that can reach other models
does not grant access to them.

For a task-authorized service, site policy assigns a tenant's Ed25519 public key to
exact service IDs. Executor projects only the matching public authority into the
runtime grant; the private key stays off-node. The tenant authority signs a
short-lived DSSE statement for one exact JSON request. Gateway compares the
signature with the active tenant, instance, runtime, generation, admitted artifact,
site and route policy, service operation, task ID, request digest and length, and
validity window.

Gateway reserves the task identity in memory, fsyncs signed authorization to its
receipt ledger, rechecks time and lifecycle, and only then sends the configured
`POST` to the agent service. It forwards no caller-selected headers. A successful
service response must have HTTP 200, 201, or 202 and one bounded run ID. Gateway
records a separate dispatch receipt and returns its own canonical run-ID response
rather than relaying untrusted headers or body. Later status observations use only
the configured path prefix and recorded run ID. A terminal report adds a third
receipt containing its agent-reported status, exact response digest, and byte
length. A successful replay returns the stored ID; an ambiguous result is never
dispatched automatically again.

The replay identity spans workload generations for one tenant and logical instance,
but exists only on one node and one retained ledger epoch. This is node-local
at-most-once dispatch, not fleet-wide or upstream exactly-once execution. The
service supplies the run ID, so the receipt records an observation rather than
proving completed or correct agent work.

Authorized Effects makes the action-permit boundary part of signed tenant policy.
The policy pins each off-node action public key to exact connector IDs; authenticated
intent explicitly selects the mode; Executor projects the narrowed keys; and
Gateway rejects generic egress or any key/configuration mismatch. Each required
authority signs one unchanged canonical DSSE statement for one exact connector
request or an unordered set of up to eight exact requests. Gateway checks every
signer against every connector, then checks its node, tenant, instance, generation,
admitted artifact, policies, connector operation-policy digest, task, body digest
and length, method-derived content type, and validity window against live state.
The operation digest fixes
the canonical origin, credential injection mode and epoch, method, and path.
Gateway records the permit and stable task-based call digest together in receipt
format 5 or 6 before DNS. Signers never need the upstream credential, and their
private keys do not belong on the node.

`stewardctl` is a CLI, not a daemon. Its key, capsule, policy, task-issuance,
archive-inspection, and evidence commands run offline without contacting a node,
control plane, publisher, or transparency service. `image import` connects to the
local Docker daemon after offline verification. Generic `task submit`, `status`,
`observe`, and `wait` are explicitly online operations that accept only a
literal-loopback Gateway origin; remote operators use an authenticated SSH path
rather than exposing Gateway.

## Proof-carrying agent activation

A publisher-signed agent release adds an operator-facing outcome to the existing
capsule while binding the exact offline archive, fixed qualification canary,
qualification-evidence digest, and known limitations. It remains descriptive. The
site policy, instance intent, live Executor decision, Gateway configuration, and
tenant task permit still authorize the deployment and canary.

The one-shot activation coordinator composes existing local interfaces through a
fixed state machine. An unsigned plan binds exact inputs and finite timeouts. An
owner-only workspace retains generated artifacts once and appends sequential state
checkpoints. After authority, policy, and read-only admission preflights pass,
Executor signs an `activation_begin` marker before the admission-allow receipt,
mutation journal, or host mutation. The marker binds the activation and runtime
identity. After real admission, the coordinator emits an unsigned challenge that
binds the runtime reference, grant, policies, request, and public task
authorities. The default flow pauses until a separate signing station returns the
matching tenant-signed task bundle; the private key does not enter the node.

The current qualified agent recipes are dedicated-host compositions, not a shared-host
activation path. It requires exactly one tenant in the signed site policy,
host-administrator local admission, and the explicit unquotaed-state compatibility
setting because Docker's portable local volume driver does not enforce hard byte
or inode quotas.

The initial canary is only the release-selected closed Hermes or OpenClaw fresh-state workspace audit. A final
unsigned proof manifest correlates the passed state, exact result digest, task and
permit, activation-begin and activation-checkpoint digests, Executor and Gateway
receipt coordinates, and the controller witness coordinate. After verifying
Gateway's authorization, dispatch, and terminal receipts, the coordinator writes
the checkpoint digest to Executor's signed chain. The final witness must cover
that checkpoint and have no later receipts for the same activation; unrelated
tenant suffix receipts are allowed. Signed receipt order provides the causal link
without comparing Gateway and controller clocks. Authenticity comes from
separately verified signed companions and externally pinned public keys. The
activation workspace prevents a compliant retry from rewriting generated history,
but does not provide hostile-host attestation.

## Proof-carrying fleet rollout

The operator-side rollout coordinator applies the same closed qualified-agent activation
contract to an explicit ordered node list through Steward Control. It authenticates
all retained inputs before contacting the controller, signs exact commands on the
trusted coordinator, and stores each command before submission. The controller
delivers those bytes and retains bounded evidence; it does not receive the command
or task private keys and does not choose targets.

The rollout plan is a bounded unsigned manifest, but it is not accepted as
authority by itself. Before the first controller request, the common tenant command
key authorized by site policy for `admit`, `start`, and `activation-canary` signs
the exact plan digest. Before any later batch starts, the same key signs a chained
promotion that binds the previous authorization, the completed batch boundary and
ordered passed evidence, and the exact next boundary. The admit, start, and canary
commands for each batch carry the applicable authorization-envelope digest. A
protocol-4 node must advertise `rollout-authorization-context-v1` so the strict
command decoder can accept and retain that signed command field. The node does not
fetch or verify the referenced plan or promotion envelope; the coordinator and
offline verifier perform that correlation.

Target 0 is the canary. One `rollout run` invocation advances only the current
deterministic batch, processes its targets sequentially, and stops before the next
operator promotion decision. A target must pass its admission, fixed task, Gateway
receipt, Executor marker, controller capture, and activation-proof checks before a
later target can advance. Transient transport failure can resume from immutable
artifacts; an ambiguous outcome or evidence conflict becomes sticky
`action_required` instead of creating replacement authority.

The owner-side workspace publishes each artifact without replacement through a
same-directory hard-link transaction, syncing the file and directory at the
durable boundaries. Reopening reconciles only two bounded crash shapes: remove an
unpublished staging inode, or remove the staging name after a linked final artifact
was durably published. Any other shape fails closed. This requires a filesystem
with reliable POSIX hard links, `fsync`, `flock`, Unix ownership, and link counts;
there is no weaker fallback.

The aggregate `proof.json` is unsigned. It correlates the plan and ordered target
activation proofs. Its `plan_authorization_digest` and ordered
`batch_promotion_digests` bind the signed plan and promotion envelopes. Each target
entry binds the exact admit, start, and canary DSSE command envelopes through their
three command digests. The aggregate's own digest therefore commits the exact
retained plan, promotion, and outer-command authorization envelopes. Offline
verification still authenticates every signed companion and the separately
transferred OCI archive. The current runner does not transfer or import images,
select nodes, reconcile desired state, run arbitrary canaries, or roll back
workloads. Signed promotions attest what the common command signer authorized from
the retained evidence; they are not an independent clock, hostile-host attestation,
or record of human reasoning. See the
[fleet rollout guide]({{ '/guides/fleet-rollout/' | relative_url }}).

## Controller replaceability and authority separation

`steward-control` implements Steward's public control and uplink contracts. Any
compatible system may implement the same contracts, and nodes do not import a
controller SDK or require a hosted endpoint.

This boundary lets an operator audit and build the controller and node software
from the same public repository while deploying them as separate trust domains. It
also keeps SSO, approvals, fleet scheduling, rollout policy, tenant private keys,
and Docker authority out of the controller process.

## Inference, connector, and egress separation

Steward does not host, schedule, or select models. Gateway can expose an
operator-selected local or remote OpenAI-compatible inference system through a
finite, per-instance grant.

For agent-service task submission, the host operator first configures one exact
service method and path plus its fixed status-path prefix, observation timeout, and
poll interval. A separately controlled tenant key then narrows the active service
grant to one request. The host Gateway token authenticates transport and does not
replace the tenant signature. Passive lifecycle status and bounded observations are
host operations; the task permit authorizes only its exact configured POST.

For an authenticated connector, the agent sends a logical connector and operation
ID to its Relay. Gateway selects one exact operator-configured origin, method, and
path, pins an allowed resolved address, strips agent-supplied credentials, and adds
the owner-provided credential at the last hop. Spend-before-effect task claims and
per-grant call budgets survive restart. The connector is not an arbitrary proxy or
secret-delivery mechanism. An optional action permit narrows that outer connector
grant to one authority-signed request; it cannot add an operation or tenant that
the admitted grant lacks. Authorized Effects additionally makes that requirement
continuous from signed tenant policy through intent, immutable runtime state,
Gateway grant, exact signed authority, durable per-task spend, and format-5,
format-6, or context-locked format-7 evidence. Context locking can invalidate a
permit after a later managed connector response. It assumes the agent is compromised and applies only to fully mediated connector
calls; it is not prompt-injection detection or control over unmanaged channels.

For HTTP(S) egress, the agent receives standard proxy variables that point to its
relay. The relay has no Internet route; it forwards bytes to one grant-owned Unix
socket. Gateway intersects the grant with operator route configuration, resolves
and pins an allowed IP address, and performs the network connection. Stop and
destroy deactivate or remove the same grant. DNS checks, private-address policy,
auditing, and lifecycle enforcement therefore stay at the trusted boundary.
Gateway also caps synchronous denied-attempt work at 30 per grant, 120 per tenant,
and 480 per host per minute. Exhausting any layer suppresses further denial-audit
writes and returns `egress_rate_limited` only for requests that are denied; traffic
that satisfies policy continues. Inactive and revoked grants retain their
`grant_inactive` or `grant_revoked` status even when no further denial record is
written.

For implementation details and residual risks, read
[`ARCHITECTURE.md`](https://github.com/hardrails/steward/blob/main/ARCHITECTURE.md)
and the [security model]({{ '/concepts/security-model/' | relative_url }}).
