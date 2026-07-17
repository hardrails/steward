# Steward

**Open-source admission and execution software for isolated AI agents on Linux.**

[![CI](https://github.com/hardrails/steward/actions/workflows/ci.yml/badge.svg)](https://github.com/hardrails/steward/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hardrails/steward?display_name=tag)](https://github.com/hardrails/steward/releases/latest)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-f2532d)](https://hardrails.github.io/steward/)
[![License](https://img.shields.io/github/license/hardrails/steward)](LICENSE)

A sandbox answers where untrusted code runs. It does not answer who authorized the
code, which tenant it represents, which exact external effect is allowed, whether a
request was replayed, or what an auditor can verify after the site disconnects.
Steward supplies that missing control layer for Docker and gVisor Linux servers.

gVisor is a userspace-kernel sandbox that reduces direct exposure to the host
kernel. Steward adds local artifact and policy admission, tenant isolation,
capability mediation, durable anti-replay state, and signed evidence around that
sandbox. It is for operators who need to decide locally which immutable workload
may run, for which tenant, and with which finite capabilities.

The optional signed-admission path verifies three inputs: a publisher-signed
workload profile that fixes the image identity and maximum capabilities; an
operator-signed site policy; and an instance request bound to one tenant, node,
and generation. A generation is an increasing version number for a logical
instance. It prevents a delayed command for an older instance from acting on its
replacement. Steward records each accepted host mutation in a signed receipt
chain that can be verified without a network connection.

For sensitive external actions, Authorized Effects assumes the agent is already
compromised by hostile calendar, email, web, document, memory, or tool content.
Signed tenant policy pins off-node action keys to named connectors and can require
separate operators to sign the same immutable request. Gateway spends the complete
one-use permit durably before DNS while keeping the upstream credential outside the
workload. This protects only
Steward-mediated connector calls, not unmanaged credentials, browser sessions,
local filesystem or computer-use effects, inference confidentiality, or host root.

For a qualified agent outcome, a publisher can also sign one release that binds
operator-facing outcome text, the embedded workload profile, exact offline image
archive, deterministic canary, qualification-evidence digest, and known limits.
The release remains descriptive: local site policy, tenant intent, live admission,
and an exact tenant-signed task still control what runs.

Steward includes a replaceable open-source control plane, while nodes remain
independently operable through public contracts. Nothing has a build-time or
runtime dependency on a private package, API, account, or hosted service.

For a qualified Hermes release, the operator-side rollout coordinator can require
one verified canary before advancing explicit later batches across remote nodes.
The same policy-authorized command key signs the exact rollout plan, each
evidence-bound promotion into a later batch, and commands that name the applicable
authorization digest. Deterministic command IDs and crash-recoverable write-once
workspace transactions prevent a compliant retry from changing that history. The
coordinator keeps command and task signing keys outside the controller and produces
a proof set that can be verified on a disconnected system. The final unsigned
aggregate binds the signed plan authorization, ordered promotion envelopes, and
each target's exact signed admit, start, and canary command envelopes, so its digest
commits those retained authorization bytes. It does not select nodes, transfer
images, run arbitrary canaries, or roll back workloads automatically. The current
Hermes recipe requires the exact image to be
pre-imported on each dedicated target host.

## Install on Linux

Docker must already be installed. The guided installer detects DEB, RPM, and other
systemd Linux hosts. It can install gVisor after asking for approval. That optional
online step fetches gVisor binaries and checksum files from Google-hosted gVisor
release storage. Its default `latest` selector can change. For a reproducible
installation, pin `--gvisor-version` to a dated gVisor release or use the verified
offline path.

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/hardrails/steward/releases/latest/download/install-steward.sh | sudo /bin/bash -p
```

The `-p` flag is required. It prevents a root installer from loading
user-controlled Bash startup files or imported shell functions before its own
validation runs.

The guided flow first offers a loopback-only evaluation, then remote enrollment.
Declining both leaves the software installed, disabled, and unconfigured. Remote
enrollment can install signed multi-tenant authority in the same transaction.

Piping a script to a root shell trusts GitHub's TLS delivery and the release
account. Approving the online gVisor step also trusts its Google-hosted release
storage. A checksum downloaded beside a binary detects transfer errors but does not
independently authenticate that release. For higher assurance, download and inspect
the script, authenticate the release manifest through your own trust process, and
use the [offline installation guide](https://hardrails.github.io/steward/guides/air-gapped/).

After configuration and activation, verify the node before admitting a workload:

```console
sudo /usr/local/libexec/steward/node-doctor
```

To coordinate multiple nodes, install the bundled controller on a separate
systemd Linux management host:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/hardrails/steward/releases/latest/download/install-control.sh | sudo /bin/bash -p
```

It defaults to literal loopback, creates no Docker authority, and keeps tenant
signing keys outside the service. A remote listener requires an explicit TLS
certificate and an owner-only key staged through the trusted root-owned path
described in the guide. See the
[control-plane guide](https://hardrails.github.io/steward/guides/control-plane/)
for PKI, tenant creation, scoped operators, one-time node enrollment, signed
command delivery, separately keyed Executor evidence witnessing, offline export,
secret-free command and credential inventory, derived action-required findings,
opt-in authenticated metrics, backup, and MCP. The
[fleet rollout guide](https://hardrails.github.io/steward/guides/fleet-rollout/)
shows how to promote one exact qualified Hermes release through a canary and
operator-approved batches without giving the controller either signing key.

Steward Control also embeds a read-only operator console at `/console/`. It shows
the scoped operations summary, attention findings, nodes, command metadata, and
credential metadata through the same authenticated API. The browser holds the
bearer only in JavaScript memory. The console exposes no mutation or signing
controls and no secret plaintext; use `stewardctl`, another authenticated API
client, or a documented offline workflow for changes. For the default listener,
open exactly `http://127.0.0.1:8443/console/`. See the
[operator console guide](https://hardrails.github.io/steward/guides/operator-console/)
before exposing it remotely or entering an administrator bearer.

The doctor checks the installed release, Docker and gVisor, systemd services,
loopback health and readiness, Gateway, fixed evidence stores, and filesystem
capacity without changing node state. Its optional canary submits a real signed
task and records agent-reported completion; see the [node verification procedure](https://hardrails.github.io/steward/getting-started/#verify-the-selected-installation-mode).

For a first workload, follow the
[loopback evaluation lifecycle](https://hardrails.github.io/steward/guides/workload-lifecycle/)
or the [signed-admission procedure](https://hardrails.github.io/steward/guides/signed-admission/).
Both return a `runtime_ref` that identifies the admitted workload.

If the workload can change accounts, send messages, rotate secrets, or mutate
infrastructure, follow the
[Authorized Effects guide](https://hardrails.github.io/steward/guides/authorized-effects/)
to require one independently signed exact request before each managed effect.
For inference keys and connector tokens, follow the
[secret materialization guide](https://hardrails.github.io/steward/guides/secrets/)
to keep reusable values in Gateway while OpenBao or another trusted service
manages storage and distribution.

After admission, replace `executor-DIGEST` with the returned `runtime_ref` to query
the workload through the bearer-protected loopback API:

```bash
sudo stewardctl node status --node-url http://127.0.0.1:8090 \
  --token-file /etc/steward/executor-token --runtime-ref executor-DIGEST
```

For any lifecycle-enabled service, an off-node tenant key can sign one exact JSON
request. The generic task client submits the resulting owner-only bundle through
Gateway without placing that signing key in the agent or on the node:

```bash
sudo stewardctl task submit \
  -bundle task.json \
  -gateway-url http://127.0.0.1:8091 \
  -token-file /etc/steward/gateway-service-token

sudo stewardctl task wait \
  -bundle task.json \
  -gateway-url http://127.0.0.1:8091 \
  -token-file /etc/steward/gateway-service-token \
  -result-out task-result.json
```

Keep the same bundle after a timeout or transport error: inspect or wait for that
exact task instead of creating replacement authority. The
[task lifecycle reference](https://hardrails.github.io/steward/reference/offline-tools/#submit-and-recover-a-service-task)
and [Hermes guide](https://hardrails.github.io/steward/guides/hermes-agent/#authorize-and-run-one-exact-hermes-task)
show signing, verification, dispatch, recovery, result handling, and offline audit.

### Choose an agent release without a hosted registry

A curator can sign an offline catalog of exact publisher-signed releases. The
catalog presents useful outcomes and the signed capsule data needed for selection:
resources, capabilities, validity, state, services, and exact companion artifact
identities. Its signature authenticates descriptive inventory; it does not grant
deployment authority or prove a skill is safe.

```console
stewardctl agent-catalog verify \
  -in agents.catalog.dsse.json \
  -public-key curator.public.pem \
  -key-id curator-key-id

stewardctl agent-catalog search \
  -in agents.catalog.dsse.json \
  -public-key curator.public.pem \
  -key-id curator-key-id \
  -query capability:inference
```

Read the
[offline agent catalog guide](https://hardrails.github.io/steward/guides/agent-catalog/)
for issuing, transferring, comparing, and pinning catalog revisions.

### From a signed release to offline proof

A publisher-signed agent release describes useful work in operator terms while
binding the exact workload capsule, offline image archive, deterministic canary,
qualification evidence digest, and known limitations. It is descriptive metadata,
not tenant, node, image-import, or task authority.

Authenticate the publisher key separately, then verify both the release and the
transferred archive:

```console
stewardctl agent-release verify \
  -in hermes-workspace-audit.release.dsse.json \
  -public-key publisher.public.pem \
  -key-id publisher-key-id \
  -archive hermes-agent-adapter.tar
```

Steward's activation contract then follows a fixed
choose/configure/preflight/activate/canary/prove/monitor journey. The default
canary flow derives its signing challenge from the real admission response, so the
tenant private key stays off-node. Generated artifacts and state checkpoints are
retained in an owner-only append-only workspace, and the final proof correlates the
exact result with Executor, Gateway, and controller-witness evidence for offline
review. Executor signs one activation marker after read-only admission preflights
and before the admission-allow receipt or host mutation. It signs another after
Steward verifies Gateway's terminal evidence, creating a receipt-ordered causal
link that does not depend on comparing service clocks. A proof manifest is a
correlation record; its signed companions and pinned public keys still require
independent verification.

The built-in Hermes recipe currently requires a dedicated host whose signed site
policy contains exactly one tenant. It uses persistent Docker state, which has no
portable hard byte or inode quota, and it uses the explicitly enabled host-local
administrator path for node-local admission. Steward still supports stateless
multi-tenant workloads on a shared host; this specific activation recipe does not.

The concrete workflow is:

1. `stewardctl activation create` verifies and snapshots the release, policy,
   intent, archive, and pre-admission controller witness.
2. `stewardctl activation run` imports, records an activation-begin marker,
   admits, starts, and pauses for a tenant-signed canary task derived from the
   real admission.
3. `stewardctl activation attach -kind canary-task` adds that owner-only bundle;
   rerunning advances through the deterministic Hermes result, verifies Gateway
   receipts, and records an Executor activation checkpoint.
4. `stewardctl activation attach -kind final-witness` adds a controller evidence
   export that covers that checkpoint; rerunning writes the proof.
5. `stewardctl activation verify` authenticates the copied workspace and signed
   evidence entirely offline. `activation status` is only an unverified local
   progress view.

Runs are resumable against retained checkpoints while the applicable deadline
remains open. The canary uses one absolute deadline anchored to its
`canary_authorized` checkpoint; retries do not reset it, and expiry becomes sticky
`action_required`. Invalid canary authorization, terminal canary failure, and
invalid or conflicting retained evidence are also sticky. Recovery requires
stopping and destroying the failed workload, then using a new activation ID and
an instance generation greater than the failed activation.

Read [Activate a qualified Hermes release](https://hardrails.github.io/steward/guides/agent-activation/)
for the exact commands, handoff files, runtime overrides, threat boundaries,
failure handling, and proof limits.

To apply the same closed activation contract to an ordered remote fleet, follow
[Proof-carrying fleet rollout](https://hardrails.github.io/steward/guides/fleet-rollout/).
The image must already be imported on every target. Each invocation advances only
the current canary or later batch. The initial invocation signs the exact plan;
each later invocation signs a chained promotion that binds the preceding batch's
passed evidence before it signs any command for the next batch.

`steward-mcp` exposes bounded Steward Control fleet operations, Executor lifecycle
operations, or both to a local Model Context Protocol (MCP) client over standard
input and output. Starting it directly waits for an MCP client; this example
enables only the local node tools:

```bash
sudo steward-mcp -node-url http://127.0.0.1:8090 \
  -token-file /etc/steward/executor-token
```

Fleet tools require a scoped control operator token and the controller CA; they do
not expose operator or enrollment secret issuance. Optional task tools require a loopback Gateway credential and a dedicated
owner-only result directory. The task signing key still stays off-node; MCP can
submit only a pre-signed exact request. These bearer tokens are privileged
credentials and must not be exposed to an untrusted agent or MCP client.

MCP is a standard tool interface for AI clients. See the
[installation guide](https://hardrails.github.io/steward/getting-started/),
[MCP setup](https://hardrails.github.io/steward/guides/mcp/), and
[capability setup](https://hardrails.github.io/steward/guides/positive-capabilities/).

## Why Steward exists

An agent combines untrusted software, credentials, network access, persistent
state, and the ability to act on other systems. Running it directly on a server,
or giving the agent a Docker socket, lets one compromise expose every capability.
Steward separates those capabilities:

| Risk or requirement | Steward control |
| --- | --- |
| Untrusted image input | The offline importer verifies the signed workload profile and site policy, checks every referenced Open Container Initiative (OCI) blob, removes tags and unrelated archive content, and gives Docker only the sanitized image. Executor runs the exact local config digest and rejects image-declared volumes. The operator authenticates build provenance separately. |
| Deployment authority | A publisher-signed workload profile, site policy, and tenant/node-bound instance request must all permit the workload. |
| Stale commands | Durable policy and generation records reject policy rollback and commands for replaced instances. Read-only commands do not change lifecycle ordering. |
| Multiple tenants on one host | Each workload has its own gVisor sandbox, per-workload resource limits, host and tenant aggregate memory/CPU/PID reservations, workload-count caps, command authority, and, when needed, private Docker network. Durable admission, command-fence, journal, and receipt records bind the tenant ID. Persistent Docker volumes are disabled on shared hosts because the local volume driver does not provide portable hard byte or inode quotas. |
| Model, service, and API access | Site policy grants named inference routes, model aliases, service IDs, credential-brokered connector IDs, and HTTP(S) egress routes. A tenant task key can be scoped to one service and sign a short-lived permit for one exact service request; Gateway records authorization before dispatch. The private key is not a Steward node input and is never given to the agent. For a stronger connector boundary, signed tenant policy can require Authorized Effects: explicit instance intent, no generic egress, connector-scoped action keys, an optional multi-party threshold over one exact request, durable spend before DNS, and format-5 or format-6 signed evidence. Non-borrowing receipt budgets prevent one tenant from consuming another tenant's evidence allocation. |
| Remote nodes | Authenticated outbound polling works behind network address translation (NAT) and inbound firewalls. Tenant-signed commands include a short validity window, instance generation, and sequence number so Executor can reject replay. |
| Audit evidence | Executor writes signed, hash-linked lifecycle receipts. It can publish bounded signed deltas to the customer-owned controller, which retains a last-good checkpoint or sticky rollback/equivocation finding and signs portable exports with a separate witness key. Gateway writes a separate signed chain for connector calls and tenant-signed service-task authorization, dispatch, and terminal observation. Permit-backed records bind the authority key or canonical signer set, approval threshold, permit, operation policy, and exact request digest. Receipts omit raw prompts, request bodies, and response or result bodies. `stewardctl` verifies node chains and controller exports offline. |
| Disconnected operation | Static binaries, local public-key infrastructure (PKI), offline image import, and local model gateways do not require a public network service after transfer. |
| Vendor independence | Public OpenAPI and uplink contracts have no private runtime dependency. |

Steward is for platform and security teams running agents on customer-controlled
Linux, regulated or sovereign operators, and control-plane builders that need a
small public fleet and node contract.

Steward is not an agent framework, inference server, hosted control-plane service,
or general-purpose container orchestrator. Model serving remains a separate
operator responsibility behind an OpenAI-compatible endpoint.

Steward's differentiator is not a claim that it can detect every prompt injection.
Browser origin isolation, model screening, planner information-flow controls, and
application-protocol firewalls are useful additional layers. Steward supplies a
framework-independent enforcement path for unmodified containerized agents: local
signed admission, tenant-pinned connector authority, exact one-use request permits,
spend-before-network durability, credentials outside the workload, and offline
permit-to-terminal verification without a required hosted service.

## Components and trust boundaries

```text
  tenant/site signer -- exact signed command --> steward-control
                                                 ^
                                                 | node-initiated HTTPS
                                                 v
  +------------------- Steward node -------------------+
  | steward | steward-executor | steward-gateway       |
  | state   | admission+Docker | inference+connectors  |
  +-----------------------|-----------------------------+
                          v
              gVisor agent <-> trusted relay
                                  |
           approved inference + connectors + HTTP(S) routes
```

A Linux release contains seven static binaries:

- `steward-control` provides the optional self-hosted tenant, enrollment,
  inventory, signed-command delivery, and separately keyed evidence-witness
  plane without holding tenant private keys or Docker authority. Its embedded
  `/console/` is a read-only view of bounded control API metadata, not a mutation
  or signing surface.
- `steward` tracks lifecycle state and provides the generic outbound uplink.
- `steward-executor` verifies admission and is the only long-running Steward
  service with Docker-group membership.
- `steward-gateway` holds upstream credentials and enforces inference, service,
  exact connector-operation, and HTTP(S) egress grants.
- `steward-relay` is a fixed-destination companion inside one workload network.
- `stewardctl` manages controller TLS, tenants, operators, enrollment, command
  delivery, evidence status, signed witness export, and offline verification;
  keys and policy; outcome-led signed agent releases; exact-request connector and
  service-task permits; generic task lifecycle and recovery; OCI import; node
  evidence; and local node actions.
- `steward-mcp` exposes bounded fleet and node operations plus optional pre-signed
  task lifecycle tools over MCP stdio.

`steward-control`, `steward`, `steward-executor`, and `steward-gateway` run as
separate services and Unix users when deployed. The node installer enables only
the three node services; the controller has its own explicit installation path.
On a node, Executor must be the Docker group's only member because Docker socket
access is root-equivalent. The controller, agent containers, supervisor,
Gateway, and MCP server never receive the Docker socket.
`sudo stewardctl image import` is a deliberate one-shot exception: it verifies and
sanitizes one bounded image archive, then connects directly to Docker to load it.
The root-only relay-image build helper also invokes Docker during node setup.

[Read the architecture](https://hardrails.github.io/steward/concepts/architecture/) ·
[Read the security model](https://hardrails.github.io/steward/concepts/security-model/) ·
[Review the public APIs](https://hardrails.github.io/steward/reference/api/)

## Default workload policy

Executor requires Docker to advertise gVisor's `runsc` runtime. Every admitted
agent has:

- an immutable image reference verified against its local config digest;
- gVisor isolation and fixed UID/GID `65532:65532`;
- all Linux capabilities dropped and `no-new-privileges` enabled;
- a read-only root filesystem and bounded temporary filesystems;
- explicit per-workload memory, swap, CPU, and PID limits, plus aggregate
  memory, CPU, PID, and workload-count caps for the host and each tenant;
- bounded local logs, request bodies, and response bodies;
- no host mount, device, published port, Docker socket, or caller-defined
  environment;
- `network=none`, unless a signed inference, service, connector, or egress
  capability needs the per-instance relay;
- an isolated bridge with no host gateway for inference, service, connector, or
  egress;
- persistent state only through a Steward-owned volume for one tenant and logical
  workload, and only after the operator enables the documented dedicated-host
  compatibility mode; and
- exact drift checks before lifecycle actions, plus periodic reconciliation.

Docker Engine 28 or newer is required for capability networks because Steward uses
Docker's isolated bridge gateway mode. Workloads with `network=none` do not depend
on that feature.

These controls reduce authority; they do not make a shared host equivalent to
separate hardware. Host root, Docker, gVisor, the Linux kernel, and operator
configuration remain trusted. See the [security model](https://hardrails.github.io/steward/concepts/security-model/)
for residual risks such as kernel compromise, host administrators, and shared
hardware side channels.

## What is different

Sandboxes, lifecycle APIs, self-hosted fleet controllers, egress allowlists, and
credential injection are necessary but widely available. Steward connects them into a portable
authorization-to-enforcement record. Local keys and policy identify the artifact,
tenant, instance, and capability. An off-node tenant key can authorize one exact
service request, while separate optional action keys can jointly authorize one
exact connector request. Gateway spends either authority durably before the external
effect. Signed receipts retain the permit, request digest, policy, task identity,
and observed outcome linkage for offline audit.

Among the products reviewed in the dated
[market analysis](https://hardrails.github.io/steward/product/market-analysis/), none
documents the same combination of customer-operated air-gapped nodes,
publisher-signed artifacts, site-root-signed policy, authenticated tenant intent,
service-scoped off-node task keys,
exact-request dispatch, durable node-local replay control, and offline-verifiable
authorization-to-outcome receipts. This is a comparison of public documentation,
not a certification or a claim that another product cannot add these controls.

Connector credential isolation has a precise boundary: Gateway does not hand the
configured credential to the workload and aborts an upstream response if any header
or decoded body chunk contains that exact value. It does not detect encoded or
transformed credentials, private-origin disclosure, or application-specific secret
fields. Operators must still use a narrow trusted upstream. Tenant receipt budgets
isolate ledger bytes; they do not isolate the shared disk, synchronous writes, or a
hostile host root.

This claim is intentionally limited. Service-task dispatch is node-local
at-most-once only while the same Gateway ledger and epoch are retained; it is not
fleet-wide or upstream exactly-once delivery. The run ID is supplied by the
untrusted agent service. Receipts show what Steward authorized, dispatched, and
observed, not whether the agent did useful work. They do not prove prompt meaning,
model honesty, semantic tool behavior, or an uncompromised host. Read
[the product position](https://hardrails.github.io/steward/product/positioning/) and
[market analysis](https://hardrails.github.io/steward/product/market-analysis/).

## Hermes Agent and OpenClaw

Steward includes a qualified, source-built adapter definition for
[Hermes Agent](https://github.com/NousResearch/hermes-agent) at exact upstream commit
`095b9eed3801c251796df93f48a8f2a527ff6e70`. The retained qualification applies to
`linux/amd64`; other platforms require a separate qualification run. The hardened image runs as
`65532:65532`, fixes inference through `http://steward-relay:8080/v1`, and exposes
only negotiation, health, run submission, and run-status operations on service port
`8766`. Run event streams are not exposed.

Qualification runs two signed skills as real Hermes work under gVisor. The harness checks
the bounded `steward.workspace-audit` inventory, changed persisted workspace state,
restarted the container, opened a fresh session, and required the changed result.
For `steward.connector-work`, Hermes had to discover the native skill index entry,
load the exact signed `SKILL.md` with `skill_view`, and follow its terminal command.
The integration gate demonstrated one authenticated upstream effect, replay and
undeclared-operation denial, fixed-material secret scans, state purge, and separate
Executor and Gateway receipt chains. The task-enabled service workflow additionally
uses a tenant key scoped to `hermes-api`, signs five exact requests, dispatches them
through the generic task lifecycle, and checks each format-4 authorization,
dispatch, and terminal chain. The retained qualification evidence applies only to
the pinned source, adapter, and
documented inference, service, state, connector, task, and skill behavior. The
official upstream image remains inadmissible
because it starts as root and declares a volume.

Linux releases include the interactive or non-interactive builder and the
`hermes-steward-acceptance` disposable-host harness. The builder can fetch the exact
pinned commit or use a transferred source checkout. Steward does not redistribute a
prebuilt Hermes OCI archive because dependency and base-image notices are incomplete.
Operators build, qualify, inspect, and sign their exact archive.

Persistent state still requires the explicit dedicated single-tenant host mode for
volumes without enforced byte or inode quotas. Raw TCP/UDP, host mounts, arbitrary
secret injection, privileged mode, Docker access, and undeclared ports remain
unavailable.

[OpenClaw](https://github.com/openclaw/openclaw) remains a layout contract only. Its
official image is not a qualified, directly runnable Steward adapter.

- [Build and run the Hermes Agent adapter](https://hardrails.github.io/steward/guides/hermes-agent/)
- [OpenClaw adapter contract](https://hardrails.github.io/steward/guides/openclaw/)
- [Current limitations](https://hardrails.github.io/steward/limitations/)

## Platforms and independence

Production nodes are systemd Linux on `amd64` or `arm64`. The installer uses DEB
for Debian/Ubuntu families, RPM for common RPM families, and a systemd archive for
other distributions that the operator validates. CI builds and inspects packages
on Ubuntu 24.04; it does not run node acceptance on every listed distribution.
macOS builds are for development. Windows, macOS,
BSD, Alpine/OpenRC, and other non-systemd systems are not Executor node targets.

See the [platform matrix](https://hardrails.github.io/steward/reference/platform-support/).

Steward's Go module uses only the Go standard library:

```console
$ go list -m all
github.com/hardrails/steward
```

The source tree separately has frontend-maintenance dependencies: the embedded
operator console's lockfile pins React and Vite, while its reviewed production
assets are committed and embedded in `steward-control`. Normal and air-gapped Go
builds do not run npm, and the installed service needs neither Node.js nor a CDN.
CI uses Node.js 24 LTS to audit, check, rebuild, and compare the committed
distribution byte for byte.

Its public contracts are hand-written and CI-linted:

- [`openapi/steward.v1.yaml`](openapi/steward.v1.yaml)
- [`openapi/steward-executor.v1.yaml`](openapi/steward-executor.v1.yaml)
- [`openapi/steward-control.v1.yaml`](openapi/steward-control.v1.yaml)

An operator can clone this repository alone, audit it, and build all seven binaries
without access to private source or infrastructure.

## Documentation

- [Install and enroll](https://hardrails.github.io/steward/getting-started/)
- [Activate a qualified Hermes release](https://hardrails.github.io/steward/guides/agent-activation/)
- [Operate a workload](https://hardrails.github.io/steward/guides/workload-lifecycle/)
- [Install without public network access](https://hardrails.github.io/steward/guides/air-gapped/)
- [Configure signed admission](https://hardrails.github.io/steward/guides/signed-admission/)
- [Inspect a fleet in the read-only console](https://hardrails.github.io/steward/guides/operator-console/)
- [Authorize exact external effects](https://hardrails.github.io/steward/guides/authorized-effects/)
- [Store and distribute Gateway credentials](https://hardrails.github.io/steward/guides/secrets/)
- [Broker authenticated API operations](https://hardrails.github.io/steward/guides/connectors/)
- [Upgrade and roll back](https://hardrails.github.io/steward/guides/upgrades/)
- [Configuration reference](https://hardrails.github.io/steward/reference/configuration/)
- [FAQ](https://hardrails.github.io/steward/faq/)

Machine-oriented documentation is available at
[`llms.txt`](https://hardrails.github.io/steward/llms.txt).

## Build and contribute

Go 1.24 or newer is required to build from source. Published Linux binaries are
static and do not require Go.

```console
go build ./...
go vet ./...
go test ./...
```

Read [`AGENTS.md`](AGENTS.md) before changing code. It documents the invariants
enforced by review and CI. Steward is licensed under [Apache-2.0](LICENSE).
