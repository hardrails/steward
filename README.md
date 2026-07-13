# Steward

**Open-source admission and execution software for isolated AI agents on Linux.**

[![CI](https://github.com/hardrails/steward/actions/workflows/ci.yml/badge.svg)](https://github.com/hardrails/steward/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hardrails/steward?display_name=tag)](https://github.com/hardrails/steward/releases/latest)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-f2532d)](https://hardrails.github.io/steward/)
[![License](https://img.shields.io/github/license/hardrails/steward)](LICENSE)

Steward turns a Docker and gVisor Linux server into a hardened agent node. gVisor
is a userspace-kernel sandbox that reduces direct exposure to the host kernel.
Steward is for operators who need to decide locally which immutable workload may
run, for which tenant, and with which limited capabilities.

The optional signed-admission path verifies three inputs: a publisher-signed
workload profile that fixes the image identity and maximum capabilities; an
operator-signed site policy; and an instance request bound to one tenant, node,
and generation. A generation is an increasing version number for a logical
instance. It prevents a delayed command for an older instance from acting on its
replacement. Steward records each accepted host mutation in a signed receipt
chain that can be verified without a network connection.

Steward is independent of any control plane. It has no build-time or runtime
dependency on a private package, API, account, or hosted service.

## Install on Linux

Docker must already be installed. The guided installer detects DEB, RPM, and other
systemd Linux hosts. It can install gVisor after asking for approval. That optional
online step fetches gVisor binaries and checksum files from Google-hosted gVisor
release storage. Its default `latest` selector can change. For a reproducible
installation, pin `--gvisor-version` to a dated gVisor release or use the verified
offline path.

```bash
curl -fsSL https://github.com/hardrails/steward/releases/latest/download/install-steward.sh | sudo bash
```

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
sudo /usr/local/libexec/steward/node-preflight
systemctl is-active steward steward-executor steward-gateway
```

For a first workload, follow the
[loopback evaluation lifecycle](https://hardrails.github.io/steward/guides/workload-lifecycle/)
or the [signed-admission procedure](https://hardrails.github.io/steward/guides/signed-admission/).
Both return a `runtime_ref` that identifies the admitted workload.

After admission, replace `executor-DIGEST` with the returned `runtime_ref` to query
the workload through the bearer-protected loopback API:

```bash
sudo stewardctl node status --node-url http://127.0.0.1:8090 \
  --token-file /etc/steward/executor-token --runtime-ref executor-DIGEST
```

`steward-mcp` exposes the same bounded Executor lifecycle operations to a local
Model Context Protocol (MCP) client over standard input and output. Starting it
directly waits for an MCP client:

```bash
sudo steward-mcp -node-url http://127.0.0.1:8090 \
  -token-file /etc/steward/executor-token
```

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
| Model and API access | Site policy grants named inference routes, model aliases, service IDs, credential-brokered connector IDs, and HTTP(S) egress routes. A connector maps a logical operation to one operator-owned origin, method, path, credential, and call budget. Gateway gives the configured credential only to that upstream operation, not directly to the workload. Explicit non-borrowing receipt budgets prevent one tenant from consuming another tenant's evidence allocation. The agent gets no general network route. |
| Remote nodes | Authenticated outbound polling works behind network address translation (NAT) and inbound firewalls. Tenant-signed commands include a short validity window, instance generation, and sequence number so Executor can reject replay. |
| Audit evidence | Executor writes signed, hash-linked lifecycle receipts. Gateway writes a separate signed chain for connector authorizations and outcomes. `stewardctl` verifies both offline. |
| Disconnected operation | Static binaries, local public-key infrastructure (PKI), offline image import, and local model gateways do not require a public network service after transfer. |
| Vendor independence | Public OpenAPI and uplink contracts have no private runtime dependency. |

Steward is for platform and security teams running agents on customer-controlled
Linux, regulated or sovereign operators, and control-plane builders that need a
small public node contract.

Steward is not an agent framework, inference server, hosted control plane, or
general-purpose container orchestrator. Model serving remains a separate operator
responsibility behind an OpenAI-compatible endpoint.

## Components and trust boundaries

```text
  local CLI / MCP or independent remote control plane
                         |
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

A Linux release contains six static binaries:

- `steward` tracks lifecycle state and provides the generic outbound uplink.
- `steward-executor` verifies admission and is the only long-running Steward
  service with Docker-group membership.
- `steward-gateway` holds upstream credentials and enforces inference, service,
  exact connector-operation, and HTTP(S) egress grants.
- `steward-relay` is a fixed-destination companion inside one workload network.
- `stewardctl` manages keys, policy, OCI import, evidence, and local node actions.
- `steward-mcp` exposes bounded node operations over MCP stdio.

`steward`, `steward-executor`, and `steward-gateway` run as separate systemd
services and Unix users. Only Executor joins the Docker group. Agent containers,
the supervisor, Gateway, and MCP server never receive the Docker socket.
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

Sandboxes, lifecycle APIs, egress allowlists, and credential injection are necessary
but widely available. Steward connects them into a portable
authorization-to-enforcement record: local keys and policy identify the artifact,
tenant request, and exact connector operation; Gateway sends the configured
credential only to that upstream operation, the node durably spends bounded
connector calls before external effects, rejects stale authority, and binds
effective route policy into signed receipts.

Connector credential isolation has a precise boundary: Gateway does not hand the
configured credential to the workload, but it does relay bounded upstream response
bodies and non-Steward headers. Operators must use an upstream operation that does
not reflect authentication material. Tenant receipt budgets isolate ledger bytes;
they do not isolate the shared disk, synchronous writes, or a hostile host root.

This claim is intentionally limited. Receipts show what Steward accepted and which
host mutations it recorded. They do not prove prompt meaning, model honesty,
semantic tool behavior, or an uncompromised host. Read
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

Qualification ran two signed skills as real Hermes work under gVisor. It verified
the bounded `steward.workspace-audit` inventory, changed persisted workspace state,
restarted the container, opened a fresh session, and required the changed result.
For `steward.connector-work`, Hermes had to discover the native skill index entry,
load the exact signed `SKILL.md` with `skill_view`, and follow its terminal command.
The integration gate proved one authenticated upstream effect, replay and
undeclared-operation denial, fixed-material secret scans, state purge, and separate
Executor and Gateway connector receipt chains. The proof applies only to the pinned
source, adapter, and documented inference, service, state, connector, and skill
behavior. The official upstream image remains inadmissible because it starts as
root and declares a volume.

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

Steward currently uses only the Go standard library:

```console
$ go list -m all
github.com/hardrails/steward
```

Its public contracts are hand-written and CI-linted:

- [`openapi/steward.v1.yaml`](openapi/steward.v1.yaml)
- [`openapi/steward-executor.v1.yaml`](openapi/steward-executor.v1.yaml)

An operator can clone this repository alone, audit it, and build all six binaries
without access to private source or infrastructure.

## Documentation

- [Install and enroll](https://hardrails.github.io/steward/getting-started/)
- [Operate a workload](https://hardrails.github.io/steward/guides/workload-lifecycle/)
- [Install without public network access](https://hardrails.github.io/steward/guides/air-gapped/)
- [Configure signed admission](https://hardrails.github.io/steward/guides/signed-admission/)
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
