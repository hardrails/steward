# Steward

**Open-source sovereign admission and execution runtime for AI agents on Linux.**

[![CI](https://github.com/hardrails/steward/actions/workflows/ci.yml/badge.svg)](https://github.com/hardrails/steward/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hardrails/steward?display_name=tag)](https://github.com/hardrails/steward/releases/latest)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-f2532d)](https://hardrails.github.io/steward/)
[![License](https://img.shields.io/github/license/hardrails/steward)](LICENSE)

Steward turns a Docker-and-gVisor Linux server into a hardened execution node that
admits immutable agent workloads under local authority. It is designed for
enterprise, regulated, defense, critical-infrastructure, and sovereign operators
who cannot accept “the platform said it was allowed” as their only evidence.

The hard question is no longer merely *can this agent be sandboxed?* It is: **which
artifact was authorized for which tenant, under which local policy, and what did
the node actually enforce?** When its opt-in signed admission path is configured,
Steward v1.3 uses signed profile capsules,
site-root policy, tenant-bound instance intents, rollback fences, a crash-detecting
operation journal, and signed receipts that can be verified offline.

Steward is control-plane neutral and independently useful. It has **no build-time or
runtime dependency on any private system**.

## Install on a Linux server

Docker must already be installed. Paste one command; the interactive installer
detects DEB, RPM, or generic systemd hosts and can install gVisor with your approval:

```bash
curl -fsSL https://github.com/hardrails/steward/releases/latest/download/install-steward.sh | sudo bash
```

The installer asks whether to enroll and activate the node or only stage the
software. For automation and air-gapped installation, see the
[installation guide](https://hardrails.github.io/steward/getting-started/).

> Piping a script to a root shell trusts GitHub's TLS delivery and the release
> account. High-assurance operators should download, inspect, and verify the
> release files before running them; the [air-gapped guide](https://hardrails.github.io/steward/guides/air-gapped/)
> documents that path.

After installation, local operators can use either interface against the same
loopback enforcement API:

```bash
sudo stewardctl node status --node-url http://127.0.0.1:8090 \
  --token-file /etc/steward/executor-token --runtime-ref executor-<digest>

sudo steward-mcp -node-url http://127.0.0.1:8090 \
  -token-file /etc/steward/executor-token
```

See the [MCP setup](https://hardrails.github.io/steward/guides/mcp/) and
[positive-capability setup](https://hardrails.github.io/steward/guides/positive-capabilities/).

## The problem Steward solves

AI agents are unusually risky workloads. They combine untrusted or frequently
changing software, powerful credentials, external communications, durable memory,
and actions that can affect other systems. Running them directly on a server—or
giving an orchestration process the Docker socket—collapses too many trust
boundaries into one compromise domain.

Steward separates those concerns:

| Concern | Steward's answer |
| --- | --- |
| Untrusted agent images | A separate Executor admits only digest-pinned OCI images and runs them with Docker + gVisor. |
| Who authorized this deployment? | A publisher-signed capsule is intersected with site-root-signed policy and a tenant/node-bound instance intent. |
| Stale or replaced authority | Durable policy-epoch and `(tenant, instance)` generation fences reject rollback. |
| Auditor independence | Executor emits signed, hash-linked, node-local enforcement receipts; `stewardctl` verifies them without a network. |
| Multiple tenants on one host | Tenant-labelled containers, per-tenant capacity ceilings, per-instance internal networks, lineage-scoped volumes, and a gVisor sandbox per workload. |
| Agents need models and services | Per-instance relays provide one policy-approved inference route and one declared service port without exposing an upstream credential or general network. |
| Humans and agents need operations | The same bounded node contract is available through HTTP, `stewardctl node`, and an MCP 2025-11-25 stdio server. |
| Remote fleet operations | Outbound-only, replay-fenced command channels work behind NAT and inbound firewalls. |
| Host compromise surface | The lifecycle supervisor never receives the Docker socket; workloads never receive it either. |
| Sovereign and disconnected sites | Static binaries, offline release artifacts, operator-owned PKI, no phone-home dependency, and reproducible public source. |
| Vendor independence | Public OpenAPI contracts and zero private package or service dependencies. |

## Who Steward is for

- Platform and security teams operating agent fleets on customer-controlled Linux.
- Regulated or sovereign organizations that require local authority, auditability,
  and an air-gapped installation path.
- Control-plane builders that need a small, stable node contract instead of a
  vendor-specific runtime SDK.
- Agent projects such as Hermes Agent and OpenClaw that need a hardened deployment
  boundary beneath them.

Steward is not an inference server, an agent framework, a hosted control plane, or
a general-purpose container orchestrator. It brokers an operator-selected,
OpenAI-compatible inference service but does not operate the model server itself.

## How it is built

```text
  local CLI / MCP or independent remote control plane
                         |
                         v
  +------------------- Steward node -------------------+
  | steward | steward-executor | steward-gateway       |
  | state   | admission+Docker | credentials+services  |
  +-----------------------|-----------------------------+
                          v
              gVisor agent <-> trusted relay
                                  |
                     OpenAI-compatible inference
```

The release contains six small, static binaries:

- `steward` is the lightweight lifecycle supervisor and generic uplink client.
- `steward-executor` is the narrow Docker/gVisor admission and execution boundary.
- `stewardctl` creates and verifies offline keys, signed capsules, site policies,
  and receipt chains, and operates a local node directly.
- `steward-gateway` owns inference credentials and authenticated local service ingress.
- `steward-relay` is the fixed-destination, per-instance companion inside the
  private runtime network.
- `steward-mcp` exposes bounded node operations as MCP tools over stdio.

They ship as one system. `steward` and `steward-executor` run as different Unix
users and systemd services; `stewardctl` is an offline CLI. Only Executor joins the
Docker group. The package supplies hardened units, configuration validation,
preflight, atomic version activation, and rollback utilities.

[Read the architecture](https://hardrails.github.io/steward/concepts/architecture/) ·
[Read the security model](https://hardrails.github.io/steward/concepts/security-model/) ·
[Review the public APIs](https://hardrails.github.io/steward/reference/api/)

## Hardened defaults

Executor refuses to start unless Docker advertises gVisor's `runsc` runtime. Every
admitted workload has:

- an immutable `@sha256` image reference;
- mandatory memory, CPU, PID, host-wide, and per-tenant limits;
- gVisor isolation, UID/GID `65532`, and every Linux capability dropped;
- `no-new-privileges`, a read-only root filesystem, and bounded tmpfs;
- no general egress, host mount, device, Docker socket, or caller-supplied environment;
- optional state only through an Executor-derived tenant-lineage volume;
- optional inference/service only through an internal network and hardened relay;
- bounded request bodies and log responses; and
- drift detection before any lifecycle operation.

These defaults are deliberately restrictive. Security-sensitive capabilities must
become narrow, explicit grants rather than ambient container privileges.

## What is differentiated—and what is not

gVisor, microVMs, lifecycle APIs, egress allowlists, secret injection, snapshots,
and JSON audit logs are important, but they are increasingly standard across agent
sandbox products. Steward's v1.3 wedge is the **authorization-to-enforcement
receipt chain**: operator-owned keys and policy, tenant-bound deployment intent,
immutable artifact admission, replay fencing, and offline-verifiable node receipts.

This is deliberately a bounded claim. Receipts record what Steward accepted and
enforced; they are not prompt transcripts and do not prove model honesty, semantic
tool behavior, or an uncompromised host. Read [why Steward exists](https://hardrails.github.io/steward/product/positioning/)
and the [dated market analysis](https://hardrails.github.io/steward/product/market-analysis/).

## Hermes Agent and OpenClaw

Steward is agent-agnostic and can admit OCI images for projects such as
[Hermes Agent](https://github.com/NousResearch/hermes-agent) and
[OpenClaw](https://github.com/openclaw/openclaw).

**v1.3 compatibility boundary:** Steward supplies persistent state, one
OpenAI-compatible inference route, and one declared private service through narrow
grants. Images that require arbitrary Internet egress, host mounts, raw secrets, a
Docker socket, privileged mode, or undeclared ports remain incompatible by design.

- [Hermes Agent compatibility guide](https://hardrails.github.io/steward/guides/hermes-agent/)
- [OpenClaw compatibility guide](https://hardrails.github.io/steward/guides/openclaw/)
- [Current limitations and capability roadmap](https://hardrails.github.io/steward/limitations/)

## Platform support

Production nodes are systemd Linux on `amd64` or `arm64` with Docker installed.
The guided installer selects:

- DEB for Debian and Ubuntu families;
- RPM for RHEL, Rocky, Alma, Fedora, Amazon Linux, Oracle Linux, and SUSE families;
- a universal archive for other systemd distributions.

macOS release archives are for development; Windows is not a v1.3 release target.
Neither is an Executor node platform. See the
[platform matrix](https://hardrails.github.io/steward/reference/platform-support/).

## Verifiable independence

Steward uses the Go standard library and has no third-party Go modules today:

```console
$ go list -m all
github.com/hardrails/steward
```

Its public contracts are hand-written and CI-linted:

- [`openapi/steward.v1.yaml`](openapi/steward.v1.yaml)
- [`openapi/steward-executor.v1.yaml`](openapi/steward-executor.v1.yaml)

An operator can clone this repository alone, audit it, build all three binaries, and run
them without access to vendor-private code or infrastructure.

## Documentation

The [Steward node field manual](https://hardrails.github.io/steward/) is organized
by task:

- [Install and enroll](https://hardrails.github.io/steward/getting-started/)
- [Operate workload lifecycle](https://hardrails.github.io/steward/guides/workload-lifecycle/)
- [Deploy without internet access](https://hardrails.github.io/steward/guides/air-gapped/)
- [Upgrade and roll back](https://hardrails.github.io/steward/guides/upgrades/)
- [Production deployment](https://hardrails.github.io/steward/production-deployment/)
- [Configuration reference](https://hardrails.github.io/steward/reference/configuration/)
- [FAQ](https://hardrails.github.io/steward/faq/)

Machine-oriented documentation is available at
[`llms.txt`](https://hardrails.github.io/steward/llms.txt).

## Build and contribute

Go 1.24 or newer is required to build from source; published Linux binaries are
static and do not require Go.

```console
go build ./...
go vet ./...
go test ./...
```

Read [`AGENTS.md`](AGENTS.md) before changing code. It documents the security and
compatibility invariants enforced by review and CI. Steward is licensed under
[Apache-2.0](LICENSE).
