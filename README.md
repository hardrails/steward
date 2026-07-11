# Steward

**Open-source node runtime for isolated, multi-tenant AI agent workloads on Linux.**

[![CI](https://github.com/hardrails/steward/actions/workflows/ci.yml/badge.svg)](https://github.com/hardrails/steward/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hardrails/steward?display_name=tag)](https://github.com/hardrails/steward/releases/latest)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-f2532d)](https://hardrails.github.io/steward/)
[![License](https://img.shields.io/github/license/hardrails/steward)](LICENSE)

Steward turns a Docker-and-gVisor Linux server into a hardened execution node that
a remote control plane can manage without receiving Docker access. It is designed
for enterprise, regulated, defense, critical-infrastructure, and sovereign
operators who need to run untrusted agent images and configuration on infrastructure
they control—including disconnected environments.

Steward is control-plane neutral and independently useful. Railyard is a first-party
proprietary control plane for Steward fleets, but Steward has **no build-time or
runtime dependency on Railyard or any other private system**.

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
| Multiple tenants on one host | Tenant-labelled containers, per-tenant capacity ceilings, no shared host mounts, and a sandbox per workload. |
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
a general-purpose container orchestrator. Inference remains a separate service,
typically exposed through an operator-selected OpenAI-compatible gateway.

## How it is built

```text
  Independent control plane (Railyard or another implementation)
                 |  outbound HTTPS, desired state, evidence
                 v
  +---------------- Steward node ----------------+
  | steward              steward-executor         |
  | lifecycle + uplink   Docker authority boundary|
  | no Docker socket              |               |
  +-------------------------------|---------------+
                                  v
                     Docker -> gVisor -> agent OCI image
                                  |
                           inference is external
```

The release contains two intentionally separate binaries:

- `steward` is the lightweight lifecycle supervisor and generic uplink client.
- `steward-executor` is the narrow Docker/gVisor admission and execution boundary.

They ship as one system but run as different Unix users and systemd services. Only
Executor joins the Docker group. The package supplies hardened units, configuration
validation, preflight, atomic version activation, and rollback utilities.

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
- no network, host mount, device, Docker socket, or caller-supplied environment;
- bounded request bodies and log responses; and
- drift detection before any lifecycle operation.

These defaults are deliberately restrictive. Security-sensitive capabilities must
become narrow, explicit grants rather than ambient container privileges.

## Hermes Agent and OpenClaw

Steward is agent-agnostic and can admit OCI images for projects such as
[Hermes Agent](https://github.com/NousResearch/hermes-agent) and
[OpenClaw](https://github.com/openclaw/openclaw).

**v0.1 compatibility boundary:** Steward can validate image admission and exercise
container lifecycle behavior under its hardened policy. Full connected operation is
not yet available because these agents require some combination of outbound network,
secrets, persistent state, and listening ports—capabilities Executor v0.1 does not
grant. Steward does not recommend bypassing that boundary.

- [Hermes Agent compatibility guide](https://hardrails.github.io/steward/guides/hermes-agent/)
- [OpenClaw compatibility guide](https://hardrails.github.io/steward/guides/openclaw/)
- [Current limitations and planned grant model](https://hardrails.github.io/steward/limitations/)

## Platform support

Production nodes are systemd Linux on `amd64` or `arm64` with Docker installed.
The guided installer selects:

- DEB for Debian and Ubuntu families;
- RPM for RHEL, Rocky, Alma, Fedora, Amazon Linux, Oracle Linux, and SUSE families;
- a universal archive for other systemd distributions.

macOS release archives are for development; Windows is not a v0.1 release target.
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

An operator can clone this repository alone, audit it, build both binaries, and run
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
