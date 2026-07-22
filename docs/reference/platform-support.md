---
title: Platform support matrix
description: Exact operating-system, architecture, packaging, Docker, gVisor, and development support for Steward.
section: Reference
---

# Platform support matrix

For the contract embedded in the installed binary, including known limits, run:

<!-- cli-flags: support matrix | -output -->
```console
stewardctl support matrix
stewardctl support matrix -output json
```

See the [installed support contract]({{ '/reference/support-contract/' | relative_url }})
for the schema, release asset, and upgrade use.

## Production controller hosts

The dedicated `steward-control_<version>_linux_<arch>.tar.gz` and
`install-control.sh` path supports systemd Linux on `amd64` and `arm64`. A
controller host needs a supported systemd version, local durable storage, and TLS
material for a non-loopback listener. It does not need Docker, gVisor, an agent
image, model service, database server, or message broker. The installer creates a
dedicated non-root identity with no Docker-group membership.

Distribution-specific controller boot tests are not run across every Linux family.
Validate the installed hardening directives, service readiness, backup/restore,
and private-CA behavior on the exact production image.

## Production Executor nodes

| Host family | Architectures | Preferred package | Status |
| --- | --- | --- | --- |
| Debian, Ubuntu, derivatives | `amd64`, `arm64` | DEB | Published packaging path; package construction is tested on Ubuntu 24.04 |
| RHEL, Rocky, Alma, CentOS Stream, Fedora | `amd64`, `arm64` | RPM | Published packaging path; no per-distribution node acceptance in CI |
| Amazon Linux, Oracle Linux, SUSE families | `amd64`, `arm64` | RPM | Published packaging path; no per-distribution node acceptance in CI |
| Other systemd Linux distributions | `amd64`, `arm64` | `.tar.gz` appliance | Compatibility path; operator validation required |
| Alpine/OpenRC and non-systemd Linux | — | — | Not supported |
| macOS, Windows, BSD | — | — | Not Executor node targets |

Each production node requires:

- systemd 235 or newer for `RuntimeDirectoryPreserve=yes`; the selected version
  must also recognize every hardening directive in the shipped units;
- Docker Engine installed by the operator;
- Docker Engine 28 or newer for positive-capability networks, which use native
  isolated bridge gateway mode;
- a local Docker group and Unix socket, with no human or unrelated service
  membership and no account using the Docker group as its primary group;
- gVisor registered with Docker as runtime `runsc`; and
- a Linux kernel/runtime combination supported by the selected Docker and gVisor releases.

CI builds both architectures and constructs and inspects DEB and RPM artifacts on
Ubuntu 24.04. It does not boot every listed distribution or run Docker/gVisor node
acceptance on both architectures. Before production rollout, run packaged preflight
and workload acceptance on the exact operating-system image, systemd version,
kernel, Docker release, gVisor release, and architecture. Treat any unknown systemd
unit directive as an unsupported hardening gap, not a harmless warning.

With explicit approval, the guided installer can install and register the official
gVisor runtime. It never installs Docker.

## Published release artifacts

| Target | `steward-control` | `steward` | `steward-executor` | Service packaging |
| --- | --- | --- | --- | --- |
| Linux `amd64` | Yes | Yes | Yes | Controller archive; node DEB, RPM, and archive |
| Linux `arm64` | Yes | Yes | Yes | Controller archive; node DEB, RPM, and archive |
| macOS Intel | Operator and development binary | Yes | No | Native user installer |
| macOS Apple Silicon | Operator and development binary | Yes | No | Native user installer |
| Windows | No artifact | No artifact | No | No |

The checksummed `install-macos.sh` release asset installs the native operator,
control-plane, CLI, and MCP binaries without root by default. macOS supports agent
authoring, policy evaluation, scheduling decisions, Docker Desktop development,
and API integration. It does not run `steward-executor`; production Executor
services require Linux, a Docker Unix socket, systemd, and gVisor runtime
enforcement.

## Build requirements

Building from source requires Go 1.24 or newer. Published static binaries do not
require Go. The Go module has no third-party dependencies.

The packaged Hermes adapter builder is currently qualified only on `linux/amd64`.
This is narrower than the Executor node and release-artifact matrix above.

The optional Buzz integration bridge builds natively on supported Linux and macOS
operator hosts. It is not an Executor node and does not require Docker or gVisor.
The released build recipe compiles the exact pinned Buzz CLI with its pinned Rust
toolchain, then builds the dependency-free Steward bridge and CLI. Steward ships a
hardened systemd service recipe for Linux; macOS operators must supervise the
bridge with their normal service manager. The bridge reaches Gateway only through
a literal-loopback endpoint, normally an operator-owned SSH or private-network
tunnel to the selected Linux node.
