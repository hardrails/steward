---
title: Platform support matrix
description: Exact operating-system, architecture, packaging, Docker, gVisor, and development support for Steward.
section: Reference
---

# Platform support matrix

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
- a local Docker group and Unix socket;
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

| Target | `steward` | `steward-executor` | Node appliance |
| --- | --- | --- | --- |
| Linux `amd64` | Yes | Yes | DEB, RPM, archive |
| Linux `arm64` | Yes | Yes | DEB, RPM, archive |
| macOS Intel | Yes | No | No |
| macOS Apple Silicon | Yes | No | No |
| Windows | No artifact | No | No |

macOS archives support development and API integration. Executor runs only on Linux
because it requires a Docker Unix socket, systemd, and gVisor runtime enforcement.

## Build requirements

Building from source requires Go 1.24 or newer. Published static binaries do not
require Go. The Go module has no third-party dependencies.
