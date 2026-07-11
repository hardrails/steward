---
title: Platform support matrix
description: Exact operating-system, architecture, packaging, Docker, gVisor, and development support for Steward v0.1.
section: Reference
---

# Platform support matrix

## Production Executor nodes

| Host family | Architectures | Preferred package | Status |
| --- | --- | --- | --- |
| Debian, Ubuntu, derivatives | `amd64`, `arm64` | DEB | Supported |
| RHEL, Rocky, Alma, CentOS Stream, Fedora | `amd64`, `arm64` | RPM | Supported |
| Amazon Linux, Oracle Linux, SUSE families | `amd64`, `arm64` | RPM | Supported |
| Other systemd Linux distributions | `amd64`, `arm64` | `.tar.gz` appliance | Supported fallback |
| Alpine/OpenRC and non-systemd Linux | — | — | Not supported in v0.1 |
| macOS, Windows, BSD | — | — | Not Executor node targets |

Every production node requires:

- systemd;
- Docker Engine installed by the operator;
- a local Docker group and Unix socket;
- gVisor registered with Docker as runtime `runsc`; and
- a Linux kernel/runtime combination supported by the selected Docker and gVisor releases.

The guided installer can install and register official gVisor after explicit
approval. It never installs Docker.

## Published release artifacts

| Target | `steward` | `steward-executor` | Node appliance |
| --- | --- | --- | --- |
| Linux `amd64` | Yes | Yes | DEB, RPM, archive |
| Linux `arm64` | Yes | Yes | DEB, RPM, archive |
| macOS Intel | Yes | No | No |
| macOS Apple Silicon | Yes | No | No |
| Windows | No v0.1 artifact | No | No |

macOS archives support development and API integration. Executor is Linux-only
because its contract depends on the Docker Unix socket, systemd deployment, and
gVisor runtime enforcement.

## Build requirements

Building from source requires Go 1.24 or newer. Published binaries are static and do
not require a Go toolchain. The Go module has no third-party dependencies.
