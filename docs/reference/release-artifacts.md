---
title: Release artifacts and verification
description: Steward release filenames, target matrix, package contents, version identity, checksum verification, and first-install selection rules.
section: Reference
---

# Release artifacts and verification

Each GitHub release contains static archives, native Linux node packages, the guided
installer, and a SHA-256 manifest.

## File matrix

| Filename pattern | Contents |
| --- | --- |
| `steward_<version>_linux_amd64.tar.gz` | Six binaries plus universal node appliance |
| `steward_<version>_linux_arm64.tar.gz` | Six binaries plus universal node appliance |
| `steward-node_<version>_amd64.deb` | Debian-family node package |
| `steward-node_<version>_arm64.deb` | Debian-family node package |
| `steward-node_<version>_amd64.rpm` | RPM-family node package (`x86_64` metadata) |
| `steward-node_<version>_arm64.rpm` | RPM-family node package (`aarch64` metadata) |
| `steward_<version>_darwin_amd64.tar.gz` | macOS development supervisor, CLI, and MCP adapter |
| `steward_<version>_darwin_arm64.tar.gz` | macOS development supervisor, CLI, and MCP adapter |
| `install-steward.sh` | Interactive and unattended top-level installer |
| `checksums.txt` | SHA-256 values for every other release asset |

Linux archives and packages include hardened systemd units, configuration templates,
enrollment and preflight helpers, and whole-release activation and removal tools.
macOS archives contain `steward`, `stewardctl`, `steward-mcp`, the license, and
README.

## Verify a downloaded release

```console
RELEASE_TAG="<release-tag>"
gh release download "$RELEASE_TAG" --repo hardrails/steward --dir "steward-$RELEASE_TAG"
cd "steward-$RELEASE_TAG"
sha256sum -c checksums.txt
```

On stock macOS, use `shasum -a 256 -c checksums.txt` instead of `sha256sum`.

A checksum proves only that files match the downloaded manifest. For high-assurance
imports, authenticate the manifest with a trusted signature or verify it as part of
an independently authenticated release bundle.

## Version identity

Published binaries are linker-stamped. For each Linux target, the release build
executes all six host-native binaries and requires each to report the exact tag.
Verify after installation:

```console
steward -version
steward-executor -version
stewardctl -version
steward-gateway -version
steward-relay -version
steward-mcp -version
```

All six must match the active `/opt/steward/releases/<version>` directory. Release
tags use `vX.Y.Z` semantic versioning, with optional prerelease suffixes and no build
metadata.

Linux releases also contain `release.json`. Its canonical file map binds every
binary and host-integration asset by SHA-256. Its `state_formats` map declares the
minimum and maximum durable format each release reads and the format it writes for
Gateway state, admission fences, the operation journal, evidence, uplink replay
state, and supervisor state. Activation uses these ranges to reject an unsafe
upgrade or rollback before changing the active-release symlink or relay binding.

See [platform support]({{ '/reference/platform-support/' | relative_url }}) and
[air-gapped installation]({{ '/guides/air-gapped/' | relative_url }}).
