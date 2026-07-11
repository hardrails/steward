---
title: Release artifacts and verification
description: Steward release filenames, target matrix, package contents, version identity, checksum verification, and first-install selection rules.
section: Reference
---

# Release artifacts and verification

Every GitHub release contains static archives, native Linux node packages, the
guided installer, and one SHA-256 manifest.

## File matrix

| Filename pattern | Contents |
| --- | --- |
| `steward_<version>_linux_amd64.tar.gz` | Three binaries plus universal node appliance |
| `steward_<version>_linux_arm64.tar.gz` | Three binaries plus universal node appliance |
| `steward-node_<version>_amd64.deb` | Debian-family node package |
| `steward-node_<version>_arm64.deb` | Debian-family node package |
| `steward-node_<version>_amd64.rpm` | RPM-family node package (`x86_64` metadata) |
| `steward-node_<version>_arm64.rpm` | RPM-family node package (`aarch64` metadata) |
| `steward_<version>_darwin_amd64.tar.gz` | macOS development supervisor and `stewardctl` |
| `steward_<version>_darwin_arm64.tar.gz` | macOS development supervisor and `stewardctl` |
| `install-steward.sh` | Interactive and unattended top-level installer |
| `checksums.txt` | SHA-256 values for all release assets |

Linux archives and packages include the hardened systemd units, configuration
templates, enrollment/preflight helpers, and atomic activation/removal tools. macOS
archives contain `steward`, `stewardctl`, the license, and README.

## Verify a downloaded release

```console
gh release download v1.2.0 --repo hardrails/steward --dir steward-v1.2.0
cd steward-v1.2.0
sha256sum -c checksums.txt
```

A checksum proves consistency with the downloaded manifest; authenticate the
manifest or outer software bundle independently for high-assurance imports.

## Version identity

Published binaries are linker-stamped and the release build executes all three
host-native binaries to assert they self-report the exact tag. Verify after installation:

```console
steward -version
steward-executor -version
stewardctl -version
```

All three must match the active `/opt/steward/releases/<version>` directory. Release tags
use `vX.Y.Z` semantic versioning with optional prerelease suffixes and no build
metadata.

See [platform support]({{ '/reference/platform-support/' | relative_url }}) and
[air-gapped installation]({{ '/guides/air-gapped/' | relative_url }}).
