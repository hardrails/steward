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
They also include the exact-pinned Hermes Agent adapter definition, builder, signed
workspace-audit and connector-work skills, and qualification test harness. They do
not include a built Hermes image.
macOS archives contain `steward`, `stewardctl`, `steward-mcp`, the license, and
README.

## Hermes adapter build outputs

Steward does not publish a prebuilt Hermes OCI archive. Dependency and base-image
notices are incomplete, so redistribution remains blocked even though the pinned
adapter has passed its runtime qualification.

On an installed Linux node, the packaged interactive builder is:

```console
/usr/local/libexec/steward/build-hermes-adapter \
  --output hermes-agent-adapter.tar
```

For unattended operation, add `--non-interactive`. Without `--source-dir`, the
builder downloads only Hermes commit
`095b9eed3801c251796df93f48a8f2a527ff6e70` into a temporary directory. An operator
can instead transfer an exact clean checkout and pass
`--source-dir /path/to/hermes-agent`; that prevents the source download. The
digest-pinned base image and locked build dependencies must still be present locally
or reachable during the build.

The builder publishes the requested image archive and a sibling file named
`<archive>.attestation.json`. The canonical metadata records the pinned source,
adapter and builder identities, digest-pinned base image, output manifest and config
digests, platform, archive digest, and size. It contains no agent content or secrets.
It is metadata, not a signature or independent proof of provenance. Authenticate the
Steward release and source transfer, then inspect and sign the exact archive through
the documented admission workflow.

The Linux payload also exposes the packaged end-to-end harness at
`/usr/local/libexec/steward/hermes-steward-acceptance`. It requires Docker, the
`runsc` gVisor runtime, Python 3, `curl`, `base64`, and standard GNU userland tools.
Run it only on a disposable `linux/amd64` host with no production Steward services:
it uses fixed ports and creates and removes Docker resources.

```console
sudo env \
  STEWARD_ACCEPT_DISPOSABLE_HOST_RISK=YES \
  HERMES_ARCHIVE="$PWD/hermes-agent-adapter.tar" \
  /usr/local/libexec/steward/hermes-steward-acceptance
```

Set `HERMES_INTEGRATION_EVIDENCE_OUT` to a new path when an owner-only,
metadata-only qualification record is required. The detailed
[Hermes guide]({{ '/guides/hermes-agent/' | relative_url }}) explains the proof and
its limits.

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
Gateway state, Gateway connector receipts, admission fences, the operation journal,
Executor evidence, uplink replay state, and supervisor state. Activation uses these
ranges to reject an unsafe upgrade or rollback before changing the active-release
symlink or relay binding.

See [platform support]({{ '/reference/platform-support/' | relative_url }}) and
[air-gapped installation]({{ '/guides/air-gapped/' | relative_url }}).
