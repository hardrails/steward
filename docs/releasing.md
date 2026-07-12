---
title: Releasing Steward
description: Maintainer runbook for validating, tagging, building, checksumming, publishing, and verifying a Steward release.
section: Maintainer guide
---

# Release Steward

Pushing a `vX.Y.Z` tag builds cross-platform binaries, Linux packages, the guided
installer, and SHA-256 checksums, then attaches them to a GitHub Release. No manual
upload is required. This runbook also records the release-identity and packaging
decisions that protect artifact consistency and publishing authority.

## Cut a release

```console
# 1. Make sure main is green and you are on the exact commit you want to ship.
git checkout main
git pull origin main

# 2. Choose the semver tag once and reuse it throughout the runbook.
RELEASE_TAG="<release-tag>"

# 3. Tag the release commit and push the tag. The tag push is what triggers the
#    Release workflow.
git tag "$RELEASE_TAG"
git push origin "$RELEASE_TAG"

# 4. Watch the run; it publishes the GitHub Release when green.
gh run watch "$(gh run list --workflow=release.yml --limit=1 --json databaseId --jq '.[0].databaseId')"
gh release view "$RELEASE_TAG" --web
```

## What the workflow does

`.github/workflows/release.yml` starts on any `v*` tag. GitHub tag-filter globs
cannot reliably express the complete semantic-version rule, so
`scripts/release.sh` is authoritative: before building, it requires `vX.Y.Z` with
an optional valid prerelease suffix and rejects malformed tags, leading zeros,
and build-metadata suffixes. This fail-fast check prevents tags such as `vnext` or
`v2` from reaching publication.

The workflow uses four job executions:

1. **`build / amd64` and `build / arm64`:** each runs on a matching native host
   with a read-only token. For a tag build, each job first proves that the commit
   referenced by the tag is reachable from `origin/main`; a tag created from an
   unmerged branch cannot publish. `scripts/release.sh` cross-compiles Linux and Darwin,
   creates `.tar.gz` archives with `LICENSE` and `README.md`, builds DEB and RPM
   packages, includes `install-steward.sh`, and checks that all six host-native
   binaries report the tag. Each Linux artifact contains a deterministic
   `release.json` that binds the tag, target, six binaries, units, templates, and
   helper scripts by SHA-256 and declares durable-state reader/writer ranges. Native
   package hosts are required because RPM validates build architecture;
   cross-compiled payloads alone do not safely
   produce an `aarch64` package on `x86_64`.
2. **`combine`:** with a read-only token and no source checkout, downloads both
   architecture sets, requires the complete matrix, and writes one SHA-256
   manifest over exactly those files.
3. **`publish`:** only on a tag push, with the workflow's only `contents: write`
   token and no source checkout, runs `gh release create` against the combined
   artifacts. It adds generated notes, archives, packages, the installer, and
   `checksums.txt`.

Code from the tagged commit runs only in read-only jobs. The job allowed to
publish executes no repository code. A bad tagged commit can therefore fail or
produce bad artifacts, but it cannot run its own code with release-write
authority.

### Target matrix

| GOOS | GOARCH | Archive | Binaries |
| --- | --- | --- | --- |
| linux | amd64 | `steward_vX.Y.Z_linux_amd64.tar.gz` | All six Steward binaries |
| linux | arm64 | `steward_vX.Y.Z_linux_arm64.tar.gz` | All six Steward binaries |
| darwin | amd64 | `steward_vX.Y.Z_darwin_amd64.tar.gz` | `steward`, `stewardctl`, `steward-mcp` |
| darwin | arm64 | `steward_vX.Y.Z_darwin_arm64.tar.gz` | `steward`, `stewardctl`, `steward-mcp` |

Each Linux target also produces `steward-node_vX.Y.Z_<arch>.deb` and
`steward-node_vX.Y.Z_<arch>.rpm`. The architecture-independent
`install-steward.sh` selects a native package or archive at install time.

Steward uses only the Go standard library. Linux archives include Executor,
Gateway, Relay, systemd units, configuration, and installation, preflight, and
activation assets. The node installer requires the expected version and rejects a
manifest whose version, operating system, architecture, file set, or digest differs.
Darwin archives contain `steward`, `stewardctl`, and
`steward-mcp`; they do not claim support for Executor or the Linux service
installer because macOS cannot satisfy the Docker `runsc` host contract. Add a
target only after deciding whether it can meet that contract.

## Release identity

`internal/buildinfo.Resolve()` chooses a version in this order:

1. **Stamped release version:** `scripts/release.sh` sets private
   `releaseVersion` through Go's `-ldflags -X`.
2. **`debug.ReadBuildInfo().Main.Version`:** used for versioned `go install`.
3. **VCS revision:** the commit SHA, with `-dirty` for uncommitted changes.
4. **`const Version`:** fallback for metadata-free `go run`, `go test`, or builds
   with VCS stamping disabled.

The explicit stamp is required. A checkout normally reports
`Main.Version="(devel)"`; VCS metadata identifies a commit rather than its release
tag; and `-trimpath` builds may omit that metadata. Artifact names,
`/opt/steward/releases/<version>`, and activation arguments must still match.
Every cross-build therefore receives the tag directly:

```console
RELEASE_TAG="<release-tag>"
go build -trimpath \
  -ldflags "-s -w -X github.com/hardrails/steward/internal/buildinfo.releaseVersion=$RELEASE_TAG" \
  ./cmd/steward
```

The script also builds host-native copies through this path, runs all six with
`-version`, and fails unless each result equals the `VERSION` stamped into the
artifacts. On a tag build, that value is `GITHUB_REF_NAME`. This checks the linker
symbol, import path, and every entry point.

`go install "github.com/hardrails/steward/cmd/steward@$RELEASE_TAG"` still reports
the selected tag through `Main.Version` without linker flags. Keep the shared
fallback constant reasonably current for developer builds, but it does not
identify published artifacts.

## Why the release uses native package tools

The release invokes `dpkg-deb` and `rpmbuild` from short audited scripts instead
of using goreleaser, nfpm, fpm, or a self-extracting installer.

- DEB and RPM already provide file ownership, upgrade ordering, dependency
  checks, and removal semantics.
- These distribution tools add no Go module or runtime dependency.
  `go list -m all` remains only the Steward module.
- Package templates carry the built release stage and call the same
  `install-node.sh` lifecycle, avoiding a second implementation of identity,
  configuration, units, or activation.
- One standard `-X` linker value is enough, and executing each host-native binary
  verifies the result.
- `scripts/release.sh` is the script CI runs, so maintainers can reproduce the
  build locally. End-to-end validation has cross-compiled all four targets and
  confirmed each host-native binary reports the selected tag.
- `actions/checkout`, `actions/setup-go`, and
  `actions/{upload,download}-artifact` are pinned to full commit SHAs.
  Publication uses the built-in `GITHUB_TOKEN` and `gh`, with no third-party
  release action.

Reconsider a packaging framework if Steward adds another native package format or
the DEB/RPM metadata becomes harder to maintain safely than the dependency. Script
length alone is not a reason to add one.

## Why each Linux release has an embedded manifest

Steward uses the host's SHA-256 tools and the existing package and archive formats.
This keeps the node install path offline and adds no parser, package framework, or
runtime dependency. `release.json` has one canonical layout, so the installer
reconstructs it from the expected tag, host target, and actual files and requires an
exact byte match.

The embedded manifest prevents version-label and mixed-file mistakes inside a
verified artifact. It does not authenticate the artifact by itself: an attacker who
can replace both the payload and manifest can recompute every digest. Operators must
still verify the outer artifact through `checksums.txt` obtained over a trusted
channel or an independently pinned mirror hash. Revisit signed release metadata if
Steward adopts a public signing and key-rotation policy.

## Dry-run without publishing

### Local dry-run

```console
# Builds every target and any native packages whose platform tools are installed,
# then writes checksums into ./dist. Publishes nothing. dist/ is git-ignored.
bash scripts/release.sh
ls dist/
(cd dist && sha256sum -c checksums.txt)   # use `shasum -a 256 -c` on macOS
```

Ubuntu CI installs `dpkg-deb` and `rpmbuild`; matching x86 and ARM runners make
every advertised package mandatory. A macOS dry-run builds archives and skips
Linux-native packages. Use a CI dry-run to verify the complete matrix.

To exercise tag validation and version assertions locally:

```console
RELEASE_TAG="<release-tag>"
GITHUB_REF_TYPE=tag GITHUB_REF_NAME="$RELEASE_TAG" bash scripts/release.sh
```

### GitHub dry-run

A `workflow_dispatch` run performs the same builds, checksums, and six-binary
version assertion, then uploads `dist/` to the workflow run. It checks the
immutable development `VERSION` used for those artifacts because a dispatch has
no release tag. Its publish job is gated to a `v*` tag push, so manual dispatch
cannot create or change a release.

```console
gh workflow run release.yml --ref main
gh run watch "$(gh run list --workflow=release.yml --limit=1 --json databaseId --jq '.[0].databaseId')"
# Then download the built artifacts from the run to inspect them:
gh run download "$(gh run list --workflow=release.yml --limit=1 --json databaseId --jq '.[0].databaseId')" -n steward-dist -D /tmp/steward-dist
```

Without a tag, archives and binaries receive the immutable prerelease identity
`v0.0.0-dev.<commit>`. The offline installer accepts this form, but the workflow
never publishes it as a GitHub Release.

## Verify a published download

```console
# Download the archive and the checksums for the release, then verify.
RELEASE_TAG="<release-tag>"
gh release download "$RELEASE_TAG" --repo hardrails/steward
sha256sum -c checksums.txt      # macOS: shasum -a 256 -c checksums.txt
tar -xzf "steward_${RELEASE_TAG}_linux_amd64.tar.gz"
./steward -version              # must report "$RELEASE_TAG"
# On Linux, the other five binaries are in the same verified archive.
```

## Preflight checklist

Run Docker acceptance only on a disposable host that contains no real Steward
workloads. Each script refuses to start unless
`STEWARD_ACCEPT_DISPOSABLE_HOST_RISK=YES` is set. It assigns a random run ID and
removes only relays and networks carrying that run's exact tenant and instance
labels. The scripts still bind fixed host ports, exercise the local Docker daemon,
and intentionally create and destroy workloads, so a shared or production node is
not a supported test target.

- [ ] `main` is green at the exact commit to tag.
- [ ] `scripts/signed-admission-acceptance.sh` passes on Linux with Docker and
      `runsc`, using the release binaries and a local digest-pinned image.
- [ ] `scripts/positive-capabilities-acceptance.sh` passes on Docker Engine 28+
      with `runsc`. It tests persistent state, model brokering, service ingress,
      MCP lifecycle, purge, and receipts through the production topology.
- [ ] `scripts/egress-acceptance.sh` passes with a preloaded digest-pinned image
      containing `/bin/sleep` and `curl`. It tests HTTP, HTTPS CONNECT, denial,
      DNS isolation, audit, statistics, lifecycle, and receipts through gVisor.
- [ ] The tag is `vX.Y.Z`, optionally with a prerelease suffix. A hyphen marks a
      GitHub prerelease.
- [ ] `git log -1` shows the intended commit.
- [ ] Optional: `const Version` in `internal/buildinfo/version.go` is reasonably
      current.

## Withdraw and replace a release

A release consists of a tag and a GitHub Release. To withdraw both:

```console
# Remove the GitHub Release and delete the tag locally and on the remote.
RELEASE_TAG="<release-tag>"
gh release delete "$RELEASE_TAG" --repo hardrails/steward --yes
git push origin ":refs/tags/$RELEASE_TAG"
git tag -d "$RELEASE_TAG"
```

Commit the fix and publish a new patch tag. Do not move a published tag: consumers
and the Go module proxy may have cached the original, so moving it can make the same
tag resolve to different source for different consumers.
