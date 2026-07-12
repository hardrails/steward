---
title: Releasing Steward
description: Maintainer runbook for validating, tagging, building, checksumming, publishing, and verifying a Steward release.
section: Maintainer guide
---

# Releasing Steward

This document is the maintainer runbook for cutting a Steward release. Pushing a
version tag (`vX.Y.Z`) builds cross-platform binaries, Linux packages, the guided
installer, and SHA-256 checksums and attaches them to a GitHub Release — no manual
uploads. It also records *why* the release uses native package tools rather than a
packaging framework, and how the
version a binary reports is derived, because both were decided from empirical
tests, not assumption.

## TL;DR — cut a release

```console
# 1. Make sure main is green and you are on the exact commit you want to ship.
git checkout main
git pull origin main

# 2. (Optional) bump the compiled-in fallback constant if it is stale. This is
#    ONLY the version reported under `go run`/`go test`; a real tagged build does
#    not use it (see "How the version is derived" below). Skip if it already
#    matches the release you are cutting.
#    -> internal/buildinfo/version.go: const Version = "1.2.0"

# 3. Tag the release commit and push the tag. The tag push is what triggers the
#    Release workflow.
git tag v1.3.0
git push origin v1.3.0

# 4. Watch the run; it publishes the GitHub Release when green.
gh run watch "$(gh run list --workflow=release.yml --limit=1 --json databaseId --jq '.[0].databaseId')"
gh release view v1.3.0 --web
```

That is the whole flow. Everything below is the detail behind it.

## What the automation does

`.github/workflows/release.yml` triggers on `push` of any `v*` tag. (The trigger
is a broad glob on purpose: GitHub's tag-filter syntax cannot reliably express
"semver only", and a filter that silently failed to match the release tag would be
worse than a broad one — so `scripts/release.sh` enforces the `vX.Y.Z` shape
itself, failing a stray tag like `vnext` or `v2` fast and loudly before anything is
built or published.) It uses four job executions, split deliberately for native
packaging and least privilege:

1. **`build / amd64` and `build / arm64`** — each with a **read-only** token and
   a matching native host — check out the release source with full history, then
   run `scripts/release.sh`, which rejects a
   non-semver tag up front, cross-compiles that architecture's Linux and Darwin
   targets, packages each build
   as a `.tar.gz` (`steward` and `stewardctl` everywhere, plus `steward-executor` and the offline
   node-appliance assets on Linux, with `LICENSE` + `README.md`), writes a `checksums.txt` of
   SHA-256 sums, builds DEB and RPM node packages for both Linux architectures,
   includes `install-steward.sh`, asserts all three binaries self-report the tag, and
   uploads that architecture's artifacts. Native hosts are load-bearing here:
   RPM validates build architecture and will not safely produce an `aarch64`
   package on an `x86_64` host merely because its payload was cross-compiled.
2. **`combine`** — still read-only and with **no checkout** — downloads both
   architecture sets, verifies the complete advertised matrix is present, and
   writes one SHA-256 manifest over exactly those release files.
3. **`publish`** — the only job with a `contents: write` token — runs **only on a
   tag push**, checks out **no repository code**, downloads the artifacts the
   combine job produced, and creates a GitHub Release named after the tag (auto-generated
   notes, archives, and `checksums.txt` attached).

The split is the point: the jobs that run the tagged commit's own code
(`scripts/release.sh`) never holds a token that can publish, and the job that can
publish runs nothing but `gh release create` against already-built artifacts. So
an accidentally-tagged bad commit cannot execute with publish permissions.

### Target matrix

| GOOS   | GOARCH | Archive                              | Processes |
| ------ | ------ | ------------------------------------ | --------- |
| linux  | amd64  | `steward_vX.Y.Z_linux_amd64.tar.gz`  | `steward`, `steward-executor`, `stewardctl` |
| linux  | arm64  | `steward_vX.Y.Z_linux_arm64.tar.gz`  | `steward`, `steward-executor`, `stewardctl` |
| darwin | amd64  | `steward_vX.Y.Z_darwin_amd64.tar.gz` | `steward`, `stewardctl` |
| darwin | arm64  | `steward_vX.Y.Z_darwin_arm64.tar.gz` | `steward`, `stewardctl` |

Each Linux row additionally produces
`steward-node_vX.Y.Z_<arch>.deb` and
`steward-node_vX.Y.Z_<arch>.rpm`. `install-steward.sh` is architecture-independent
and selects among those packages and the archive at runtime.

All Steward binaries are pure–standard-library Go. Executor and the
systemd/config/install/preflight/activation node-appliance assets are shipped in each
Linux archive—the supported node-server platform—and versioned as an integral Steward
component. Darwin archives contain the usable `steward` client/supervisor and
offline `stewardctl`; they do not advertise an Executor or Linux service installer that cannot obtain Docker `runsc`
on macOS. Adding a target requires deciding explicitly whether it can satisfy Executor's
host contract.

## How release identity is stamped

`internal/buildinfo.Resolve()` has four explicit precedence levels:

1. **Stamped release version** — `scripts/release.sh` sets the otherwise-empty
   private string `releaseVersion` through Go's standard `-ldflags -X` support.
2. **`debug.ReadBuildInfo().Main.Version`** — used by a versioned `go install`.
3. **VCS revision** — the commit SHA (`-dirty` when the tree had uncommitted
   changes), stamped by any `go build` of a committed tree.
4. **`const Version`** (`"1.2.0"`) — the development fallback when there is no build
   metadata at all (`go run`, `go test`, or a build with VCS stamping disabled).

The explicit first level is load-bearing. A local-module checkout normally has
`Main.Version="(devel)"`; VCS metadata identifies a commit, not the human release
tag; and reproducible `-trimpath` builds may omit that metadata. The artifact
filename, `/opt/steward/releases/<version>` directory, and activation argument must
still agree exactly, so the release tag is passed directly to every cross-build:

```console
go build -trimpath \
  -ldflags "-s -w -X github.com/hardrails/steward/internal/buildinfo.releaseVersion=v1.3.0" \
  ./cmd/steward
```

The release script then builds host-native copies through the same path, executes
both `steward -version` and `steward-executor -version`, and fails before publishing
unless both equal `GITHUB_REF_NAME`. This guards the linker symbol, import path, and
all three entry points rather than assuming a successful `go build` implies the version
arrived.

A canonical `go install github.com/hardrails/steward/cmd/steward@v1.3.0` still
reports `v1.3.0` through `Main.Version` without release flags. The shared fallback
constant matters only for metadata-free developer invocations; keep it roughly in
step for tidiness, but it does not identify published artifacts.

## Why native package tools, not a packaging framework

The release deliberately uses `dpkg-deb` and `rpmbuild`, invoked by short audited
scripts, instead of goreleaser, nfpm, fpm, or a self-extracting installer:

- **Use the host's ownership model.** DEB and RPM provide atomic file ownership,
  upgrade ordering, dependency checks, and removal semantics. A self-extracting
  shell archive would have to recreate those poorly.
- **No application dependency.** The package builders are distribution-native
  release tools, not Go module or runtime dependencies. `go list -m all` remains
  exactly the Steward module.
- **Small audit surface.** The templates only carry the already-built release stage
  and invoke the same `install-node.sh` lifecycle on the target. There is no second
  implementation of identity, configuration, unit, or activation behavior.
- **The one linker stamp needs no framework.** The native release script applies a
  single standard `-X` value and executes both outputs to verify it. A packaging
  framework would not make that contract smaller or safer.
- **Locally and fully verifiable.** `scripts/release.sh` is the exact build CI
  runs; a maintainer can dry-run the whole thing on their laptop. The build was
  validated end-to-end (all four targets cross-compiled, each self-reporting
  `v1.3.0` from a tagged checkout) before this workflow was committed.
- **Smaller trusted-action surface.** The workflow pins only `actions/checkout`,
  `actions/setup-go`, and `actions/{upload,download}-artifact` to full commit SHAs
  — the same supply-chain discipline the rest of CI already uses — and publishes
  with the built-in `GITHUB_TOKEN` via `gh`, adding no third-party release action.

Revisit a packaging framework only when Steward commits to another native format
(for example, a non-systemd platform) or package metadata becomes complex enough
that maintaining the two templates is riskier than adopting the tool. Do not adopt
one merely to shorten these build scripts.

## Dry-running the release without publishing

You never have to publish to test the automation. Two ways:

### Locally (no GitHub involved)

```console
# Builds every target and any native packages whose platform tools are installed,
# then writes checksums into ./dist. Publishes nothing. dist/ is git-ignored.
bash scripts/release.sh
ls dist/
(cd dist && sha256sum -c checksums.txt)   # use `shasum -a 256 -c` on macOS
```

On Ubuntu CI, `dpkg-deb` and `rpmbuild` are both installed and every advertised
package is mandatory; x86 and ARM RPMs are built on matching native runners. A
maintainer's macOS dry run builds archives and skips native packages whose Linux
tools are absent; use the CI dry run for the complete matrix.

Run against a tag locally to also exercise the version assertion:

```console
GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v1.3.0 bash scripts/release.sh
```

### On GitHub (`workflow_dispatch`)

The workflow also accepts a manual trigger. A `workflow_dispatch` run performs the
**identical** build, checksum, and assertion steps and uploads `dist/` to the
workflow run — but the "Create GitHub Release" step is gated to `push` of a `v*`
tag, so a dispatch run **cannot create or mutate a release**. Fire one from the
Actions tab, or:

```console
gh workflow run release.yml --ref main
gh run watch "$(gh run list --workflow=release.yml --limit=1 --json databaseId --jq '.[0].databaseId')"
# Then download the built artifacts from the run to inspect them:
gh run download "$(gh run list --workflow=release.yml --limit=1 --json databaseId --jq '.[0].databaseId')" -n steward-dist -D /tmp/steward-dist
```

(On a dispatch run the archives and binaries use an immutable
`v0.0.0-dev.<commit>` prerelease identity, since there is no tag. The shape is
accepted by the offline installer, so a maintainer can exercise the downloaded
set as well as inspect it. That identity is never published as a GitHub Release.)

## Verifying a published download (for consumers)

```console
# Download the archive and the checksums for the release, then verify.
gh release download v1.3.0 --repo hardrails/steward
sha256sum -c checksums.txt      # macOS: shasum -a 256 -c checksums.txt
tar -xzf steward_v1.3.0_linux_amd64.tar.gz
./steward -version              # -> steward v1.3.0
# On Linux, steward-executor is in the same verified archive.
```

## Pre-flight checklist

- [ ] `main` is green (all required checks pass) at the commit you will tag.
- [ ] `scripts/signed-admission-acceptance.sh` passes on a Linux Docker host with
      `runsc`, using the exact release binaries and an already-local pinned image.
- [ ] The tag is a valid semver `vX.Y.Z` (a pre-release such as `v1.3.0-rc.1`
      is auto-marked as a GitHub pre-release; a hyphen in the tag is the signal).
- [ ] You are tagging the intended commit (`git log -1`).
- [ ] (Optional) `const Version` in `internal/buildinfo/version.go` is not
      embarrassingly stale.

## Rollback / re-cut

A release is a tag plus a GitHub Release. If something is wrong:

```console
# Remove the GitHub Release and delete the tag locally and on the remote.
gh release delete v1.3.0 --repo hardrails/steward --yes
git push origin :refs/tags/v1.3.0
git tag -d v1.3.0
```

Then fix forward and tag again. Prefer a new patch tag (`v1.2.1`) over re-pointing
an already-published tag: consumers and the Go module proxy may have cached the
old tag, and a moved tag is a supply-chain surprise.
