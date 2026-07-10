# Releasing Steward

This document is the maintainer runbook for cutting a Steward release. Pushing a
version tag (`vX.Y.Z`) builds cross-platform binaries with SHA-256 checksums and
attaches them to a GitHub Release — no manual uploads. It also records *why* the
release is a plain GitHub Actions matrix rather than goreleaser, and how the
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
#    -> internal/server/server.go: const Version = "0.1.0"

# 3. Tag the release commit and push the tag. The tag push is what triggers the
#    Release workflow.
git tag v0.1.0
git push origin v0.1.0

# 4. Watch the run; it publishes the GitHub Release when green.
gh run watch "$(gh run list --workflow=release.yml --limit=1 --json databaseId --jq '.[0].databaseId')"
gh release view v0.1.0 --web
```

That is the whole flow. Everything below is the detail behind it.

## What the automation does

`.github/workflows/release.yml` triggers on `push` of a semver-shaped tag
(`v[0-9]+.[0-9]+.[0-9]+*`, so `vnext` or `v2` never enter the release path). It
runs **two jobs**, split deliberately for least privilege:

1. **`build`** — with a **read-only** token — checks out the tag with **full
   history** (`fetch-depth: 0`) so the Go toolchain can stamp the tag as the
   binary's version (see below), then runs `scripts/release.sh`, which
   cross-compiles the target matrix, packages each build as a `.tar.gz` (binary +
   `LICENSE` + `README.md`), writes a `checksums.txt` of SHA-256 sums, asserts the
   binary self-reports the tag, and uploads the whole `dist/` directory as a
   workflow artifact.
2. **`publish`** — the only job with a `contents: write` token — runs **only on a
   tag push**, checks out **no repository code**, downloads the artifacts the
   build produced, and creates a GitHub Release named after the tag (auto-generated
   notes, archives, and `checksums.txt` attached).

The split is the point: the job that runs the tagged commit's own code
(`scripts/release.sh`) never holds a token that can publish, and the job that can
publish runs nothing but `gh release create` against already-built artifacts. So
an accidentally-tagged bad commit cannot execute with publish permissions.

### Target matrix

| GOOS   | GOARCH | Archive                                 |
| ------ | ------ | --------------------------------------- |
| linux  | amd64  | `steward_vX.Y.Z_linux_amd64.tar.gz`     |
| linux  | arm64  | `steward_vX.Y.Z_linux_arm64.tar.gz`     |
| darwin | amd64  | `steward_vX.Y.Z_darwin_amd64.tar.gz`    |
| darwin | arm64  | `steward_vX.Y.Z_darwin_arm64.tar.gz`    |

Steward is pure–standard-library Go, so every target is a trivial `CGO_ENABLED=0`
cross-compile from any host. Adding a target (for example `windows/amd64`) is one
line in the `targets` array of `scripts/release.sh`.

## How the version is derived (and why there is no ldflags injection)

`internal/server.ResolveVersion()` prefers the build metadata the Go toolchain
embeds, and only falls back to the compiled-in `const Version` when none exists.
Its precedence, confirmed empirically by building the binary several ways, is:

1. **`debug.ReadBuildInfo().Main.Version`** — the module version. This is set by
   the module system, not by the linker.
2. **VCS revision** — the commit SHA (`-dirty` when the tree had uncommitted
   changes), stamped by any `go build` of a committed tree.
3. **`const Version`** (`"0.1.0"`) — the fallback when there is no build
   metadata at all (`go run`, `go test`, or a build with VCS stamping disabled).

The load-bearing finding: **when the binary is built from a checkout that sits
exactly on a semver tag, the Go toolchain derives `Main.Version` as that tag.**
So both supported install paths report the tag with no version injection:

```console
# Canonical `go install` — Main.Version is the tagged module version:
$ go install github.com/hardrails/steward/cmd/steward@v0.1.0
$ steward -version
steward v0.1.0

# The release workflow's `go build` from the tag checkout — same result, because
# Go stamps the tag as Main.Version when it is checked out with full history:
$ steward -version
steward v0.1.0
```

Two consequences worth stating plainly, because they were verified rather than
assumed:

- **No `-ldflags -X` injection is used or needed.** The tag-derived version is
  already correct. And `Version` is a `const`, which the linker's
  `-ldflags -X importpath.Version=...` **cannot patch** anyway — a `const` is
  inlined at compile time and has no linker-visible symbol, so the flag is
  silently inert (it does not error; it simply does nothing). Making the binaries
  report the tag through injection would require both changing the `const` to a
  `var` *and* disabling VCS stamping — strictly worse than letting Go's native
  mechanism do it for free.
- **`fetch-depth: 0` is mandatory in CI.** A shallow checkout would leave the tag
  unresolvable, and the binary would self-report a `v0.0.0-<timestamp>-<sha>`
  pseudo-version (an untagged clean tree) or the bare `const` fallback instead of
  the tag. `scripts/release.sh` guards against exactly this: on a tag build it
  builds the host-native binary, reads its `-version`, and **fails the release**
  if it does not equal the tag — so a stamping regression aborts the publish
  instead of shipping a mislabeled artifact.

The `const Version` in `internal/server/server.go` therefore matters only for
non-release invocations (`go run ./cmd/steward -version` prints `steward 0.1.0`).
Keep it roughly in step with the latest release for tidiness, but it is not what a
released binary reports and bumping it is optional.

## Why a plain Actions matrix, not goreleaser

[goreleaser](https://goreleaser.com) is the Go ecosystem's standard release tool
and would also work here. This repository deliberately uses a plain GitHub Actions
matrix build instead, for reasons specific to Steward:

- **Zero new tooling in the release path.** Steward's whole premise is that it is
  "buildable by anyone with only the Go toolchain installed" (see `AGENTS.md` and
  the pre-commit hook). The release uses only `go build` plus POSIX shell and the
  `gh` CLI that is preinstalled on the runner — nothing a contributor cannot run
  locally with `scripts/release.sh`. goreleaser would add a tool (and its GitHub
  Action or binary) to the trusted release surface for functionality this project
  does not need.
- **The native version mechanism removes goreleaser's main draw.** goreleaser's
  headline feature for a project like this is templated `-ldflags` version
  injection. Steward gets the correct tagged version from Go's own VCS build info
  with no injection at all (above), so that feature would be redundant.
- **Locally and fully verifiable.** `scripts/release.sh` is the exact build CI
  runs; a maintainer can dry-run the whole thing on their laptop. The build was
  validated end-to-end (all four targets cross-compiled, each self-reporting
  `v0.1.0` from a tagged checkout) before this workflow was committed.
- **Smaller trusted-action surface.** The workflow pins only `actions/checkout`,
  `actions/setup-go`, and `actions/{upload,download}-artifact` to full commit SHAs
  — the same supply-chain discipline the rest of CI already uses — and publishes
  with the built-in `GITHUB_TOKEN` via `gh`, adding no third-party release action.

If Steward later grows needs goreleaser serves well — Linux packages (`.deb`/
`.rpm`), Homebrew taps, Docker manifests, SBOM/signing pipelines — revisit this
decision then. For a single static binary with checksums, the matrix is the
smaller, more auditable, more on-ethos choice.

## Dry-running the release without publishing

You never have to publish to test the automation. Two ways:

### Locally (no GitHub involved)

```console
# Builds every target, archives them, writes checksums — into ./dist. Publishes
# nothing. dist/ is git-ignored.
bash scripts/release.sh
ls dist/
sha256sum -c dist/checksums.txt   # (shasum -a 256 -c on macOS)
```

Run against a tag locally to also exercise the version assertion:

```console
GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v0.1.0 bash scripts/release.sh
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

(On a dispatch run the archives are named after the branch and the binaries report
a pseudo-version, since there is no tag — that is expected; the point is to prove
the build, packaging, and checksum steps are sound.)

## Verifying a published download (for consumers)

```console
# Download the archive and the checksums for the release, then verify.
gh release download v0.1.0 --repo hardrails/steward
sha256sum -c checksums.txt      # macOS: shasum -a 256 -c checksums.txt
tar -xzf steward_v0.1.0_linux_amd64.tar.gz
./steward -version              # -> steward v0.1.0
```

## Pre-flight checklist

- [ ] `main` is green (all required checks pass) at the commit you will tag.
- [ ] The tag is a valid semver `vX.Y.Z` (a pre-release such as `v0.1.0-rc.1`
      is auto-marked as a GitHub pre-release; a hyphen in the tag is the signal).
- [ ] You are tagging the intended commit (`git log -1`).
- [ ] (Optional) `const Version` in `internal/server/server.go` is not
      embarrassingly stale.

## Rollback / re-cut

A release is a tag plus a GitHub Release. If something is wrong:

```console
# Remove the GitHub Release and delete the tag locally and on the remote.
gh release delete v0.1.0 --repo hardrails/steward --yes
git push origin :refs/tags/v0.1.0
git tag -d v0.1.0
```

Then fix forward and tag again. Prefer a new patch tag (`v0.1.1`) over re-pointing
an already-published tag: consumers and the Go module proxy may have cached the
old tag, and a moved tag is a supply-chain surprise.
