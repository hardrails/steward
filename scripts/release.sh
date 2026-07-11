#!/usr/bin/env bash
# Cross-compile Steward for every published target, package each build as a
# self-contained .tar.gz (the target's usable process binaries + LICENSE + README;
# Linux also carries the offline node-appliance assets), and write a SHA-256 checksums
# file over the archives. Dependency-free — only the Go toolchain and
# POSIX shell utilities — matching Steward's stdlib-only, "buildable by anyone
# with just the Go toolchain" ethos. The release GitHub Actions workflow
# (.github/workflows/release.yml) runs this and then uploads dist/ to a GitHub
# Release; a maintainer can run it locally to dry-build the exact same artifacts.
#
# Version reporting is NOT injected here. The binary derives its own version from
# Go's VCS build metadata (runtime/debug.ReadBuildInfo -> Main.Version), which
# resolves to the exact tag when built from a checkout AT that tag — verified
# empirically, see docs/releasing.md. `Version` in internal/buildinfo is a `const`
# that a linker `-ldflags -X` cannot patch anyway, and injection is unnecessary
# because the tag-derived version is already correct. What this script DOES do is
# assert, on a tag build, that the binary self-reports the tag — so a build that
# silently lost its VCS stamp (a shallow clone, a missing tag, git "dubious
# ownership") fails the release loudly instead of shipping a mislabeled binary.
#
# Usage: scripts/release.sh
# Env (set automatically by GitHub Actions; optional locally):
#   GITHUB_REF_TYPE  "tag" enables the strict version assertion below.
#   GITHUB_REF_NAME  the tag (e.g. v0.1.0); used for artifact names and the assertion.
set -euo pipefail

cd "$(dirname "$0")/.."

# The published target matrix: pure-stdlib Go with CGO off, so every target is a
# trivial cross-compile from any host.
targets=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64)

# VERSION labels the artifact FILENAMES only; it never feeds the binary's own
# version string (that comes from Go's VCS metadata, above). On a tag push
# GITHUB_REF_NAME is the tag; run locally it falls back to `git describe`, then to
# "dev" outside any checkout.
VERSION="${GITHUB_REF_NAME:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"

# Fail-fast release-tag gate. The workflow's push trigger is the broad `v*`
# (GitHub's tag-filter glob cannot reliably express "semver only"), so THIS is the
# authoritative shape check: on a tag build, a tag that is not vX.Y.Z (with an
# optional -prerelease suffix) is refused here, before a single target is built,
# instead of failing late — a stray tag like `vnext` or `v2` never proceeds to a
# build or a publish. Build-metadata tags (a `+...` suffix, e.g. `v1.2.3+ci`) are
# rejected too: they are not resolvable Go module versions, so `go install
# pkg@v1.2.3+ci` — a supported install path per the README — could not install
# them; the accepted release tags are kept to installable versions only. The
# stricter version assertion at the end still runs too; this one just makes the
# common mistake fail immediately and legibly. The pattern is strict semver: no
# leading-zero numeric parts, and a prerelease is dot-separated non-empty
# identifiers (so a malformed suffix like `-a..b` or a trailing `-` is refused),
# and no build-metadata `+...` — i.e. exactly the tags that resolve as Go module
# versions for `go install pkg@vX.Y.Z`.
if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
	if [[ ! "${GITHUB_REF_NAME}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
		echo "release: FATAL — tag '${GITHUB_REF_NAME}' is not an installable semver release tag." >&2
		echo "  Expected vX.Y.Z with an optional -prerelease suffix, e.g. v0.1.0 or v0.1.0-rc.1" >&2
		echo "  (no leading-zero parts, no malformed prerelease, no build-metadata '+...' suffix —" >&2
		echo "  it must resolve as a Go module version). See docs/releasing.md." >&2
		exit 1
	fi
fi

dist="dist"
rm -rf "$dist"
mkdir -p "$dist"

for target in "${targets[@]}"; do
	goos="${target%/*}"
	goarch="${target#*/}"
	echo "release: building ${goos}/${goarch}"
	stage="$(mktemp -d)"
	# -trimpath: reproducible, no local filesystem paths in the binary.
	# -ldflags "-s -w": strip the symbol table and DWARF for a smaller binary.
	# Neither removes the VCS build metadata Main.Version is derived from.
	CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
		go build -trimpath -ldflags "-s -w" -o "${stage}/steward" ./cmd/steward
	files=(steward LICENSE README.md)
	if [ "$goos" = "linux" ]; then
		CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
			go build -trimpath -ldflags "-s -w" -o "${stage}/steward-executor" ./cmd/steward-executor
		mkdir -p "${stage}/deploy" "${stage}/scripts"
		cp -R deploy/config deploy/systemd "${stage}/deploy/"
		cp scripts/install-node.sh scripts/activate-node-release.sh \
			scripts/node-preflight.sh "${stage}/scripts/"
		chmod 0755 "${stage}"/scripts/*.sh
		files=(steward steward-executor LICENSE README.md deploy scripts)
	fi
	# Ship the license and readme alongside both binaries so the download is
	# self-contained and license-compliant.
	cp LICENSE README.md "${stage}/"
	# Never carry workstation xattrs (notably macOS provenance) into the sovereign
	# artifact. Both bsdtar and GNU tar accept --no-xattrs; COPYFILE_DISABLE also
	# suppresses AppleDouble metadata on macOS.
	COPYFILE_DISABLE=1 tar --no-xattrs -C "${stage}" \
		-czf "${dist}/steward_${VERSION}_${goos}_${goarch}.tar.gz" \
		"${files[@]}"
	rm -rf "${stage}"
done

# SHA-256 over every archive, in one checksums.txt (the conventional shape a
# consumer verifies with `sha256sum -c`). Prefer sha256sum (Linux/CI); fall back
# to shasum -a 256 (macOS) so the script runs identically on a maintainer's Mac.
(
	cd "$dist"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum ./*.tar.gz >checksums.txt
	else
		shasum -a 256 ./*.tar.gz >checksums.txt
	fi
)

# Version-assertion gate. Build the host-native binary and read the version it
# reports. On a tag build this MUST equal the tag; if it does not, Go failed to
# stamp the tag as the module version (a shallow checkout, a lost tag, or git
# "dubious ownership" in CI) and we would otherwise publish a binary whose
# `-version` disagrees with its release. Fail closed and name the fix.
native_dir="$(mktemp -d)"
go build -trimpath -ldflags "-s -w" -o "$native_dir/steward" ./cmd/steward
go build -trimpath -ldflags "-s -w" -o "$native_dir/steward-executor" ./cmd/steward-executor
reported="$("$native_dir/steward" -version | awk '{print $2}')"
executor_reported="$("$native_dir/steward-executor" -version | awk '{print $2}')"
echo "release: host-native steward self-reports version '${reported}'"
echo "release: host-native steward-executor self-reports version '${executor_reported}'"
if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
	if [ "${reported}" != "${GITHUB_REF_NAME}" ] || [ "${executor_reported}" != "${GITHUB_REF_NAME}" ]; then
		echo "release: FATAL — steward reports '${reported}' and steward-executor reports '${executor_reported}', but the tag is '${GITHUB_REF_NAME}'." >&2
		echo "  Go did not stamp the tag as the module version, so the release binaries" >&2
		echo "  would misreport their version. Ensure the release job checks out the tag" >&2
		echo "  with full history (actions/checkout fetch-depth: 0). See docs/releasing.md." >&2
		exit 1
	fi
	echo "release: version assertion OK — both binaries self-report the tag ${GITHUB_REF_NAME}"
fi
rm -rf "$native_dir"

echo "release: artifacts in ${dist}/:"
ls -1 "$dist"
