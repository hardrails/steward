#!/usr/bin/env bash
# Cross-compile Steward for every published target, package each build as a
# self-contained .tar.gz (the target's usable process binaries + LICENSE + README;
# Linux also carries the offline node-appliance assets), and write a SHA-256 checksums
# file over every artifact. Archive builds need only the Go toolchain and shell;
# optional native packages use the platform's dpkg-deb and rpmbuild tools. These
# remain release-time tools, never Go module or runtime dependencies. The release GitHub Actions workflow
# (.github/workflows/release.yml) runs this and then uploads dist/ to a GitHub
# Release; a maintainer can run it locally to dry-build the exact same artifacts.
#
# Published binaries receive VERSION through the Go linker's standard -X string
# injection. Checkout builds otherwise have Main.Version="(devel)" and VCS metadata
# identifies a commit rather than the release tag; -trimpath may omit that metadata
# entirely. The explicit stamp makes every cross-compiled archive and package agree
# with its filename. The host-native assertion below independently executes both
# binaries and fails a release if the stamp ever stops working.
#
# Usage: scripts/release.sh
# Env (set automatically by GitHub Actions; optional locally):
#   GITHUB_REF_TYPE         "tag" enables the strict version assertion below.
#   GITHUB_REF_NAME         the tag (e.g. v0.1.0); used for artifact names and the assertion.
#   STEWARD_RELEASE_VERSION explicit path-safe artifact and binary version. CI
#                           uses the tag, or dev-<commit> for a manual dry-run.
#   STEWARD_RELEASE_TARGETS whitespace-separated GOOS/GOARCH targets. The default
#                           remains the complete public matrix. CI narrows this to
#                           one architecture per native package-building runner.
set -euo pipefail

cd "$(dirname "$0")/.."

# The published target matrix: pure-stdlib Go with CGO off, so every target is a
# trivial cross-compile from any host.
default_targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64"
read -r -a targets <<<"${STEWARD_RELEASE_TARGETS:-$default_targets}"
if (( ${#targets[@]} == 0 )); then
	echo "release: STEWARD_RELEASE_TARGETS selected no targets" >&2
	exit 2
fi

# VERSION labels artifacts and is stamped into both binaries. On a tag push
# GITHUB_REF_NAME is authoritative; a local dry run falls back to `git describe`,
# then to "dev" outside any checkout.
VERSION="${STEWARD_RELEASE_VERSION:-${GITHUB_REF_NAME:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}}"
release_ldflags="-s -w -X github.com/hardrails/steward/internal/buildinfo.releaseVersion=${VERSION}"

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
	# -s -w strips the symbol table and DWARF; -X supplies the release identity.
	CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
		go build -trimpath -ldflags "$release_ldflags" -o "${stage}/steward" ./cmd/steward
	files=(steward LICENSE README.md)
	if [ "$goos" = "linux" ]; then
		CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
			go build -trimpath -ldflags "$release_ldflags" -o "${stage}/steward-executor" ./cmd/steward-executor
		mkdir -p "${stage}/deploy" "${stage}/scripts"
		cp -R deploy/config deploy/systemd "${stage}/deploy/"
		cp scripts/install-node.sh scripts/activate-node-release.sh \
			scripts/node-preflight.sh scripts/configure-node.sh \
			scripts/uninstall-node.sh \
			"${stage}/scripts/"
		chmod 0755 "${stage}"/scripts/*.sh
		files=(steward steward-executor LICENSE README.md deploy scripts)
	fi
	# Ship the license and readme alongside both binaries so the download is
	# self-contained and license-compliant.
	cp LICENSE README.md "${stage}/"
	# Never carry workstation xattrs (notably macOS provenance) into the sovereign
	# artifact. COPYFILE_DISABLE handles macOS; use --no-xattrs where the installed
	# tar accepts it, without making a local dry run depend on that extension.
	if tar --no-xattrs -cf /dev/null -T /dev/null >/dev/null 2>&1; then
		COPYFILE_DISABLE=1 tar --no-xattrs -C "${stage}" \
			-czf "${dist}/steward_${VERSION}_${goos}_${goarch}.tar.gz" \
			"${files[@]}"
	else
		COPYFILE_DISABLE=1 tar -C "${stage}" \
			-czf "${dist}/steward_${VERSION}_${goos}_${goarch}.tar.gz" \
			"${files[@]}"
	fi
	if [ "$goos" = "linux" ] && command -v dpkg-deb >/dev/null 2>&1; then
		bash scripts/build-deb.sh "$stage" "$VERSION" "$goarch" \
			"${dist}/steward-node_${VERSION}_${goarch}.deb"
	elif [ "$goos" = "linux" ]; then
		echo "release: dpkg-deb unavailable; skipping Debian package for ${goarch}"
	fi
	if [ "$goos" = "linux" ] && command -v rpmbuild >/dev/null 2>&1; then
		bash scripts/build-rpm.sh "$stage" "$VERSION" "$goarch" \
			"${dist}/steward-node_${VERSION}_${goarch}.rpm"
	elif [ "$goos" = "linux" ]; then
		echo "release: rpmbuild unavailable; skipping RPM package for ${goarch}"
	fi
	rm -rf "${stage}"
done

# The reviewed installer is itself a release asset so users can download one
# immutable script beside the packages, or carry it into an air-gapped site.
install -m 0755 scripts/install-steward.sh "${dist}/install-steward.sh"

# SHA-256 over every archive, in one checksums.txt (the conventional shape a
# consumer verifies with `sha256sum -c`). Prefer sha256sum (Linux/CI); fall back
# to shasum -a 256 (macOS) so the script runs identically on a maintainer's Mac.
(
	cd "$dist"
	shopt -s nullglob
	artifacts=(./*.tar.gz ./*.deb ./*.rpm ./install-steward.sh)
	if (( ${#artifacts[@]} == 0 )); then
		echo "release: no artifacts were built" >&2
		exit 1
	fi
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "${artifacts[@]}" >checksums.txt
	else
		shasum -a 256 "${artifacts[@]}" >checksums.txt
	fi
)

# Version-assertion gate. Build the host-native binary and read the version it
# reports. On a tag build this MUST equal the tag; otherwise the linker stamp is
# broken and the package lifecycle would address a different release directory.
native_dir="$(mktemp -d)"
go build -trimpath -ldflags "$release_ldflags" -o "$native_dir/steward" ./cmd/steward
go build -trimpath -ldflags "$release_ldflags" -o "$native_dir/steward-executor" ./cmd/steward-executor
reported="$("$native_dir/steward" -version | awk '{print $2}')"
executor_reported="$("$native_dir/steward-executor" -version | awk '{print $2}')"
echo "release: host-native steward self-reports version '${reported}'"
echo "release: host-native steward-executor self-reports version '${executor_reported}'"
if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
	if [ "${reported}" != "${GITHUB_REF_NAME}" ] || [ "${executor_reported}" != "${GITHUB_REF_NAME}" ]; then
		echo "release: FATAL — steward reports '${reported}' and steward-executor reports '${executor_reported}', but the tag is '${GITHUB_REF_NAME}'." >&2
		echo "  The explicit release-version linker stamp did not reach both binaries," >&2
		echo "  so the artifacts would misreport their version. Ensure scripts/release.sh" >&2
		echo "  supplies release_ldflags to both entry points. See docs/releasing.md." >&2
		exit 1
	fi
	echo "release: version assertion OK — both binaries self-report the tag ${GITHUB_REF_NAME}"
fi
rm -rf "$native_dir"

echo "release: artifacts in ${dist}/:"
ls -1 "$dist"
