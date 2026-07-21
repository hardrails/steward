#!/bin/bash -p
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
# with its filename. The host-native assertion below independently executes every
# binaries and fails a release if the stamp ever stops working.
#
# Usage: scripts/release.sh
# Env (set automatically by GitHub Actions; optional locally):
#   GITHUB_REF_TYPE         "tag" enables the strict version assertion below.
#   GITHUB_REF_NAME         the tag (e.g. v0.1.0); used for artifact names and the assertion.
#   STEWARD_RELEASE_VERSION explicit path-safe artifact and binary version. CI
#                           uses the tag, or v0.0.0-dev.<commit> for a dry-run.
#   STEWARD_RELEASE_TARGETS whitespace-separated GOOS/GOARCH targets. The default
#                           remains the complete public matrix. CI narrows this to
#                           one architecture per native package-building runner.
set -euo pipefail
if ! shopt -qo privileged; then
	echo "release: invoke this script with /bin/bash -p so caller-controlled shell startup files and exported functions are ignored" >&2
	exit 2
fi
unset BASH_ENV ENV TAR_OPTIONS GZIP POSIXLY_CORRECT

cd "$(dirname "$0")/.."

# The manifest writer and privileged installer deliberately keep closed file
# inventories. Refuse the release before building anything if those inventories
# drift, because such an artifact would reject its own integrity manifest.
/bin/bash -p scripts/check-release-inventory.sh
/bin/bash -p scripts/check-docs-consistency.sh
/bin/bash -p scripts/check-cli-docs-contract.sh

# The published target matrix: pure-stdlib Go with CGO off, so every target is a
# trivial cross-compile from any host.
default_targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64"
target_input=${STEWARD_RELEASE_TARGETS:-$default_targets}
targets=()
while IFS= read -r target_line; do
	line_targets=()
	read -r -a line_targets <<<"$target_line"
	targets+=("${line_targets[@]}")
done <<<"$target_input"
if (( ${#targets[@]} == 0 )); then
	echo "release: STEWARD_RELEASE_TARGETS selected no targets" >&2
	exit 2
fi
for target in "${targets[@]}"; do
	case "$target" in
		linux/amd64 | linux/arm64 | darwin/amd64 | darwin/arm64) ;;
		*)
			echo "release: unsupported target '$target'" >&2
			exit 2
			;;
	esac
done

# VERSION labels artifacts and is stamped into every shipped binary. On a tag push
# GITHUB_REF_NAME is authoritative; a local dry run falls back to `git describe`,
# then to "dev" outside any checkout.
VERSION="${STEWARD_RELEASE_VERSION:-${GITHUB_REF_NAME:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}}"

valid_release_version() {
	local candidate=$1 core prerelease identifier
	(( ${#candidate} <= 128 )) || return 1
	[[ $candidate =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$ ]] || return 1
	core=${candidate#v}
	if [[ $core == *-* ]]; then
		prerelease=${core#*-}
		IFS=. read -r -a identifiers <<<"$prerelease"
		for identifier in "${identifiers[@]}"; do
			if [[ $identifier =~ ^[0-9]+$ && $identifier == 0[0-9]* ]]; then
				return 1
			fi
		done
	fi
	return 0
}

if [[ ${STEWARD_RELEASE_VERSION+x} == x ]] && ! valid_release_version "$VERSION"; then
	echo "release: explicit STEWARD_RELEASE_VERSION must be a release tag of at most 128 bytes" >&2
	exit 2
fi

if [[ ${GITHUB_REF_TYPE:-} != tag ]] && ! valid_release_version "$VERSION"; then
	dev_identity=${VERSION//[^0-9A-Za-z-]/-}
	dev_prefix=v0.0.0-dev.source-
	dev_identity=${dev_identity:-local}
	VERSION="${dev_prefix}${dev_identity:0:$((128 - ${#dev_prefix}))}"
	valid_release_version "$VERSION" || { echo "release: could not derive a bounded development release identity" >&2; exit 2; }
fi
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
	if ! valid_release_version "${GITHUB_REF_NAME}"; then
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
	CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
		go build -trimpath -ldflags "$release_ldflags" -o "${stage}/stewardctl" ./cmd/stewardctl
	CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
		go build -trimpath -ldflags "$release_ldflags" -o "${stage}/steward-mcp" ./cmd/steward-mcp
	CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
		go build -trimpath -ldflags "$release_ldflags" -o "${stage}/steward-control" ./cmd/steward-control
	files=(steward steward-control stewardctl steward-mcp LICENSE README.md)
	mkdir -p "${stage}/examples" "${stage}/schemas"
	cp -R examples/agents examples/policy "${stage}/examples/"
	cp schemas/agent.cue "${stage}/schemas/"
	files=(steward steward-control stewardctl steward-mcp LICENSE README.md examples schemas)
	if [ "$goos" = "linux" ]; then
		CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
			go build -trimpath -ldflags "$release_ldflags" -o "${stage}/steward-executor" ./cmd/steward-executor
		CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
			go build -trimpath -ldflags "$release_ldflags" -o "${stage}/steward-gateway" ./cmd/steward-gateway
		CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
			go build -trimpath -ldflags "$release_ldflags" -o "${stage}/steward-relay" ./cmd/steward-relay
		CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
			go build -trimpath -ldflags "$release_ldflags" -o "${stage}/steward-storage-zfs" ./cmd/steward-storage-zfs
		# The controller is deployed independently from the Docker-bearing node
		# appliance. Publish a small, closed-inventory archive for install-control.sh
		# instead of allowing controller authority to ride inside a node package.
		control_stage="$(mktemp -d)"
		install -m 0755 "${stage}/steward-control" "${control_stage}/steward-control"
		install -m 0755 scripts/control-doctor.sh "${control_stage}/control-doctor.sh"
		install -m 0644 deploy/systemd/steward-control.service "${control_stage}/steward-control.service"
		install -m 0644 deploy/config/control.env "${control_stage}/control.env"
		install -m 0644 LICENSE "${control_stage}/LICENSE"
		control_archive="${dist}/steward-control_${VERSION}_linux_${goarch}.tar.gz"
		control_files=(LICENSE control.env control-doctor.sh steward-control steward-control.service)
		if tar --no-xattrs -cf /dev/null -T /dev/null >/dev/null 2>&1; then
			COPYFILE_DISABLE=1 tar --no-xattrs -C "$control_stage" -czf "$control_archive" "${control_files[@]}"
		else
			COPYFILE_DISABLE=1 tar -C "$control_stage" -czf "$control_archive" "${control_files[@]}"
		fi
		rm -rf "$control_stage"
		mkdir -p "${stage}/adapters" "${stage}/deploy" "${stage}/scripts"
		cp -R adapters/hermes-agent adapters/openclaw "${stage}/adapters/"
		cp -R deploy/config deploy/systemd "${stage}/deploy/"
		# Controller deployment assets belong only to the dedicated archive. The
		# node archive and native packages retain the binary for operator tooling,
		# but never install or activate a controller service.
		rm -f "${stage}/deploy/config/control.env" \
			"${stage}/deploy/systemd/steward-control.service"
		cp scripts/install-node.sh scripts/activate-node-release.sh \
			scripts/node-preflight.sh scripts/node-doctor.sh scripts/configure-node.sh scripts/configure-admission.sh \
			scripts/uninstall-node.sh scripts/node-removal-guard.sh scripts/build-relay-image.sh \
			scripts/build-hermes-adapter.sh scripts/hermes-feasibility.sh \
			scripts/hermes-steward-acceptance.sh scripts/build-openclaw-adapter.sh \
			scripts/openclaw-feasibility.sh \
			"${stage}/scripts/"
		chmod 0755 "${stage}"/scripts/*.sh
		# Bind the exact node payload before wrapping it in an archive or native
		# package. The canonical manifest records the target and SHA-256 of every
		# binaries plus every integration file installed with that release.
		/bin/bash -p scripts/write-release-manifest.sh "$stage" "$VERSION" "$goos" "$goarch"
		files=(steward steward-control stewardctl steward-mcp steward-executor steward-gateway steward-relay steward-storage-zfs release.json LICENSE README.md adapters deploy scripts examples schemas)
	fi
	# Ship the license and readme alongside every binary so the download is
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
		/bin/bash -p scripts/build-deb.sh "$stage" "$VERSION" "$goarch" \
			"${dist}/steward-node_${VERSION}_${goarch}.deb"
	elif [ "$goos" = "linux" ]; then
		echo "release: dpkg-deb unavailable; skipping Debian package for ${goarch}"
	fi
	if [ "$goos" = "linux" ] && command -v rpmbuild >/dev/null 2>&1; then
		/bin/bash -p scripts/build-rpm.sh "$stage" "$VERSION" "$goarch" \
			"${dist}/steward-node_${VERSION}_${goarch}.rpm"
	elif [ "$goos" = "linux" ]; then
		echo "release: rpmbuild unavailable; skipping RPM package for ${goarch}"
	fi
	rm -rf "${stage}"
done

# The reviewed installer is itself a release asset so users can download one
# immutable script beside the packages, or carry it into an air-gapped site.
install -m 0755 scripts/install-steward.sh "${dist}/install-steward.sh"
install -m 0755 scripts/install-control.sh "${dist}/install-control.sh"
install -m 0755 scripts/install-macos.sh "${dist}/install-macos.sh"

# SHA-256 over every archive, in one checksums.txt (the conventional shape a
# consumer verifies with `sha256sum -c`). Prefer sha256sum (Linux/CI); fall back
# to shasum -a 256 (macOS) so the script runs identically on a maintainer's Mac.
(
	cd "$dist"
	shopt -s nullglob
	artifacts=(./*.tar.gz ./*.deb ./*.rpm ./install-steward.sh ./install-control.sh ./install-macos.sh)
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

# Version-assertion gate. Build every host-native binary and require each one to
# report the exact VERSION stamped into the artifacts. This runs for tag builds,
# manual workflow dispatches, and local dry runs.
native_dir="$(mktemp -d)"
go build -trimpath -ldflags "$release_ldflags" -o "$native_dir/steward" ./cmd/steward
go build -trimpath -ldflags "$release_ldflags" -o "$native_dir/steward-control" ./cmd/steward-control
go build -trimpath -ldflags "$release_ldflags" -o "$native_dir/steward-executor" ./cmd/steward-executor
go build -trimpath -ldflags "$release_ldflags" -o "$native_dir/stewardctl" ./cmd/stewardctl
go build -trimpath -ldflags "$release_ldflags" -o "$native_dir/steward-mcp" ./cmd/steward-mcp
go build -trimpath -ldflags "$release_ldflags" -o "$native_dir/steward-gateway" ./cmd/steward-gateway
go build -trimpath -ldflags "$release_ldflags" -o "$native_dir/steward-relay" ./cmd/steward-relay
go build -trimpath -ldflags "$release_ldflags" -o "$native_dir/steward-storage-zfs" ./cmd/steward-storage-zfs
reported="$("$native_dir/steward" -version | awk '{print $2}')"
control_reported="$("$native_dir/steward-control" -version | awk '{print $2}')"
executor_reported="$("$native_dir/steward-executor" -version | awk '{print $2}')"
ctl_reported="$("$native_dir/stewardctl" -version | awk '{print $2}')"
mcp_reported="$("$native_dir/steward-mcp" -version | awk '{print $2}')"
gateway_reported="$("$native_dir/steward-gateway" -version | awk '{print $2}')"
relay_reported="$("$native_dir/steward-relay" -version | awk '{print $2}')"
storage_reported="$("$native_dir/steward-storage-zfs" -version | awk '{print $2}')"
echo "release: host-native steward self-reports version '${reported}'"
echo "release: host-native steward-control self-reports version '${control_reported}'"
echo "release: host-native steward-executor self-reports version '${executor_reported}'"
echo "release: host-native stewardctl self-reports version '${ctl_reported}'"
echo "release: host-native steward-mcp self-reports version '${mcp_reported}'"
echo "release: host-native steward-gateway self-reports version '${gateway_reported}'"
echo "release: host-native steward-relay self-reports version '${relay_reported}'"
echo "release: host-native steward-storage-zfs self-reports version '${storage_reported}'"
if [ "${reported}" != "${VERSION}" ] || [ "${control_reported}" != "${VERSION}" ] || [ "${executor_reported}" != "${VERSION}" ] || [ "${ctl_reported}" != "${VERSION}" ] || [ "${mcp_reported}" != "${VERSION}" ] || [ "${gateway_reported}" != "${VERSION}" ] || [ "${relay_reported}" != "${VERSION}" ] || [ "${storage_reported}" != "${VERSION}" ]; then
	echo "release: FATAL — one or more release binaries do not report version '${VERSION}'." >&2
	echo "  The explicit release-version linker stamp did not reach every binary," >&2
	echo "  so the artifacts would misreport their version. Ensure scripts/release.sh" >&2
	echo "  supplies release_ldflags to every entry point. See docs/releasing.md." >&2
	exit 1
fi
echo "release: version assertion OK — every binary self-reports ${VERSION}"
rm -rf "$native_dir"

echo "release: artifacts in ${dist}/:"
ls -1 "$dist"
