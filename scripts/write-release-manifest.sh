#!/usr/bin/env bash
# Write the canonical manifest for one Linux node release stage.
set -euo pipefail

if [[ $# -ne 4 ]]; then
	echo "usage: $0 STAGE VERSION linux amd64|arm64" >&2
	exit 2
fi

stage=$1
version=$2
goos=$3
goarch=$4

valid_release_version() {
	local candidate=$1 core prerelease identifier
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

if [[ ! -d $stage || -L $stage ]]; then
	echo "write-release-manifest: stage must be a directory, not a symlink: $stage" >&2
	exit 2
fi
if ! valid_release_version "$version"; then
	echo "write-release-manifest: version must be an installable vX.Y.Z release tag" >&2
	exit 2
fi
if [[ $goos != linux ]]; then
	echo "write-release-manifest: the node release manifest supports Linux only" >&2
	exit 2
fi
case "$goarch" in amd64 | arm64) ;; *)
	echo "write-release-manifest: architecture must be amd64 or arm64" >&2
	exit 2
	;;
esac

# Logical integration paths match their immutable installed location under
# /opt/steward/releases/<version>. The release build stage keeps the repository's
# deploy/ and scripts/ layout, so logical_source removes only this fixed prefix.
release_files=(
	steward
	steward-executor
	steward-gateway
	steward-mcp
	steward-relay
	stewardctl
	integration/deploy/config/executor-gateway.env
	integration/deploy/config/executor.env
	integration/deploy/config/gateway.json.in
	integration/deploy/config/steward-local.json
	integration/deploy/config/steward.json
	integration/deploy/systemd/steward-executor.service
	integration/deploy/systemd/steward-gateway.service
	integration/deploy/systemd/steward.service
	integration/scripts/activate-node-release.sh
	integration/scripts/build-relay-image.sh
	integration/scripts/configure-admission.sh
	integration/scripts/configure-node.sh
	integration/scripts/install-node.sh
	integration/scripts/node-preflight.sh
	integration/scripts/node-removal-guard.sh
	integration/scripts/uninstall-node.sh
)

logical_source() {
	local logical=$1
	if [[ $logical == integration/* ]]; then
		printf '%s/%s\n' "$stage" "${logical#integration/}"
	else
		printf '%s/%s\n' "$stage" "$logical"
	fi
}

hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		echo "write-release-manifest: sha256sum or shasum is required" >&2
		exit 2
	fi
}

for logical in "${release_files[@]}"; do
	source_path=$(logical_source "$logical")
	if [[ ! -f $source_path || -L $source_path ]]; then
		echo "write-release-manifest: release stage is missing regular file $source_path" >&2
		exit 2
	fi
done

manifest_tmp=$(mktemp "${stage}/.release.json.XXXXXX")
cleanup() { rm -f "$manifest_tmp"; }
trap cleanup EXIT HUP INT TERM
{
	printf '{\n'
	printf '  "schema": "steward.release.v2",\n'
	printf '  "version": "%s",\n' "$version"
	printf '  "os": "%s",\n' "$goos"
	printf '  "arch": "%s",\n' "$goarch"
	printf '  "state_formats": {\n'
	printf '    "admission_fence": {"read_min": 1, "read_max": 2, "write": 2},\n'
	printf '    "evidence_log": {"read_min": 1, "read_max": 1, "write": 1},\n'
	printf '    "gateway_state": {"read_min": 1, "read_max": 2, "write": 2},\n'
	printf '    "operation_journal": {"read_min": 1, "read_max": 1, "write": 1},\n'
	printf '    "supervisor_state": {"read_min": 1, "read_max": 1, "write": 1},\n'
	printf '    "uplink_state": {"read_min": 2, "read_max": 2, "write": 2}\n'
	printf '  },\n'
	printf '  "files": {\n'
	last_index=$((${#release_files[@]} - 1))
	for index in "${!release_files[@]}"; do
		logical=${release_files[$index]}
		source_path=$(logical_source "$logical")
		suffix=,
		(( index == last_index )) && suffix=
		printf '    "%s": "%s"%s\n' "$logical" "$(hash_file "$source_path")" "$suffix"
	done
	printf '  }\n'
	printf '}\n'
} >"$manifest_tmp"
chmod 0644 "$manifest_tmp"
mv -f "$manifest_tmp" "$stage/release.json"
trap - EXIT

echo "write-release-manifest: wrote $stage/release.json"
