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
	integration/adapters/hermes-agent/Dockerfile
	integration/adapters/hermes-agent/README.md
	integration/adapters/hermes-agent/adapter.json
	integration/adapters/hermes-agent/entrypoint.py
	integration/adapters/hermes-agent/fixture_connector.py
	integration/adapters/hermes-agent/fixture_mcp.py
	integration/adapters/hermes-agent/fixture_model.py
	integration/adapters/hermes-agent/fixture_secret_scan.py
	integration/adapters/hermes-agent/fixtures/connector-skill/SKILL.md
	integration/adapters/hermes-agent/fixtures/connector-skill/connector-fixture-contract.json
	integration/adapters/hermes-agent/fixtures/connector-skill/connector_work.py
	integration/adapters/hermes-agent/fixtures/connector-skill/manifest.json
	integration/adapters/hermes-agent/fixtures/connector-skill/manifest.sig
	integration/adapters/hermes-agent/fixtures/connector-skill/public.pem
	integration/adapters/hermes-agent/fixtures/skill/SKILL.md
	integration/adapters/hermes-agent/fixtures/skill/manifest.json
	integration/adapters/hermes-agent/fixtures/skill/manifest.sig
	integration/adapters/hermes-agent/fixtures/skill/public.pem
	integration/adapters/hermes-agent/fixtures/skill/workspace-fixture-contract.json
	integration/adapters/hermes-agent/fixtures/skill/workspace_audit.py
	integration/adapters/hermes-agent/license-inventory.json
	integration/adapters/hermes-agent/source-inputs.sha256
	integration/deploy/config/executor-gateway.env
	integration/deploy/config/executor.env
	integration/deploy/config/gateway.json.in
	integration/deploy/config/steward-local.json
	integration/deploy/config/steward.json
	integration/deploy/systemd/steward-executor.service
	integration/deploy/systemd/steward-gateway.service
	integration/deploy/systemd/steward.service
	integration/scripts/activate-node-release.sh
	integration/scripts/build-hermes-adapter.sh
	integration/scripts/build-relay-image.sh
	integration/scripts/configure-admission.sh
	integration/scripts/configure-node.sh
	integration/scripts/install-node.sh
	integration/scripts/hermes-feasibility.sh
	integration/scripts/hermes-steward-acceptance.sh
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

# The adapter directory is copied recursively into every Linux artifact. Keep
# that recursive payload closed over the explicit manifest above: an unreviewed
# file, empty directory, symlink, or special file must not ride alongside the
# signed skill without a digest in release.json.
adapter_root=$stage/adapters/hermes-agent
for directory in "$adapter_root" "$adapter_root/fixtures" "$adapter_root/fixtures/connector-skill" "$adapter_root/fixtures/skill"; do
	if [[ ! -d $directory || -L $directory ]]; then
		echo "write-release-manifest: adapter directory is missing or invalid: $directory" >&2
		exit 2
	fi
done
if find "$adapter_root" -mindepth 1 -type l -print -quit | grep -q . ||
	find "$adapter_root" -mindepth 1 ! -type f ! -type d -print -quit | grep -q .; then
	echo "write-release-manifest: adapter contains a symlink or special file" >&2
	exit 2
fi
expected_adapter_file_count=0
for logical in "${release_files[@]}"; do
	case "$logical" in
		integration/adapters/hermes-agent/*) ((expected_adapter_file_count += 1)) ;;
	esac
done
adapter_file_count=$(find "$adapter_root" -type f | wc -l)
adapter_directory_count=$(find "$adapter_root" -type d | wc -l)
if [[ $adapter_file_count -ne $expected_adapter_file_count || $adapter_directory_count -ne 4 ]]; then
	echo "write-release-manifest: adapter contains an unexpected file or directory" >&2
	exit 2
fi

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
	printf '    "connector_receipt_log": {"read_min": 1, "read_max": 3, "write": 3},\n'
	printf '    "evidence_log": {"read_min": 1, "read_max": 1, "write": 1},\n'
	printf '    "gateway_state": {"read_min": 1, "read_max": 4, "write": 4},\n'
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
