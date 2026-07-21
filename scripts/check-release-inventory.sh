#!/usr/bin/env bash
# Keep the manifest writer and privileged node installer on one exact payload.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM

read_inventory() {
	local script=$1 output=$2
	awk '
		/^release_files=\($/ { inside=1; next }
		inside && /^\)$/ { exit }
		inside {
			sub(/^[[:space:]]+/, "")
			if (length($0) > 0) print
		}
	' "$script" >"$output"
	[[ -s $output ]] || {
		echo "check-release-inventory: could not read release_files from $script" >&2
		return 1
	}
	while IFS= read -r path; do
		if [[ ! $path =~ ^[A-Za-z0-9._/-]+$ || $path == /* || $path == *//* ||
			$path == '..' || $path == ../* || $path == */../* || $path == */.. ]]; then
			echo "check-release-inventory: unsafe release path '$path' in $script" >&2
			return 1
		fi
	done <"$output"
	if [[ $(sort "$output" | uniq -d | wc -l) -ne 0 ]]; then
		echo "check-release-inventory: duplicate release path in $script" >&2
		return 1
	fi
}

read_inventory "$root/scripts/write-release-manifest.sh" "$work/manifest"
read_inventory "$root/scripts/install-node.sh" "$work/installer"
# Order is part of the canonical release.json byte contract. The installer
# reconstructs the manifest in this order before cmp, so set equality is not
# sufficient: differently ordered inventories would still self-reject.
if ! cmp -s "$work/manifest" "$work/installer"; then
	echo "check-release-inventory: manifest writer and node installer inventories differ" >&2
	diff -u "$work/manifest" "$work/installer" >&2 || true
	exit 1
fi

read_state_formats() {
	local script=$1 output=$2
	awk '
		/printf .*"state_formats"/ { inside=1 }
		inside && /printf .*"files"/ { exit }
		inside {
			sub(/^[[:space:]]+/, "")
			print
		}
	' "$script" >"$output"
	[[ -s $output ]] || {
		echo "check-release-inventory: could not read state formats from $script" >&2
		return 1
	}
}

# Three independent paths create or reconstruct release.json. Keep their durable
# format contracts byte-identical, then bind Gateway's declared reader/writer
# range to the constants used by the running process. A new persisted format must
# update this gate in the same change; packaging cannot silently advertise the
# previous writer as happened when controller events introduced Gateway format 8.
read_state_formats "$root/scripts/write-release-manifest.sh" "$work/formats-manifest"
read_state_formats "$root/scripts/install-node.sh" "$work/formats-installer"
read_state_formats "$root/scripts/activate-node-release.sh" "$work/formats-activation"
for candidate in "$work/formats-installer" "$work/formats-activation"; do
	if ! cmp -s "$work/formats-manifest" "$candidate"; then
		echo "check-release-inventory: release state-format declarations differ" >&2
		diff -u "$work/formats-manifest" "$candidate" >&2 || true
		exit 1
	fi
done

gateway_format_line=$(grep -F '"gateway_state"' "$work/formats-manifest")
if [[ ! $gateway_format_line =~ read_min\":\ ([0-9]+),\ \"read_max\":\ ([0-9]+),\ \"write\":\ ([0-9]+) ]]; then
	echo "check-release-inventory: gateway state format declaration is invalid" >&2
	exit 1
fi
manifest_read_min=${BASH_REMATCH[1]}
manifest_read_max=${BASH_REMATCH[2]}
manifest_write=${BASH_REMATCH[3]}
gateway_constant() {
	local name=$1
	awk -v name="$name" '$1 == name && $2 == "=" { print $3; found=1; exit } END { if (!found) exit 1 }' \
		"$root/internal/gateway/server.go"
}
code_read_min=$(gateway_constant gatewayStateReadMinVersion)
code_read_max=$(gateway_constant gatewayStateReadMaxVersion)
code_write=$(gateway_constant gatewayStateWriteVersion)
if [[ $manifest_read_min != "$code_read_min" || $manifest_read_max != "$code_read_max" ||
	$manifest_write != "$code_write" ]]; then
	echo "check-release-inventory: gateway state format differs from runtime constants" >&2
	exit 1
fi

echo "check-release-inventory: node release inventory and state formats are synchronized"
