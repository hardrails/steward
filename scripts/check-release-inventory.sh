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
if ! cmp -s "$work/manifest" "$work/installer"; then
	echo "check-release-inventory: manifest writer and node installer inventories differ" >&2
	diff -u "$work/manifest" "$work/installer" >&2 || true
	exit 1
fi

echo "check-release-inventory: node release inventory is synchronized"
