#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
if [[ ! -x $root/scripts/build-buzz-bridge.sh || ! -d $root/prebuilt ]]; then
	printf '%s\n' 'build-buzz: this entry point must be run from an extracted Steward Buzz release kit' >&2
	exit 1
fi
exec "$root/scripts/build-buzz-bridge.sh" --steward-binaries "$root/prebuilt" "$@"
