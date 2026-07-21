#!/usr/bin/env bash
# Reject documented stewardctl command paths that the binary built from the
# same source does not expose. Tagged docs and artifacts then share a contract;
# the Pages layout separately warns when current source leads an older install.
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/steward-cli-docs.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

go build -o "$work/stewardctl" "$root/cmd/stewardctl"
roots=$("$work/stewardctl" __complete "")
failed=false
while read -r command subcommand; do
	[[ -n ${command:-} ]] || continue
	if ! grep -Fxq -- "$command" <<<"$roots"; then
		echo "CLI docs contract: documented command does not exist: stewardctl $command" >&2
		failed=true
		continue
	fi
	[[ -n ${subcommand:-} ]] || continue
	candidates=$("$work/stewardctl" __complete "$command" "")
	if ! grep -Fxq -- "$subcommand" <<<"$candidates"; then
		echo "CLI docs contract: documented subcommand does not exist: stewardctl $command $subcommand" >&2
		failed=true
	fi
done < <(
	while IFS= read -r -d '' path; do
		awk '
			/^```/ { fenced = !fenced; next }
			/cli-contract-ignore/ { ignore_next = 1; next }
			{
				if (ignore_next) { ignore_next = 0; next }
				line = $0
				if (fenced && match(line, /stewardctl[[:space:]]+[a-z][a-z0-9-]*([[:space:]]+[a-z][a-z0-9-]*)?/)) {
					print substr(line, RSTART, RLENGTH)
				}
				while (match(line, /`stewardctl[[:space:]]+[a-z][a-z0-9-]*([[:space:]]+[a-z][a-z0-9-]*)?/)) {
					print substr(line, RSTART + 1, RLENGTH - 1)
					line = substr(line, RSTART + RLENGTH)
				}
			}
		' "$path"
	done < <(printf '%s\0%s\0' "$root/README.md" "$root/ARCHITECTURE.md"; \
		find "$root/docs" -type f -name '*.md' -print0) |
		awk '{ print $2, $3 }' | sort -u
)

if [[ $failed == true ]]; then
	exit 1
fi
echo "CLI docs contract: every documented stewardctl command path exists"
