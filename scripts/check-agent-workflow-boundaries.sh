#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

failed=false
authority_paths=(
	cmd/steward-control
	cmd/steward-mcp
	internal/controlplane
	internal/controlstore
	internal/mcpserver
)

# Control and MCP may transport exact tenant-signed schedule and response
# envelopes, but they must never mint that tenant authority. Test fixtures sign
# inputs so they are excluded from this production-source check.
matches=$(
	find "${authority_paths[@]}" -type f -name '*.go' ! -name '*_test.go' -print0 |
		xargs -0 grep -En '(^|[^[:alnum:]_])(schedulepermit|interactionpermit)[.]Sign[(]' ||
		true
)
if [[ -n $matches ]]; then
	printf '%s\n%s\n' \
		'agent workflow boundary: Control or MCP gained tenant schedule/interaction signing authority' \
		"$matches" >&2
	failed=true
fi

# The browser is an observation and exact-envelope transfer surface. A new
# schedule or interaction mutation here would bypass the deliberate trusted-CLI
# signing step even if the server later rejected malformed authority.
console=internal/controlplane/console/src/App.jsx
matches=$(grep -En \
	'method:[[:space:]]*"(POST|PUT|PATCH|DELETE)".*(schedules|interactions)|/(schedules|interactions).*method:[[:space:]]*"(POST|PUT|PATCH|DELETE)"' \
	"$console" || true)
if [[ -n $matches ]]; then
	printf '%s\n%s\n' \
		'agent workflow boundary: React console gained a schedule or interaction mutation' \
		"$matches" >&2
	failed=true
fi

if [[ $failed == true ]]; then
	exit 1
fi

printf '%s\n' 'agent workflow boundary: signing remains operator-side and console remains observation-only'
