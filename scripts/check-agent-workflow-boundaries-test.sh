#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM

safe=$work/safe.jsx
unsafe=$work/unsafe.jsx
cat >"$safe" <<'EOF'
const schedules = api("/v1/tenants/tenant-a/schedules?limit=100", epoch);
const interactions = api("/v1/tenants/tenant-a/interactions?limit=100", epoch);
EOF
STEWARD_CONSOLE_SOURCE=$safe bash "$root/scripts/check-agent-workflow-boundaries.sh" >/dev/null

cat >"$unsafe" <<'EOF'
const result = await fetch(
  "/v1/tenants/tenant-a/schedules",
  {
    method:
      "POST",
  },
);
EOF
if STEWARD_CONSOLE_SOURCE=$unsafe bash "$root/scripts/check-agent-workflow-boundaries.sh" >/dev/null 2>&1; then
	echo "agent workflow boundary test: multiline schedule mutation was accepted" >&2
	exit 1
fi

echo "agent workflow boundary test: multiline mutations fail closed"
