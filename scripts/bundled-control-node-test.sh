#!/usr/bin/env bash
# Hermetic plan and static safety checks for bundled-control node enrollment.
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
installer="$root/scripts/install-steward.sh"
configurator="$root/scripts/configure-node.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/steward-bundled-control-test.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

common_remote=(
	--non-interactive
	--dry-run
	--version v0.0.0
	--package tar
	--control-plane-url https://control.example.test
	--executor-credential /trust/node-credential.json
	--ca-file /trust/control-ca.pem
)
signed_admission=(
	--admission-policy /trust/site-policy.dsse.json
	--site-root-public-key /trust/site-root.public
	--site-root-key-id site-root
	--node-id node-1
)

bash -n "$installer" "$configurator"

bash "$installer" "${common_remote[@]}" "${signed_admission[@]}" \
	>"$work/bundled.plan"
grep -Fqx '  enrollment:   bundled-control-executor-only' "$work/bundled.plan"
grep -Fqx '  admission:    signed' "$work/bundled.plan"

bash "$installer" "${common_remote[@]}" \
	--steward-credential /trust/generic-supervisor.json \
	>"$work/generic.plan"
grep -Fqx '  enrollment:   generic-supervisor-and-executor' "$work/generic.plan"
grep -Fqx '  admission:    unchanged' "$work/generic.plan"

if bash "$installer" "${common_remote[@]}" >"$work/unsigned.out" 2>"$work/unsigned.err"; then
	echo "bundled-control-node-test: bundled control accepted missing signed admission" >&2
	exit 1
fi
grep -Fqx \
	'install-steward: bundled steward-control enrollment requires complete signed-admission inputs' \
	"$work/unsigned.err"

bash "$installer" --non-interactive --dry-run --local-only \
	--version v0.0.0 --package tar >"$work/local.plan"
grep -Fqx '  enrollment:   local-only' "$work/local.plan"
bash "$installer" --non-interactive --dry-run --stage-only \
	--version v0.0.0 --package tar >"$work/staged.plan"
grep -Fqx '  enrollment:   staged-only' "$work/staged.plan"

# Exercise the exact generator used for both local-only and Executor-only
# supervisor configuration without touching host paths or requiring root.
awk '
	/^write_loopback_supervisor_config\(\) \{/ { copying = 1 }
	copying && /^steward_tmp=/ { exit }
	copying { print }
' "$configurator" >"$work/config-function.sh"
# shellcheck source=/dev/null
source "$work/config-function.sh"
write_loopback_supervisor_config >"$work/actual.json"
cat >"$work/expected.json" <<'EOF'
{
  "addr": "127.0.0.1:8080",
  "disable_inbound_listener": false,
  "enable_process_exec": false,
  "log_level": "info",
  "max_instances": 1024,
  "state_file": "/var/lib/steward/state.json"
}
EOF
cmp "$work/expected.json" "$work/actual.json"
if grep -Eq 'uplink|allow_nonloopback_process_exec' "$work/actual.json"; then
	echo "bundled-control-node-test: loopback supervisor config contains remote or unsafe settings" >&2
	exit 1
fi

# Keep the transaction's stale-credential deletion and delivery-state rollback
# guard visible to this focused regression check.
grep -Fq 'rm -f -- /etc/steward/uplink-credential.json' "$configurator"
grep -Fq 'uplink_delivery_state_created=true' "$configurator"
grep -Fq 'steward-control requires a node-scoped Executor credential' "$configurator"

echo "bundled-control-node-test: bundled control enrollment checks passed"
