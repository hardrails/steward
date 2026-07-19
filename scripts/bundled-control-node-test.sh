#!/usr/bin/env bash
# Hermetic plan and static safety checks for bundled-control node enrollment.
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
installer="$root/scripts/install-steward.sh"
configurator="$root/scripts/configure-node.sh"
admission_configurator="$root/scripts/configure-admission.sh"
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
evidence_enrollment=(
	--executor-evidence-config /trust/executor-evidence.env
	--executor-evidence-private-key /trust/node-receipts.private.pem
	--executor-evidence-public-key /trust/node-receipts.public
)

bash -n "$installer" "$configurator" "$admission_configurator"
for helper in "$installer" "$configurator" "$admission_configurator"; do
	/bin/bash -p "$helper" --help >"$work/${helper##*/}.help"
	grep -Fq -- '--allow-unquotaed-state-on-dedicated-host' "$work/${helper##*/}.help"
done

/bin/bash -p "$installer" "${common_remote[@]}" "${signed_admission[@]}" "${evidence_enrollment[@]}" \
	>"$work/bundled.plan"
grep -Fqx '  enrollment:   bundled-control-executor-only' "$work/bundled.plan"
grep -Fqx '  admission:    signed' "$work/bundled.plan"
grep -Fqx '  evidence:     witnessed-uplink' "$work/bundled.plan"
grep -Fqx '  state:        disabled' "$work/bundled.plan"

/bin/bash -p "$installer" "${common_remote[@]}" "${signed_admission[@]}" "${evidence_enrollment[@]}" \
	--allow-unquotaed-state-on-dedicated-host >"$work/dedicated-state.plan"
grep -Fqx '  state:        dedicated-host-unquotaed' "$work/dedicated-state.plan"

STEWARD_ALLOW_UNQUOTAED_STATE_ON_DEDICATED_HOST=true \
	/bin/bash -p "$installer" "${common_remote[@]}" "${signed_admission[@]}" \
	"${evidence_enrollment[@]}" >"$work/dedicated-state-env.plan"
grep -Fqx '  state:        dedicated-host-unquotaed' "$work/dedicated-state-env.plan"

/bin/bash -p "$installer" "${common_remote[@]}" \
	--steward-credential /trust/generic-supervisor.json \
	>"$work/generic.plan"
grep -Fqx '  enrollment:   generic-supervisor-and-executor' "$work/generic.plan"
grep -Fqx '  admission:    unchanged' "$work/generic.plan"
grep -Fqx '  evidence:     disabled' "$work/generic.plan"
grep -Fqx '  state:        disabled' "$work/generic.plan"

if /bin/bash -p "$installer" "${common_remote[@]}" \
	--steward-credential /trust/generic-supervisor.json \
	--allow-unquotaed-state-on-dedicated-host \
	>"$work/state-without-admission.out" 2>"$work/state-without-admission.err"; then
	echo "bundled-control-node-test: dedicated-host state accepted missing signed admission" >&2
	exit 1
fi
grep -Fqx \
	'install-steward: --allow-unquotaed-state-on-dedicated-host requires signed admission trust inputs' \
	"$work/state-without-admission.err"

if STEWARD_ALLOW_UNQUOTAED_STATE_ON_DEDICATED_HOST=invalid \
	/bin/bash -p "$installer" --non-interactive --dry-run --stage-only \
	--version v0.0.0 --package tar \
	>"$work/invalid-state-env.out" 2>"$work/invalid-state-env.err"; then
	echo "bundled-control-node-test: installer accepted an invalid dedicated-host state environment value" >&2
	exit 1
fi
grep -Fqx \
	'install-steward: STEWARD_ALLOW_UNQUOTAED_STATE_ON_DEDICATED_HOST must be true or false' \
	"$work/invalid-state-env.err"

if /bin/bash -p "$installer" "${common_remote[@]}" "${signed_admission[@]}" \
	>"$work/no-evidence.out" 2>"$work/no-evidence.err"; then
	echo "bundled-control-node-test: bundled control accepted missing evidence enrollment inputs" >&2
	exit 1
fi
grep -Fqx \
	'install-steward: bundled steward-control enrollment requires the Executor evidence config and receipt key pair' \
	"$work/no-evidence.err"

if /bin/bash -p "$installer" "${common_remote[@]}" >"$work/unsigned.out" 2>"$work/unsigned.err"; then
	echo "bundled-control-node-test: bundled control accepted missing signed admission" >&2
	exit 1
fi
grep -Fqx \
	'install-steward: bundled steward-control enrollment requires complete signed-admission inputs' \
	"$work/unsigned.err"

/bin/bash -p "$installer" --non-interactive --dry-run --local-only \
	--version v0.0.0 --package tar >"$work/local.plan"
grep -Fqx '  enrollment:   local-only' "$work/local.plan"
/bin/bash -p "$installer" --non-interactive --dry-run --stage-only \
	--version v0.0.0 --package tar >"$work/staged.plan"
grep -Fqx '  enrollment:   staged-only' "$work/staged.plan"
grep -Fqx '  service start: false' "$work/staged.plan"

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
grep -Fq 'admission_args+=(--allow-unquotaed-state-on-dedicated-host)' "$configurator"
grep -Fq 'configure_args+=(--allow-unquotaed-state-on-dedicated-host)' "$installer"
grep -Fq "printf 'EXECUTOR_STATE_ARG=-allow-unquotaed-state-on-dedicated-host" \
	"$admission_configurator"
grep -Fq "awk '!/^EXECUTOR_STATE_ARG=/" "$admission_configurator"

echo "bundled-control-node-test: bundled control enrollment checks passed"
