#!/usr/bin/env bash
# Keep the node and fleet-controller installers from claiming the same stable binary.
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/steward-node-control-conflict.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

node_entrypoints=(
	scripts/install-steward.sh
	scripts/install-node.sh
	scripts/activate-node-release.sh
)

for relative in "${node_entrypoints[@]}"; do
	entrypoint="$root/$relative"
	for marker in \
		/opt/steward-control \
		/etc/steward-control \
		/var/lib/steward-control-installer \
		/etc/systemd/system/steward-control.service \
		/usr/local/libexec/steward-control; do
		grep -Fq "$marker" "$entrypoint"
	done
	grep -Fq 'find_deployed_control_plane_marker' "$entrypoint"
	grep -Fq 'Run Steward Control and Steward nodes on separate management hosts' "$entrypoint"

	helper="$work/${relative##*/}.helper"
	awk '
		/^find_deployed_control_plane_marker\(\) \{$/ { copying=1 }
		copying { print }
		copying && /^}$/ { exit }
	' "$entrypoint" >"$helper"
	cat >>"$helper" <<'EOF'
marker=$1
missing=$2
found=$(find_deployed_control_plane_marker "$missing" "$marker")
[[ $found == "$marker" ]]
rm -f -- "$marker"
if find_deployed_control_plane_marker "$missing" "$marker"; then
	echo 'conflict helper accepted absent markers' >&2
	exit 1
fi
EOF
	marker="$work/${relative##*/}.broken-link"
	missing="$work/${relative##*/}.missing"
	ln -s /definitely/absent "$marker"
	bash "$helper" "$marker" "$missing"
done

for entrypoint in "$root/scripts/install-node.sh" "$root/scripts/install-control.sh" \
	"$root/scripts/uninstall-node.sh"; do
	grep -Fq '/run/steward-host-role' "$entrypoint"
	grep -Fq 'role.lock' "$entrypoint"
	grep -Fq "stat -c '%u:%g:%a:%h'" "$entrypoint"
	grep -Fq '0:0:600:1' "$entrypoint"
	grep -Fq 'flock -w 60' "$entrypoint"
done
grep -Fq '/var/lib/steward-node-installer' "$root/scripts/install-control.sh"

wrapper_role_lock_line=$(grep -n '^acquire_host_role_lock || {$' \
	"$root/scripts/install-steward.sh" | cut -d: -f1)
wrapper_claim_line=$(grep -n '^create_node_role_claim || {$' \
	"$root/scripts/install-steward.sh" | cut -d: -f1)
# shellcheck disable=SC2016 # Match the literal wrapper condition and variable.
wrapper_mutation_line=$(grep -n '^if \[\[ \$stage_only == false \]\] && ! has_runsc; then install_gvisor_runtime; fi$' \
	"$root/scripts/install-steward.sh" | cut -d: -f1)
[[ -n $wrapper_role_lock_line && -n $wrapper_claim_line && -n $wrapper_mutation_line &&
	$wrapper_role_lock_line -lt $wrapper_claim_line && $wrapper_claim_line -lt $wrapper_mutation_line ]]

grep -Fq '/var/lib/steward-node-installer' "$root/packaging/debian/preinst"
grep -Fq '%pre -f %{SOURCE2}' "$root/packaging/rpm/steward-node.spec.in"
grep -Fq 'packaging/debian/preinst' "$root/scripts/build-rpm.sh"

node_role_lock_line=$(grep -n '^acquire_host_role_lock$' "$root/scripts/install-node.sh" | cut -d: -f1)
node_marker_check_line=$(grep -n '^if control_plane_marker=' "$root/scripts/install-node.sh" | cut -d: -f1)
[[ -n $node_role_lock_line && -n $node_marker_check_line && $node_role_lock_line -lt $node_marker_check_line ]]

control_role_lock_line=$(grep -n '^[[:space:]]*acquire_host_role_lock || exit 1$' \
	"$root/scripts/install-control.sh" | cut -d: -f1)
control_marker_check_line=$(grep -n '^[[:space:]]*for node_marker in ' \
	"$root/scripts/install-control.sh" | cut -d: -f1)
[[ -n $control_role_lock_line && -n $control_marker_check_line &&
	$control_role_lock_line -lt $control_marker_check_line ]]

uninstall_role_lock_line=$(grep -n '^acquire_host_role_lock$' "$root/scripts/uninstall-node.sh" | cut -d: -f1)
uninstall_node_lock_line=$(grep -n '^acquire_node_lock 60$' "$root/scripts/uninstall-node.sh" | cut -d: -f1)
[[ -n $uninstall_role_lock_line && -n $uninstall_node_lock_line &&
	$uninstall_role_lock_line -lt $uninstall_node_lock_line ]]

printf '%s\n' 'node-control-plane-conflict-test: node/controller markers and shared host-role lock order passed'
