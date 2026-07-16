#!/usr/bin/env bash
# Exercise relay binding and removal/drain behavior with a deterministic fake Docker.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
as_root=()
relay_test=true
relay_test_root=
node_lock_test_created=false
legacy_lock_test_created=false
uninstall_test_release=
uninstall_test_parent_created=false
if [[ ${EUID} -ne 0 ]]; then
	if ! sudo -n true 2>/dev/null; then
		if [[ ${STEWARD_REQUIRE_ROOT_SMOKE:-0} == 1 ]]; then
			echo "node-upgrade-smoke: passwordless root is required for privilege-boundary and relay binding checks" >&2
			exit 1
		fi
		relay_test=false
	else
		as_root=(sudo -n)
	fi
fi
cleanup() {
	if [[ $legacy_lock_test_created == true ]]; then
		"${as_root[@]}" rm -f -- /run/lock/steward-node-activation.lock
	fi
	if [[ $node_lock_test_created == true ]]; then
		"${as_root[@]}" rm -rf -- /run/steward-node
	fi
	if [[ -n $uninstall_test_release ]]; then
		"${as_root[@]}" rm -rf -- "$uninstall_test_release"
	fi
	if [[ $uninstall_test_parent_created == true ]]; then
		"${as_root[@]}" rmdir /opt/steward/releases /opt/steward 2>/dev/null || true
	fi
	if [[ -n $relay_test_root ]]; then
		if (( ${#as_root[@]} > 0 )); then "${as_root[@]}" rm -rf -- "$relay_test_root"; else rm -rf -- "$relay_test_root"; fi
	fi
	if (( ${#as_root[@]} > 0 )); then "${as_root[@]}" rm -rf -- "$work"; else rm -rf -- "$work"; fi
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$work/bin" "$work/releases/v0.0.0-test" "$work/etc"

exercise_connector_keygen_boundary() {
	local target_user target_group target_uid helper
	if [[ ${EUID} -eq 0 ]]; then
		target_user=nobody
	else
		target_user=$(id -un)
	fi
	target_group=$(id -gn "$target_user")
	target_uid=$(id -u "$target_user")
	if (( target_uid == 0 )); then
		echo "node-upgrade-smoke: connector key generation test identity is root" >&2
		return 1
	fi

	mkdir -p "$work/key-release"
	cat >"$work/key-release/stewardctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
	keygen)
		shift
		private= public=
		while (( $# > 0 )); do
			case "$1" in
				-private-out) private=${2:-}; shift 2 ;;
				-public-out) public=${2:-}; shift 2 ;;
				*) exit 2 ;;
			esac
		done
		uid=$(id -u)
		if (( uid == 0 )); then
			echo "fake stewardctl: keygen executed as root" >&2
			exit 90
		fi
		[[ -n $private && -n $public ]]
		printf 'private:%s\n' "$uid" >"$private"
		printf 'public:%s\n' "$uid" >"$public"
		chmod 0600 "$private"
		chmod 0644 "$public"
		;;
	key)
		[[ ${2:-} == match ]] || exit 2
		shift 2
		private= public=
		while (( $# > 0 )); do
			case "$1" in
				-private-key) private=${2:-}; shift 2 ;;
				-public-key) public=${2:-}; shift 2 ;;
				*) exit 2 ;;
			esac
		done
		[[ -n $private && -n $public ]]
		private_uid=$(sed -n 's/^private://p' "$private")
		public_uid=$(sed -n 's/^public://p' "$public")
		[[ -n $private_uid && $private_uid == "$public_uid" && $(id -u) == "$private_uid" ]]
		;;
	*) exit 2 ;;
esac
EOF
	chmod 0755 "$work/key-release/stewardctl"

	helper="$work/exercise-connector-keygen.sh"
	{
		printf '#!/usr/bin/env bash\nset -euo pipefail\n'
		awk '
			/^generate_connector_receipt_keypair\(\) \($/ { copying=1 }
			copying { print }
			copying && /^\)$/ { exit }
		' "$root/scripts/install-node.sh"
		for function_name in getent_one validate_install_marker create_install_marker \
			remove_pending_regular_file validate_connector_receipt_keypair \
			remove_connector_pending_state ensure_connector_receipt_keypair; do
			sed -n "/^${function_name}() {$/,/^}$/p" "$root/scripts/install-node.sh"
		done
		cat <<'EOF'
node_lock_directory=$SMOKE_NODE_LOCK_ROOT
if [[ ${SMOKE_MODE:-generate} == ensure ]]; then
	ensure_connector_receipt_keypair "$SMOKE_RELEASE_DIR" "$SMOKE_CONFIG_ROOT" \
		"$SMOKE_STATE_ROOT" "$SMOKE_GATEWAY_USER" "$SMOKE_GATEWAY_GROUP"
else
	generate_connector_receipt_keypair "$SMOKE_RELEASE_DIR" "$SMOKE_GATEWAY_USER" \
		"$SMOKE_GATEWAY_GROUP" "$SMOKE_CONFIG_ROOT"
fi
EOF
	} >"$helper"
	chmod 0755 "$helper"
	if ! grep -q '^generate_connector_receipt_keypair() ($' "$helper"; then
		echo "node-upgrade-smoke: could not extract connector key generation boundary" >&2
		return 1
	fi

	"${as_root[@]}" chmod 0755 "$work"
	"${as_root[@]}" chown -R root:root "$work/key-release" "$helper"
	"${as_root[@]}" install -d -o root -g root -m 0755 "$work/key-config"
	"${as_root[@]}" install -d -o root -g root -m 0700 "$work/key-state" "$work/key-nss"
	"${as_root[@]}" env \
		"SMOKE_RELEASE_DIR=$work/key-release" \
		"SMOKE_GATEWAY_USER=$target_user" \
		"SMOKE_GATEWAY_GROUP=$target_group" \
		"SMOKE_CONFIG_ROOT=$work/key-config" \
		"SMOKE_STATE_ROOT=$work/key-state" \
		"SMOKE_NODE_LOCK_ROOT=$work/key-nss" \
		bash "$helper"

	[[ $(cat "$work/key-config/connector-receipts.public") == "public:$target_uid" ]]
	[[ $("${as_root[@]}" stat -c '%u:%g:%a' "$work/key-config/connector-receipts.private.pem") == "$target_uid:$(id -g "$target_user"):600" ]]
	[[ $("${as_root[@]}" stat -c '%u:%g:%a' "$work/key-config/connector-receipts.public") == "0:0:644" ]]
	if (( $("${as_root[@]}" find "$work/key-config" -maxdepth 1 -name '.connector-keygen.*' -print -quit | wc -l) != 0 )); then
		echo "node-upgrade-smoke: connector key generation left its work directory behind" >&2
		return 1
	fi

	# Model SIGKILL between the two final renames. The root-only journal makes
	# the partial pair recoverable; the same partial state without the journal
	# must remain ambiguous and be rejected.
	"${as_root[@]}" install -o root -g root -m 0600 /dev/null \
		"$work/key-state/install.connector-receipts.pending"
	"${as_root[@]}" rm -f "$work/key-config/connector-receipts.public"
	"${as_root[@]}" env SMOKE_MODE=ensure \
		"SMOKE_RELEASE_DIR=$work/key-release" \
		"SMOKE_GATEWAY_USER=$target_user" \
		"SMOKE_GATEWAY_GROUP=$target_group" \
		"SMOKE_CONFIG_ROOT=$work/key-config" \
		"SMOKE_STATE_ROOT=$work/key-state" \
		"SMOKE_NODE_LOCK_ROOT=$work/key-nss" \
		bash "$helper"
	[[ ! -e $work/key-state/install.connector-receipts.pending ]]
	[[ $(cat "$work/key-config/connector-receipts.public") == "public:$target_uid" ]]
	"${as_root[@]}" rm -f "$work/key-config/connector-receipts.public"
	if "${as_root[@]}" env SMOKE_MODE=ensure \
		"SMOKE_RELEASE_DIR=$work/key-release" \
		"SMOKE_GATEWAY_USER=$target_user" \
		"SMOKE_GATEWAY_GROUP=$target_group" \
		"SMOKE_CONFIG_ROOT=$work/key-config" \
		"SMOKE_STATE_ROOT=$work/key-state" \
		"SMOKE_NODE_LOCK_ROOT=$work/key-nss" \
		bash "$helper" >"$work/key-ambiguous.out" 2>"$work/key-ambiguous.err"; then
		echo "node-upgrade-smoke: unjournaled partial connector pair was accepted" >&2
		return 1
	fi
	grep -Fq 'must exist together' "$work/key-ambiguous.err"
}

exercise_configuration_lock() {
	local helper admission_helper admission_marker ready release error_file sentinel unsafe_error
	if ! command -v flock >/dev/null 2>&1; then
		echo "node-upgrade-smoke: configuration lock check skipped (flock unavailable)"
		return 0
	fi
	if [[ -e /run/steward-node || -L /run/steward-node ]]; then
		echo "node-upgrade-smoke: cannot safely exercise node lock over an existing /run/steward-node" >&2
		return 1
	fi
	if [[ -e /run/lock/steward-node-activation.lock || -L /run/lock/steward-node-activation.lock ]]; then
		echo "node-upgrade-smoke: cannot safely exercise legacy lock isolation over an existing legacy lock" >&2
		return 1
	fi
	node_lock_test_created=true
	legacy_lock_test_created=true
	helper="$work/exercise-configuration-lock.sh"
	{
		printf '#!/bin/bash -p\nset -Eeuo pipefail\n'
		sed -n '/^# BEGIN NODE_LOCK_BOUNDARY$/,/^# END NODE_LOCK_BOUNDARY$/p' \
			"$root/scripts/configure-node.sh"
		cat <<'EOF'
ready=$SMOKE_READY
release=$SMOKE_RELEASE
error_file=$SMOKE_ERROR
if [[ ${SMOKE_MODE:-} == unsafe ]]; then
	if acquire_node_lock 0 2>"$error_file"; then
		echo 'node-upgrade-smoke: symlinked node lock was accepted' >&2
		exit 1
	fi
	grep -Fxq 'configure-node: refusing an unsafe node activation lock' "$error_file"
	exit 0
fi
(
	acquire_node_lock 1
	: >"$ready"
	while [[ ! -e $release ]]; do sleep 0.01; done
) &
holder=$!
for ((index = 0; index < 1000; index++)); do
	[[ ! -e $ready ]] || break
	sleep 0.01
done
[[ -e $ready ]]
if acquire_node_lock 0 2>"$error_file"; then
	echo "node-upgrade-smoke: configure-node acquired a held activation lock" >&2
	exit 1
fi
grep -Fxq 'configure-node: another node configuration or activation did not finish within 0 seconds' "$error_file"
: >"$release"
wait "$holder"
acquire_node_lock 1
SMOKE_ADMISSION_MARKER="$SMOKE_ADMISSION_MARKER" /bin/bash -p "$SMOKE_ADMISSION_HELPER"
exec 9>&-
EOF
	} >"$helper"
	chmod 0755 "$helper"
	grep -Fq '# BEGIN NODE_LOCK_BOUNDARY' "$helper" || {
		echo "node-upgrade-smoke: could not extract configure-node lock acquisition" >&2
		return 1
	}
	admission_helper="$work/exercise-inherited-admission-lock.sh"
	{
		printf '#!/bin/bash -p\nset -Eeuo pipefail\n'
		sed -n '/^# BEGIN NODE_LOCK_BOUNDARY$/,/^# END NODE_LOCK_BOUNDARY$/p' \
			"$root/scripts/configure-admission.sh"
		cat <<'EOF'
use_inherited_node_lock 9
: >"$SMOKE_ADMISSION_MARKER"
EOF
	} >"$admission_helper"
	chmod 0755 "$admission_helper"
	grep -Fq 'use_inherited_node_lock() {' "$admission_helper" || {
		echo "node-upgrade-smoke: could not extract configure-admission inherited lock validation" >&2
		return 1
	}
	admission_marker="$work/admission-inherited-lock.ok"
	ready="$work/configure.lock.ready"
	release="$work/configure.lock.release"
	error_file="$work/configure.lock.error"
	sentinel="$work/node-lock-clobber-target"
	unsafe_error="$work/configure.lock.unsafe.error"
	printf '%s\n' do-not-clobber >"$sentinel"
	"${as_root[@]}" install -d -o root -g root -m 0700 /run/steward-node
	"${as_root[@]}" ln -s "$sentinel" /run/steward-node/activation.lock
	"${as_root[@]}" env SMOKE_MODE=unsafe SMOKE_READY="$ready" SMOKE_RELEASE="$release" \
		SMOKE_ERROR="$unsafe_error" /bin/bash -p "$helper"
	[[ $(cat "$sentinel") == do-not-clobber ]]
	"${as_root[@]}" rm -f /run/steward-node/activation.lock
	"${as_root[@]}" install -d -o root -g root -m 0755 /run/lock
	"${as_root[@]}" ln -s "$sentinel" /run/lock/steward-node-activation.lock
	"${as_root[@]}" env SMOKE_READY="$ready" SMOKE_RELEASE="$release" \
		SMOKE_ERROR="$error_file" SMOKE_ADMISSION_HELPER="$admission_helper" \
		SMOKE_ADMISSION_MARKER="$admission_marker" /bin/bash -p "$helper"
	[[ $(cat "$sentinel") == do-not-clobber ]]
	[[ -f $admission_marker ]]
	[[ $("${as_root[@]}" stat -c '%u:%g:%a:%h' /run/steward-node/activation.lock) == 0:0:600:1 ]]
}

exercise_uninstall_symlink_boundary() {
	local version="v0.0.0-uninstall-boundary.${BASHPID:-$$}" trusted_resolver trusted_guard attacker_guard link status
	uninstall_test_release="/opt/steward/releases/$version"
	if [[ -e $uninstall_test_release || -L $uninstall_test_release ]]; then
		echo "node-upgrade-smoke: uninstall boundary fixture release already exists" >&2
		return 1
	fi
	[[ -e /opt/steward || -L /opt/steward ]] || uninstall_test_parent_created=true
	"${as_root[@]}" install -d -o root -g root -m 0755 \
		"$uninstall_test_release/integration/scripts"
	trusted_resolver="$work/trusted-uninstall-resolver.sh"
	{
		printf '%s\n' '#!/bin/bash -p' 'set -euo pipefail' \
			'PATH=/usr/sbin:/usr/bin:/sbin:/bin' 'export PATH' "IFS=\$' \\t\\n'" 'umask 077'
		sed -n '/^# BEGIN UNINSTALL_TRUST_BOUNDARY$/,/^# END UNINSTALL_TRUST_BOUNDARY$/p' \
			"$root/scripts/uninstall-node.sh"
		cat <<'EOF'
"$guard_bin"
EOF
	} >"$trusted_resolver"
	grep -Fq 'trusted_root_executable() {' "$trusted_resolver" || {
		echo "node-upgrade-smoke: could not extract the uninstaller trust boundary" >&2
		return 1
	}
	"${as_root[@]}" install -o root -g root -m 0755 "$trusted_resolver" \
		"$uninstall_test_release/integration/scripts/uninstall-node.sh"
	trusted_guard="$work/trusted-node-removal-guard.sh"
	cat >"$trusted_guard" <<'EOF'
#!/bin/bash -p
: >"${SMOKE_TRUSTED_GUARD_MARKER:?}"
exit 73
EOF
	"${as_root[@]}" install -o root -g root -m 0755 "$trusted_guard" \
		"$uninstall_test_release/integration/scripts/node-removal-guard.sh"
	attacker_guard="$work/node-removal-guard.sh"
	cat >"$attacker_guard" <<'EOF'
#!/bin/bash -p
: >"${SMOKE_ATTACKER_GUARD_MARKER:?}"
exit 74
EOF
	chmod 0755 "$attacker_guard"
	link="$work/uninstall-node.sh"
	ln -s "$uninstall_test_release/integration/scripts/uninstall-node.sh" "$link"
	set +e
	"${as_root[@]}" env \
		"SMOKE_TRUSTED_GUARD_MARKER=$work/trusted-guard-ran" \
		"SMOKE_ATTACKER_GUARD_MARKER=$work/attacker-guard-ran" \
		"$link" >"$work/uninstall-symlink.out" 2>"$work/uninstall-symlink.err"
	status=$?
	set -e
	if [[ -e $work/attacker-guard-ran ]]; then
		echo "node-upgrade-smoke: uninstaller followed an untrusted invocation sibling" >&2
		sed 's/^/  stdout: /' "$work/uninstall-symlink.out" >&2
		sed 's/^/  stderr: /' "$work/uninstall-symlink.err" >&2
		return 1
	fi
	if (( status != 73 )) || [[ ! -f $work/trusted-guard-ran ]]; then
		echo "node-upgrade-smoke: trusted uninstaller sibling resolution did not complete (status=$status, trusted_marker=$([[ -f $work/trusted-guard-ran ]] && echo present || echo missing))" >&2
		sed 's/^/  stdout: /' "$work/uninstall-symlink.out" >&2
		sed 's/^/  stderr: /' "$work/uninstall-symlink.err" >&2
		return 1
	fi
}

exercise_activation_service_boundaries() {
	local helper function_name
	helper="$work/exercise-activation-service-boundaries.sh"
	{
		printf '%s\n' '#!/usr/bin/env bash' 'set -Eeuo pipefail'
		for function_name in read_service_activity stop_active_services replace_selector; do
			sed -n "/^${function_name}() {$/,/^}$/p" "$root/scripts/activate-node-release.sh"
		done
		cat <<'EOF'
SMOKE_GATEWAY_ACTIVITY=inactive
SMOKE_STEWARD_ACTIVITY=inactive
SMOKE_EXECUTOR_ACTIVITY=inactive
SMOKE_STOP_FAILURE=
SMOKE_STICKY_STOP=
systemctl() {
	local operation=${1:-} unit=${2:-} state
	case "$operation" in
		is-active)
			case "$unit" in
				steward-gateway.service) state=$SMOKE_GATEWAY_ACTIVITY ;;
				steward.service) state=$SMOKE_STEWARD_ACTIVITY ;;
				steward-executor.service) state=$SMOKE_EXECUTOR_ACTIVITY ;;
				*) state=query-error ;;
			esac
			case "$state" in
				active) echo active; return 0 ;;
				inactive) echo inactive; return 3 ;;
				query-error) return 2 ;;
				*) echo "$state"; return 3 ;;
			esac
			;;
		stop)
			[[ $unit != "$SMOKE_STOP_FAILURE" ]] || return 71
			if [[ $unit != "$SMOKE_STICKY_STOP" ]]; then
				case "$unit" in
					steward-gateway.service) SMOKE_GATEWAY_ACTIVITY=inactive ;;
					steward.service) SMOKE_STEWARD_ACTIVITY=inactive ;;
					steward-executor.service) SMOKE_EXECUTOR_ACTIVITY=inactive ;;
					*) return 2 ;;
				esac
			fi
			;;
		*) return 2 ;;
	esac
}

SMOKE_STEWARD_ACTIVITY=activating
if read_service_activity steward.service >/dev/null 2>&1; then
	echo 'node-upgrade-smoke: activation accepted a transitional systemd state' >&2
	exit 1
fi
SMOKE_STEWARD_ACTIVITY=query-error
if read_service_activity steward.service >/dev/null 2>&1; then
	echo 'node-upgrade-smoke: activation treated a failed systemd query as inactive' >&2
	exit 1
fi

SMOKE_GATEWAY_ACTIVITY=active
SMOKE_STEWARD_ACTIVITY=active
SMOKE_EXECUTOR_ACTIVITY=active
SMOKE_STOP_FAILURE=steward.service
if stop_active_services >/dev/null 2>&1; then
	echo 'node-upgrade-smoke: rollback ignored a failed service stop' >&2
	exit 1
fi
[[ $SMOKE_STEWARD_ACTIVITY == active ]]

SMOKE_STOP_FAILURE=
SMOKE_GATEWAY_ACTIVITY=active
SMOKE_STEWARD_ACTIVITY=active
SMOKE_EXECUTOR_ACTIVITY=active
SMOKE_STICKY_STOP=steward-executor.service
if stop_active_services >/dev/null 2>&1; then
	echo 'node-upgrade-smoke: rollback did not verify service inactivity after stop' >&2
	exit 1
fi
[[ $SMOKE_EXECUTOR_ACTIVITY == active ]]

SMOKE_STICKY_STOP=
stop_active_services
[[ $SMOKE_GATEWAY_ACTIVITY == inactive ]]
[[ $SMOKE_STEWARD_ACTIVITY == inactive ]]
[[ $SMOKE_EXECUTOR_ACTIVITY == inactive ]]

selectors_switched=false
mv() { return 72; }
if replace_selector /tmp/source /tmp/destination; then
	echo 'node-upgrade-smoke: selector replacement failure unexpectedly succeeded' >&2
	exit 1
fi
[[ $selectors_switched == true ]]
EOF
	} >"$helper"
	chmod 0755 "$helper"
	for function_name in read_service_activity stop_active_services replace_selector; do
		grep -Fq "$function_name() {" "$helper" || {
			echo "node-upgrade-smoke: could not extract activation helper $function_name" >&2
			return 1
		}
	done
	bash "$helper"
}

exercise_uninstall_quiesce_boundary() {
	local helper guard log status stop_executor_line guard_line start_executor_line start_steward_line start_gateway_line
	helper="$work/exercise-uninstall-quiesce.sh"
	guard="$work/fake-removal-guard.sh"
	cat >"$guard" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' guard >>"$SMOKE_LIFECYCLE_LOG"
exit "${SMOKE_GUARD_STATUS:-0}"
EOF
	chmod 0755 "$guard"
	{
		printf '#!/usr/bin/env bash\nset -Eeuo pipefail\n'
		cat <<'EOF'
purge_data=false
guard_bin=$SMOKE_GUARD
systemctl() {
	printf 'systemctl %s\n' "$*" >>"$SMOKE_LIFECYCLE_LOG"
	case "${1:-}" in
		is-active | stop | start) return 0 ;;
		*) return 2 ;;
	esac
}
EOF
		sed -n '/^# BEGIN QUIESCED_REMOVAL$/,/^# END QUIESCED_REMOVAL$/p' \
			"$root/scripts/uninstall-node.sh"
	} >"$helper"
	chmod 0755 "$helper"
	grep -Fq '# BEGIN QUIESCED_REMOVAL' "$helper"

	log="$work/uninstall-quiesce-success.log"
	SMOKE_GUARD="$guard" SMOKE_GUARD_STATUS=0 SMOKE_LIFECYCLE_LOG="$log" bash "$helper"
	stop_executor_line=$(grep -n '^systemctl stop steward-executor.service$' "$log" | cut -d: -f1)
	guard_line=$(grep -n '^guard$' "$log" | cut -d: -f1)
	[[ -n $stop_executor_line && -n $guard_line && $stop_executor_line -lt $guard_line ]]

	log="$work/uninstall-quiesce-failure.log"
	set +e
	SMOKE_GUARD="$guard" SMOKE_GUARD_STATUS=7 SMOKE_LIFECYCLE_LOG="$log" bash "$helper" \
		>"$work/uninstall-quiesce-failure.out" 2>"$work/uninstall-quiesce-failure.err"
	status=$?
	set -e
	[[ $status -eq 7 ]]
	grep -Fq 'restoring their previous active state' "$work/uninstall-quiesce-failure.err"
	guard_line=$(grep -n '^guard$' "$log" | cut -d: -f1)
	start_gateway_line=$(grep -n '^systemctl start steward-gateway.service$' "$log" | cut -d: -f1)
	start_steward_line=$(grep -n '^systemctl start steward.service$' "$log" | cut -d: -f1)
	start_executor_line=$(grep -n '^systemctl start steward-executor.service$' "$log" | cut -d: -f1)
	[[ $guard_line -lt $start_gateway_line && $start_gateway_line -lt $start_steward_line &&
		$start_steward_line -lt $start_executor_line ]]

	for hook in "$root/packaging/debian/prerm" "$root/packaging/rpm/steward-node.spec.in"; do
		grep -Fq '/usr/lib/steward-node/release/scripts/uninstall-node.sh' "$hook"
		# shellcheck disable=SC2016 # Match the literal package-hook variable reference.
		if grep -Fq '"$guard"' "$hook"; then
			echo "node-upgrade-smoke: package removal bypasses the serialized lifecycle uninstaller" >&2
			return 1
		fi
	done
}

exercise_delivery_activation() {
	local helper function_name
	mkdir -p "$work/delivery/bin" "$work/delivery/release" "$work/delivery/etc" \
		"$work/delivery/backup" "$work/delivery/state"
	cat >"$work/delivery/bin/runuser" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == -u && -n ${2:-} && ${3:-} == -- ]] || exit 2
shift 3
exec "$@"
EOF
	cat >"$work/delivery/bin/chown" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 2 && $1 == root:root && -f $2 ]]
EOF
	cat >"$work/delivery/release/steward-executor" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
	-inspect-uplink-credential)
		printf '%s\n%s\n' "${FAKE_SCOPE:?}" "${FAKE_NODE_ID:?}"
		;;
	-initialize-uplink-delivery-state)
		state= node=
		while (( $# > 0 )); do
			case "$1" in
				-initialize-uplink-delivery-state) shift ;;
				-uplink-delivery-state-file) state=${2:-}; shift 2 ;;
				-admission-node-id) node=${2:-}; shift 2 ;;
				*) exit 2 ;;
			esac
		done
		[[ -n $state && $node == node-a ]]
		( set -o noclobber; : >"$state" ) 2>/dev/null || exit 2
		chmod 0600 "$state"
		;;
	*) exit 2 ;;
esac
EOF
	chmod 0755 "$work/delivery/bin/runuser" "$work/delivery/bin/chown" \
		"$work/delivery/release/steward-executor"

	helper="$work/delivery/exercise.sh"
	{
		printf '#!/usr/bin/env bash\nset -Eeuo pipefail\n'
		for function_name in restore_executor_setup activation_error read_executor_setting prepare_uplink_delivery_state; do
			awk -v signature="$function_name() {" '
				$0 == signature { copying=1 }
				copying { print }
				copying && $0 == "}" { exit }
			' "$root/scripts/activate-node-release.sh"
		done
		cat <<'EOF'
executor_env=$SMOKE_EXECUTOR_ENV
gateway_env_backup=$SMOKE_BACKUP
executor_env_present=true
release_dir=$SMOKE_RELEASE
uplink_delivery_state=$SMOKE_DELIVERY_STATE
admission_mode=configured
executor_env_tmp=

write_env() {
	printf '%s\n' \
		'EXECUTOR_UPLINK_CREDENTIAL_FILE=/credential.json' \
		'EXECUTOR_ADMISSION_NODE_ID=node-a' \
		'EXECUTOR_UPLINK_DELIVERY_STATE_FILE=' >"$executor_env"
	cp -a -- "$executor_env" "$gateway_env_backup/executor.env"
	executor_setup_changed=false
	uplink_delivery_state_created=false
}

write_env
export FAKE_SCOPE=node FAKE_NODE_ID=node-a
prepare_uplink_delivery_state
grep -Fxq "EXECUTOR_UPLINK_DELIVERY_STATE_FILE=$uplink_delivery_state" "$executor_env"
[[ -f $uplink_delivery_state && $executor_setup_changed == true && $uplink_delivery_state_created == true ]]
restore_executor_setup
cmp "$executor_env" "$gateway_env_backup/executor.env"
[[ ! -e $uplink_delivery_state ]]

write_env
export FAKE_SCOPE=tenant FAKE_NODE_ID=node-a
prepare_uplink_delivery_state
cmp "$executor_env" "$gateway_env_backup/executor.env"
[[ ! -e $uplink_delivery_state && $executor_setup_changed == false ]]

write_env
: >"$uplink_delivery_state"
chmod 0600 "$uplink_delivery_state"
export FAKE_SCOPE=node FAKE_NODE_ID=node-a
prepare_uplink_delivery_state
[[ $executor_setup_changed == true && $uplink_delivery_state_created == false ]]
restore_executor_setup
[[ -f $uplink_delivery_state ]]
rm -f "$uplink_delivery_state"

write_env
export FAKE_SCOPE=node FAKE_NODE_ID=node-other
set +e
( set -e; prepare_uplink_delivery_state ) >/dev/null 2>&1
status=$?
set -e
[[ $status -ne 0 ]]
cmp "$executor_env" "$gateway_env_backup/executor.env"
[[ ! -e $uplink_delivery_state ]]
EOF
	} >"$helper"
	chmod 0755 "$helper"
	for function_name in restore_executor_setup activation_error read_executor_setting prepare_uplink_delivery_state; do
		grep -Fq "$function_name() {" "$helper" || {
			echo "node-upgrade-smoke: could not extract $function_name" >&2
			return 1
		}
	done

	delivery_env=(
		"PATH=$work/delivery/bin:$PATH"
		"SMOKE_EXECUTOR_ENV=$work/delivery/etc/executor.env"
		"SMOKE_BACKUP=$work/delivery/backup"
		"SMOKE_RELEASE=$work/delivery/release"
		"SMOKE_DELIVERY_STATE=$work/delivery/state/uplink-delivery-state.json"
	)
	if (( ${#as_root[@]} > 0 )); then
		"${as_root[@]}" env "${delivery_env[@]}" bash "$helper"
	else
		env "${delivery_env[@]}" bash "$helper"
	fi
}

if [[ $relay_test == true ]]; then
	exercise_configuration_lock
	exercise_uninstall_symlink_boundary
else
	echo "node-upgrade-smoke: configuration lock boundary check skipped (passwordless root unavailable)"
	echo "node-upgrade-smoke: uninstall sibling boundary check skipped (passwordless root unavailable)"
fi
exercise_activation_service_boundaries
exercise_uninstall_quiesce_boundary
exercise_delivery_activation
if [[ $relay_test == true ]]; then
	exercise_connector_keygen_boundary
else
	echo "node-upgrade-smoke: connector key generation boundary check skipped (passwordless root unavailable)"
fi

cat >"$work/releases/v0.0.0-test/steward-relay" <<'EOF'
#!/usr/bin/env bash
if [[ ${1:-} == -version ]]; then
	echo 'steward-relay v0.0.0-test'
	exit 0
fi
exit 2
EOF
chmod 0755 "$work/releases/v0.0.0-test/steward-relay"
binary_sha=$(sha256sum "$work/releases/v0.0.0-test/steward-relay" | awk '{print $1}')
image_id="sha256:$(printf 'a%.0s' {1..64})"

cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n ${DOCKER_HOST:-} || -n ${DOCKER_CONTEXT:-} || -n ${DOCKER_CONFIG:-} ]]; then
	echo 'fake docker: caller Docker routing environment was not scrubbed' >&2
	exit 88
fi
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
if [[ ${FAKE_DOCKER_MODE:-} == hang ]]; then
	exec sleep 60
fi
if [[ ${FAKE_DOCKER_MODE:-} == flood ]]; then
	exec dd if=/dev/zero bs=1048576 count=4 status=none
fi
case "${1:-}" in
	info) exit 0 ;;
	version) echo '29.0.0' ;;
	build) [[ -z ${FAKE_BUILD_MARKER:-} ]] || : >"$FAKE_BUILD_MARKER"; exit 0 ;;
	image)
		[[ ${2:-} == inspect && ${3:-} == --format ]] || exit 2
		if [[ ${FAKE_MISSING_UNTIL_BUILD:-0} == 1 && ! -e ${FAKE_BUILD_MARKER:-/nonexistent} ]]; then exit 1; fi
		case "${4:-}" in
			'{{.Id}}') echo "$FAKE_IMAGE_ID" ;;
			'{{index .Config.Labels "io.hardrails.steward.release.version"}}') echo 'v0.0.0-test' ;;
			'{{index .Config.Labels "io.hardrails.steward.relay.binary.sha256"}}') echo "$FAKE_BINARY_SHA" ;;
			*) exit 2 ;;
		esac
		;;
	ps)
		case "$*" in
			*io.hardrails.executor.managed=true*) [[ -z ${FAKE_AGENT_IDS:-} ]] || echo "$FAKE_AGENT_IDS" ;;
			*io.hardrails.relay.managed=true*) [[ -z ${FAKE_RELAY_IDS:-} ]] || echo "$FAKE_RELAY_IDS" ;;
		esac
		;;
	network) [[ -z ${FAKE_NETWORK_IDS:-} ]] || echo "$FAKE_NETWORK_IDS" ;;
	volume) [[ -z ${FAKE_VOLUME_IDS:-} ]] || echo "$FAKE_VOLUME_IDS" ;;
	*) exit 2 ;;
esac
EOF
chmod 0755 "$work/bin/docker"
if [[ $relay_test == true ]]; then
	relay_test_root=$("${as_root[@]}" mktemp -d /run/steward-relay-test.XXXXXX)
	"${as_root[@]}" install -d -o root -g root -m 0755 \
		"$relay_test_root/bin" \
		"$relay_test_root/etc" \
		"$relay_test_root/releases" \
		"$relay_test_root/releases/v0.0.0-test" \
		"$relay_test_root/releases/v0.0.0-test/integration" \
		"$relay_test_root/releases/v0.0.0-test/integration/scripts"
	"${as_root[@]}" install -o root -g root -m 0755 \
		"$work/bin/docker" "$relay_test_root/bin/docker"
	"${as_root[@]}" install -o root -g root -m 0755 \
		"$work/releases/v0.0.0-test/steward-relay" \
		"$relay_test_root/releases/v0.0.0-test/steward-relay"
	"${as_root[@]}" install -o root -g root -m 0755 \
		"$root/scripts/build-relay-image.sh" \
		"$relay_test_root/releases/v0.0.0-test/integration/scripts/build-relay-image.sh"
	"${as_root[@]}" install -o root -g root -m 0755 \
		"$root/scripts/node-removal-guard.sh" \
		"$relay_test_root/releases/v0.0.0-test/integration/scripts/node-removal-guard.sh"
	relay_build_script="$relay_test_root/releases/v0.0.0-test/integration/scripts/build-relay-image.sh"
	relay_guard_script="$relay_test_root/releases/v0.0.0-test/integration/scripts/node-removal-guard.sh"
	docker_log="$relay_test_root/docker.log"
	mkdir -p "$work/hostile-relay-path"
	cat >"$work/hostile-relay-path/readlink" <<EOF
#!/bin/sh
/usr/bin/touch '$work/hostile-relay-path-ran'
exit 97
EOF
	chmod 0755 "$work/hostile-relay-path/readlink"
	common_env=(
		"STEWARD_RELAY_TEST_ROOT=$relay_test_root"
		"FAKE_DOCKER_LOG=$docker_log"
		"FAKE_IMAGE_ID=$image_id"
		"FAKE_BINARY_SHA=$binary_sha"
		"PATH=$work/hostile-relay-path"
		"DOCKER_HOST=tcp://attacker.invalid:2375"
		"DOCKER_CONTEXT=attacker"
		"DOCKER_CONFIG=$work/attacker-docker-config"
		"STEWARD_RELAY_BIN=$work/untrusted-relay"
		"STEWARD_RELAY_GID=999"
		"STEWARD_RELAY_BINDING_ROOT=$work/redirected-bindings"
		"STEWARD_RELAY_CURRENT_ENV=$work/redirected-selector"
	)
	"${as_root[@]}" env "${common_env[@]}" "$relay_build_script" \
		--release-dir "$relay_test_root/releases/v0.0.0-test" >/dev/null
	binding="$relay_test_root/relay-images/v0.0.0-test.env"
	# The production binding directory is root-only and the binding itself is
	# mode 0600. Inspect it through the same privilege boundary used to create it
	# so this smoke also works for passwordless-sudo CI runners.
	"${as_root[@]}" test -f "$binding"
	"${as_root[@]}" test ! -L "$binding"
	[[ $("${as_root[@]}" stat -c '%u:%g:%a' "$binding") == 0:0:600 ]]
	"${as_root[@]}" grep -Fxq '# steward.relay-binding.v1' "$binding"
	"${as_root[@]}" grep -Fxq '# release_version=v0.0.0-test' "$binding"
	"${as_root[@]}" grep -Fxq "# relay_binary_sha256=$binary_sha" "$binding"
	"${as_root[@]}" grep -Fxq "# relay_image_id=$image_id" "$binding"
	"${as_root[@]}" grep -Fq -- "-relay-image=$image_id" "$binding"
	"${as_root[@]}" grep -Fq -- '-relay-gid=4242' "$binding"
	[[ ! -e $work/hostile-relay-path-ran && ! -e $work/redirected-bindings && ! -e $work/redirected-selector ]]
	"${as_root[@]}" test ! -e "$relay_test_root/etc/executor-gateway.env"
	"${as_root[@]}" test ! -L "$relay_test_root/etc/executor-gateway.env"
	"${as_root[@]}" grep -Fq 'build --network=none --pull=false --provenance=false' "$docker_log"

	"${as_root[@]}" env "${common_env[@]}" "$relay_build_script" \
		--release-dir "$relay_test_root/releases/v0.0.0-test" --configure >/dev/null
	"${as_root[@]}" test -L "$relay_test_root/etc/executor-gateway.env"
	[[ $("${as_root[@]}" readlink "$relay_test_root/etc/executor-gateway.env") == "$binding" ]]
	[[ $("${as_root[@]}" grep -c '^build ' "$docker_log") -eq 1 ]]

	# Model an operator-deleted image. A deterministic rebuild that returns the
	# retained image ID restores availability without replacing the binding.
	"${as_root[@]}" rm -f "$relay_test_root/build.marker"
	"${as_root[@]}" env "${common_env[@]}" FAKE_MISSING_UNTIL_BUILD=1 \
		"FAKE_BUILD_MARKER=$relay_test_root/build.marker" "$relay_build_script" \
		--release-dir "$relay_test_root/releases/v0.0.0-test" --replace-missing >/dev/null
	[[ $("${as_root[@]}" grep -c '^build ' "$docker_log") -eq 2 ]]
	"${as_root[@]}" grep -Fxq "# relay_image_id=$image_id" "$binding"

	guard_env=("STEWARD_RELAY_TEST_ROOT=$relay_test_root" "FAKE_DOCKER_LOG=$docker_log")
	"${as_root[@]}" env "${guard_env[@]}" "$relay_guard_script"
	if "${as_root[@]}" env "${guard_env[@]}" FAKE_AGENT_IDS=stopped-agent "$relay_guard_script" 2>/dev/null; then
		echo "node-upgrade-smoke: stopped managed agent did not block removal" >&2
		exit 1
	fi
	if "${as_root[@]}" env "${guard_env[@]}" FAKE_NETWORK_IDS=capability-network "$relay_guard_script" 2>/dev/null; then
		echo "node-upgrade-smoke: capability network did not block removal" >&2
		exit 1
	fi
	# Retained state is permitted for ordinary removal, but not an explicit purge.
	"${as_root[@]}" env "${guard_env[@]}" FAKE_VOLUME_IDS=retained-state "$relay_guard_script"
	if "${as_root[@]}" env "${guard_env[@]}" FAKE_VOLUME_IDS=retained-state "$relay_guard_script" --purge-data 2>/dev/null; then
		echo "node-upgrade-smoke: retained state volume did not block purge" >&2
		exit 1
	fi
	if "${as_root[@]}" env "${guard_env[@]}" FAKE_DOCKER_MODE=flood "$relay_guard_script" \
		>/dev/null 2>&1; then
		echo "node-upgrade-smoke: unbounded Docker inventory output passed the drain guard" >&2
		exit 1
	fi
	guard_started=$SECONDS
	if "${as_root[@]}" env "${guard_env[@]}" FAKE_DOCKER_MODE=hang "$relay_guard_script" \
		>/dev/null 2>&1; then
		echo "node-upgrade-smoke: stalled Docker daemon passed the drain guard" >&2
		exit 1
	fi
	if (( SECONDS - guard_started > 25 )); then
		echo "node-upgrade-smoke: stalled Docker daemon exceeded the drain-guard deadline" >&2
		exit 1
	fi
else
	echo "node-upgrade-smoke: relay binding and drain-guard checks skipped (passwordless root unavailable)"
fi
if "$root/scripts/uninstall-node.sh" --purge-config 2>/dev/null; then
	echo "node-upgrade-smoke: uninstall accepted a configuration-only identity purge" >&2
	exit 1
fi
if "$root/scripts/uninstall-node.sh" --purge-data 2>/dev/null; then
	echo "node-upgrade-smoke: uninstall accepted a data-only identity purge" >&2
	exit 1
fi

echo "node-upgrade-smoke: configuration lock, delivery activation, key-generation boundary, relay binding, and drain guards passed"
