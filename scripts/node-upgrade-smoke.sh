#!/usr/bin/env bash
# Exercise relay binding and removal/drain behavior with a deterministic fake Docker.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
as_root=()
relay_test=true
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
		cat <<'EOF'
generate_connector_receipt_keypair "$SMOKE_RELEASE_DIR" "$SMOKE_GATEWAY_USER" \
	"$SMOKE_GATEWAY_GROUP" "$SMOKE_CONFIG_ROOT"
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
	"${as_root[@]}" env \
		"SMOKE_RELEASE_DIR=$work/key-release" \
		"SMOKE_GATEWAY_USER=$target_user" \
		"SMOKE_GATEWAY_GROUP=$target_group" \
		"SMOKE_CONFIG_ROOT=$work/key-config" \
		bash "$helper"

	[[ $(cat "$work/key-config/connector-receipts.public") == "public:$target_uid" ]]
	[[ $("${as_root[@]}" stat -c '%u:%g:%a' "$work/key-config/connector-receipts.private.pem") == "$target_uid:$(id -g "$target_user"):600" ]]
	[[ $("${as_root[@]}" stat -c '%u:%g:%a' "$work/key-config/connector-receipts.public") == "0:0:644" ]]
	if (( $("${as_root[@]}" find "$work/key-config" -maxdepth 1 -name '.connector-keygen.*' -print -quit | wc -l) != 0 )); then
		echo "node-upgrade-smoke: connector key generation left its work directory behind" >&2
		return 1
	fi
}

exercise_configuration_lock() {
	local helper lock ready release error_file
	if ! command -v flock >/dev/null 2>&1; then
		echo "node-upgrade-smoke: configuration lock check skipped (flock unavailable)"
		return 0
	fi
	helper="$work/exercise-configuration-lock.sh"
	{
		printf '#!/usr/bin/env bash\nset -Eeuo pipefail\n'
		awk '
			/^acquire_node_lock\(\) \{$/ { copying=1 }
			copying { print }
			copying && /^}$/ { exit }
		' "$root/scripts/configure-node.sh"
		cat <<'EOF'
lock=$SMOKE_LOCK
ready=$SMOKE_READY
release=$SMOKE_RELEASE
error_file=$SMOKE_ERROR
(
	exec 8>"$lock"
	flock 8
	: >"$ready"
	while [[ ! -e $release ]]; do sleep 0.01; done
) &
holder=$!
for ((index = 0; index < 1000; index++)); do
	[[ ! -e $ready ]] || break
	sleep 0.01
done
[[ -e $ready ]]
if acquire_node_lock "$lock" 0 2>"$error_file"; then
	echo "node-upgrade-smoke: configure-node acquired a held activation lock" >&2
	exit 1
fi
grep -Fxq 'configure-node: another node configuration or activation did not finish within 0 seconds' "$error_file"
: >"$release"
wait "$holder"
acquire_node_lock "$lock" 1
exec 9>&-
EOF
	} >"$helper"
	chmod 0755 "$helper"
	grep -Fq 'acquire_node_lock() {' "$helper" || {
		echo "node-upgrade-smoke: could not extract configure-node lock acquisition" >&2
		return 1
	}
	lock="$work/configure.lock"
	ready="$work/configure.lock.ready"
	release="$work/configure.lock.release"
	error_file="$work/configure.lock.error"
	SMOKE_LOCK="$lock" SMOKE_READY="$ready" SMOKE_RELEASE="$release" \
		SMOKE_ERROR="$error_file" bash "$helper"
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

exercise_configuration_lock
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
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
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
: >"$work/docker.log"

common_env=(
	"PATH=$work/bin:$PATH"
	"FAKE_DOCKER_LOG=$work/docker.log"
	"FAKE_IMAGE_ID=$image_id"
	"FAKE_BINARY_SHA=$binary_sha"
	"STEWARD_RELAY_GID=4242"
	"STEWARD_RELAY_BINDING_ROOT=$work/relay-images"
	"STEWARD_RELAY_CURRENT_ENV=$work/etc/executor-gateway.env"
)
if [[ $relay_test == true ]]; then
	"${as_root[@]}" env "${common_env[@]}" "$root/scripts/build-relay-image.sh" \
		--release-dir "$work/releases/v0.0.0-test" >/dev/null
	binding="$work/relay-images/v0.0.0-test.env"
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
	[[ ! -e $work/etc/executor-gateway.env && ! -L $work/etc/executor-gateway.env ]]
	grep -Fq 'build --network=none --pull=false --provenance=false' "$work/docker.log"

	"${as_root[@]}" env "${common_env[@]}" "$root/scripts/build-relay-image.sh" \
		--release-dir "$work/releases/v0.0.0-test" --configure >/dev/null
	[[ -L $work/etc/executor-gateway.env ]]
	[[ $(readlink "$work/etc/executor-gateway.env") == "$binding" ]]
	[[ $(grep -c '^build ' "$work/docker.log") -eq 1 ]]

	# Model an operator-deleted image. A deterministic rebuild that returns the
	# retained image ID restores availability without replacing the binding.
	rm -f "$work/build.marker"
	"${as_root[@]}" env "${common_env[@]}" FAKE_MISSING_UNTIL_BUILD=1 \
		"FAKE_BUILD_MARKER=$work/build.marker" "$root/scripts/build-relay-image.sh" \
		--release-dir "$work/releases/v0.0.0-test" --replace-missing >/dev/null
	[[ $(grep -c '^build ' "$work/docker.log") -eq 2 ]]
	"${as_root[@]}" grep -Fxq "# relay_image_id=$image_id" "$binding"
else
	echo "node-upgrade-smoke: relay binding checks skipped (passwordless root unavailable)"
fi

guard_env=("PATH=$work/bin:$PATH" "FAKE_DOCKER_LOG=$work/docker.log")
env "${guard_env[@]}" "$root/scripts/node-removal-guard.sh"
if env "${guard_env[@]}" FAKE_AGENT_IDS=stopped-agent "$root/scripts/node-removal-guard.sh" 2>/dev/null; then
	echo "node-upgrade-smoke: stopped managed agent did not block removal" >&2
	exit 1
fi
if env "${guard_env[@]}" FAKE_NETWORK_IDS=capability-network "$root/scripts/node-removal-guard.sh" 2>/dev/null; then
	echo "node-upgrade-smoke: capability network did not block removal" >&2
	exit 1
fi
# Retained state is permitted for ordinary removal, but not an explicit purge.
env "${guard_env[@]}" FAKE_VOLUME_IDS=retained-state "$root/scripts/node-removal-guard.sh"
if env "${guard_env[@]}" FAKE_VOLUME_IDS=retained-state "$root/scripts/node-removal-guard.sh" --purge-data 2>/dev/null; then
	echo "node-upgrade-smoke: retained state volume did not block purge" >&2
	exit 1
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
