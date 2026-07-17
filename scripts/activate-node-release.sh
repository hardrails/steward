#!/bin/bash -p
# Validate and select one complete Steward node release as a serialized transaction.
set -Eeuo pipefail
if ! shopt -qo privileged; then
	echo "activate-node-release: execute this root helper directly or invoke it with /bin/bash -p" >&2
	exit 2
fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
LANG=C
HOME=/root
export PATH LC_ALL LANG HOME
unset BASH_ENV ENV CDPATH GLOBIGNORE TMPDIR XDG_CONFIG_HOME
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH
unset DOCKER_TLS_VERIFY DOCKER_API_VERSION DOCKER_BUILDKIT BUILDKIT_HOST
unset STEWARD_CONFIG_FILE STEWARD_EXECUTOR_ENV_FILE STEWARD_EXECUTOR_GATEWAY_ENV_FILE
unset STEWARD_BIN STEWARD_CONTROL_BIN STEWARD_CTL_BIN STEWARD_MCP_BIN
unset STEWARD_EXECUTOR_BIN STEWARD_GATEWAY_BIN STEWARD_RELAY_BIN
unset STEWARD_GATEWAY_CONFIG_FILE STEWARD_CONNECTOR_RECEIPT_PRIVATE_KEY_FILE
unset STEWARD_CONNECTOR_RECEIPT_PUBLIC_KEY_FILE STEWARD_UNIT_DIR
IFS=$' \t\n'
umask 077

usage() {
	cat <<'EOF' >&2
usage: activate-node-release VERSION [--restart|--no-restart]

--restart preserves the active/inactive state of each Steward service while
switching releases. --no-restart, and the backwards-compatible default, are
accepted only when all Steward services are already inactive.
EOF
}

if [[ ${EUID} -ne 0 ]]; then
	echo "activate-node-release: run as root" >&2
	exit 2
fi
find_deployed_control_plane_marker() {
	local marker
	for marker in "$@"; do
		if [[ -e $marker || -L $marker ]]; then
			printf '%s\n' "$marker"
			return 0
		fi
	done
	return 1
}
if control_plane_marker=$(find_deployed_control_plane_marker \
	/opt/steward-control \
	/etc/steward-control \
	/var/lib/steward-control-installer \
	/etc/systemd/system/steward-control.service \
	/usr/local/libexec/steward-control); then
	echo "activate-node-release: refusing to activate a node release over the deployed Steward control plane marker $control_plane_marker" >&2
	echo "  Run Steward Control and Steward nodes on separate management hosts; both products own /usr/local/bin/steward-control." >&2
	exit 2
fi
if [[ $# -lt 1 || $# -gt 2 ]]; then usage; exit 2; fi
version=$1
restart=false
case "${2:-}" in
	"") ;;
	--restart) restart=true ;;
	--no-restart) restart=false ;;
	*) usage; exit 2 ;;
esac

valid_release_version() {
	local candidate=$1 core prerelease identifier
	(( ${#candidate} <= 128 )) || return 1
	[[ $candidate =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$ ]] || return 1
	core=${candidate#v}
	if [[ $core == *-* ]]; then
		prerelease=${core#*-}
		IFS=. read -r -a identifiers <<<"$prerelease"
		for identifier in "${identifiers[@]}"; do
			[[ $identifier =~ ^[0-9]+$ && $identifier == 0[0-9]* ]] && return 1
		done
	fi
	return 0
}
if ! valid_release_version "$version"; then
	echo "activate-node-release: version must be an installable vX.Y.Z release tag" >&2
	exit 2
fi
case "$(uname -m)" in
	x86_64 | amd64) goarch=amd64 ;;
	aarch64 | arm64) goarch=arm64 ;;
	*) echo "activate-node-release: unsupported architecture $(uname -m)" >&2; exit 2 ;;
esac

release_dir="/opt/steward/releases/$version"
release_files=(
	steward
	steward-control
	steward-executor
	steward-gateway
	steward-mcp
	steward-relay
	stewardctl
	integration/adapters/hermes-agent/Dockerfile
	integration/adapters/hermes-agent/README.md
	integration/adapters/hermes-agent/adapter.json
	integration/adapters/hermes-agent/entrypoint.py
	integration/adapters/hermes-agent/fixture_connector.py
	integration/adapters/hermes-agent/fixture_mcp.py
	integration/adapters/hermes-agent/fixture_model.py
	integration/adapters/hermes-agent/fixture_secret_scan.py
	integration/adapters/hermes-agent/fixtures/connector-skill/SKILL.md
	integration/adapters/hermes-agent/fixtures/connector-skill/connector-fixture-contract.json
	integration/adapters/hermes-agent/fixtures/connector-skill/connector_work.py
	integration/adapters/hermes-agent/fixtures/connector-skill/manifest.json
	integration/adapters/hermes-agent/fixtures/connector-skill/manifest.sig
	integration/adapters/hermes-agent/fixtures/connector-skill/public.pem
	integration/adapters/hermes-agent/fixtures/skill/SKILL.md
	integration/adapters/hermes-agent/fixtures/skill/manifest.json
	integration/adapters/hermes-agent/fixtures/skill/manifest.sig
	integration/adapters/hermes-agent/fixtures/skill/public.pem
	integration/adapters/hermes-agent/fixtures/skill/workspace-fixture-contract.json
	integration/adapters/hermes-agent/fixtures/skill/workspace_audit.py
	integration/adapters/hermes-agent/license-inventory.json
	integration/adapters/hermes-agent/source-inputs.sha256
	integration/deploy/config/executor-gateway.env
	integration/deploy/config/executor.env
	integration/deploy/config/gateway.json.in
	integration/deploy/config/steward-local.json
	integration/deploy/config/steward.json
	integration/deploy/systemd/steward-executor.service
	integration/deploy/systemd/steward-gateway.service
	integration/deploy/systemd/steward.service
	integration/scripts/activate-node-release.sh
	integration/scripts/build-hermes-adapter.sh
	integration/scripts/build-relay-image.sh
	integration/scripts/configure-admission.sh
	integration/scripts/configure-node.sh
	integration/scripts/install-node.sh
	integration/scripts/hermes-feasibility.sh
	integration/scripts/hermes-steward-acceptance.sh
	integration/scripts/node-doctor.sh
	integration/scripts/node-preflight.sh
	integration/scripts/node-removal-guard.sh
	integration/scripts/uninstall-node.sh
)

hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		echo "activate-node-release: sha256sum or shasum is required" >&2
		exit 2
	fi
}

write_canonical_manifest() {
	local output=$1 logical path suffix index last_index
	{
		printf '{\n'
		printf '  "schema": "steward.release.v2",\n'
		printf '  "version": "%s",\n' "$version"
		printf '  "os": "linux",\n'
		printf '  "arch": "%s",\n' "$goarch"
		printf '  "state_formats": {\n'
		printf '    "admission_fence": {"read_min": 1, "read_max": 2, "write": 2},\n'
		printf '    "connector_receipt_log": {"read_min": 1, "read_max": 5, "write": 5},\n'
		printf '    "evidence_log": {"read_min": 1, "read_max": 2, "write": 2},\n'
		printf '    "gateway_state": {"read_min": 1, "read_max": 5, "write": 5},\n'
		printf '    "operation_journal": {"read_min": 1, "read_max": 1, "write": 1},\n'
		printf '    "supervisor_state": {"read_min": 1, "read_max": 1, "write": 1},\n'
		printf '    "uplink_delivery_state": {"read_min": 2, "read_max": 4, "write": 4},\n'
		printf '    "uplink_state": {"read_min": 2, "read_max": 2, "write": 2}\n'
		printf '  },\n'
		printf '  "files": {\n'
		last_index=$((${#release_files[@]} - 1))
		for index in "${!release_files[@]}"; do
			logical=${release_files[$index]}
			path="$release_dir/$logical"
			if [[ ! -f $path || -L $path ]]; then
				echo "activate-node-release: release is missing regular file $logical" >&2
				return 2
			fi
			suffix=,
			(( index == last_index )) && suffix=
			printf '    "%s": "%s"%s\n' "$logical" "$(hash_file "$path")" "$suffix"
		done
		printf '  }\n'
		printf '}\n'
	} >"$output"
}

if [[ ! -d $release_dir || -L $release_dir ]]; then
	echo "activate-node-release: release directory is missing or invalid: $release_dir" >&2
	exit 2
fi
manifest="$release_dir/release.json"
if [[ ! -f $manifest || -L $manifest ]]; then
	echo "activate-node-release: release is missing regular file release.json" >&2
	exit 2
fi
manifest_version=$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' "$manifest")
if [[ $manifest_version != "$version" ]]; then
	echo "activate-node-release: release.json reports '${manifest_version:-<invalid>}', expected '$version'" >&2
	exit 2
fi
expected_manifest=$(mktemp)
write_canonical_manifest "$expected_manifest"
if ! cmp -s "$manifest" "$expected_manifest"; then
	rm -f "$expected_manifest"
	echo "activate-node-release: release.json does not match the target or release files" >&2
	exit 2
fi
rm -f "$expected_manifest"
if find "$release_dir" -mindepth 1 -type l -print -quit | grep -q . ||
	find "$release_dir" -mindepth 1 ! -type f ! -type d -print -quit | grep -q .; then
	echo "activate-node-release: immutable release contains a symlink or special file" >&2
	exit 2
fi
file_count=$(find "$release_dir" -mindepth 1 -type f | wc -l)
if [[ $file_count -ne $((${#release_files[@]} + 1)) ]]; then
	echo "activate-node-release: immutable release contains unexpected files" >&2
	exit 2
fi
for binary in steward steward-control stewardctl steward-mcp steward-executor steward-gateway steward-relay; do
	reported=$(runuser -u steward -- "$release_dir/$binary" -version | awk '{print $2}')
	if [[ $reported != "$version" ]]; then
		echo "activate-node-release: $binary reports '$reported', expected '$version'" >&2
		exit 2
	fi
done

# BEGIN NODE_LOCK_BOUNDARY
readonly node_lock_directory=/run/steward-node
readonly node_lock_file=$node_lock_directory/activation.lock
readonly node_lock_error_prefix=activate-node-release

prepare_node_lock() {
	local metadata uid mode
	if [[ -L /run || ! -d /run ]]; then
		echo "$node_lock_error_prefix: refusing an unsafe /run directory" >&2
		return 2
	fi
	metadata=$(stat -c '%u:%a' -- /run) || return 2
	uid=${metadata%%:*}; mode=${metadata#*:}
	if [[ $uid != 0 ]] || (( (8#$mode & 022) != 0 )); then
		echo "$node_lock_error_prefix: /run must be root-owned and not group- or world-writable" >&2
		return 2
	fi
	if [[ ! -e $node_lock_directory && ! -L $node_lock_directory ]]; then
		install -d -o root -g root -m 0700 -- "$node_lock_directory"
	fi
	if [[ -L $node_lock_directory || ! -d $node_lock_directory ||
		$(readlink -e -- "$node_lock_directory" 2>/dev/null) != "$node_lock_directory" ||
		$(stat -c '%u:%g:%a' -- "$node_lock_directory" 2>/dev/null) != 0:0:700 ]]; then
		echo "$node_lock_error_prefix: refusing an unsafe node lock directory" >&2
		return 2
	fi
	if [[ ! -e $node_lock_file && ! -L $node_lock_file ]]; then
		(umask 077; set -o noclobber; : >"$node_lock_file") 2>/dev/null || true
	fi
	if [[ -L $node_lock_file || ! -f $node_lock_file ||
		$(stat -c '%u:%g:%a:%h' -- "$node_lock_file" 2>/dev/null) != 0:0:600:1 ]]; then
		echo "$node_lock_error_prefix: refusing an unsafe node activation lock" >&2
		return 2
	fi
}

node_lock_fd_matches() {
	local fd=$1 path_metadata fd_metadata process_id=${BASHPID:-$$}
	[[ $fd == 9 && -e /proc/$process_id/fd/$fd ]] || return 1
	path_metadata=$(stat -c '%d:%i:%u:%g:%a:%h' -- "$node_lock_file") || return 1
	fd_metadata=$(stat -Lc '%d:%i:%u:%g:%a:%h' -- "/proc/$process_id/fd/$fd") || return 1
	[[ $path_metadata == "$fd_metadata" && $path_metadata == *:0:0:600:1 ]]
}

acquire_node_lock() {
	local wait_seconds=${1:-60}
	[[ $wait_seconds =~ ^[0-9]+$ ]] || return 2
	command -v flock >/dev/null 2>&1 || {
		echo "$node_lock_error_prefix: flock is required to serialize node activation" >&2
		return 2
	}
	prepare_node_lock || return
	exec 9<>"$node_lock_file"
	if ! node_lock_fd_matches 9; then
		echo "$node_lock_error_prefix: node activation lock changed while it was opened" >&2
		exec 9>&-
		return 2
	fi
	if ! flock -w "$wait_seconds" 9; then
		echo "$node_lock_error_prefix: another node configuration or activation did not finish within $wait_seconds seconds" >&2
		exec 9>&-
		return 1
	fi
}
# END NODE_LOCK_BOUNDARY

acquire_node_lock 60

previous_current=
if [[ -e /opt/steward/current || -L /opt/steward/current ]]; then
	previous_current=$(readlink /opt/steward/current 2>/dev/null || true)
	case "$previous_current" in
		/opt/steward/releases/*)
			[[ -d $previous_current && ! -L $previous_current ]] || {
				echo "activate-node-release: active release target is missing or invalid: $previous_current" >&2
				exit 2
			}
			;;
		*) echo "activate-node-release: refusing unmanaged /opt/steward/current" >&2; exit 2 ;;
	esac
fi
transition=true
[[ $previous_current == "$release_dir" ]] && transition=false

was_gateway=false
was_steward=false
was_executor=false
read_service_activity() {
	local unit=$1 state status=0
	state=$(systemctl is-active "$unit" 2>/dev/null) || status=$?
	case "$status:$state" in
		0:active) printf '%s\n' active ;;
		*:inactive)
			(( status != 0 )) || return 2
			printf '%s\n' inactive
			;;
		*)
			echo "activate-node-release: could not determine the exact systemd state of $unit" >&2
			return 2
			;;
	esac
}
gateway_activity=$(read_service_activity steward-gateway.service) || exit 2
steward_activity=$(read_service_activity steward.service) || exit 2
executor_activity=$(read_service_activity steward-executor.service) || exit 2
[[ $gateway_activity == active ]] && was_gateway=true
[[ $steward_activity == active ]] && was_steward=true
[[ $executor_activity == active ]] && was_executor=true
if [[ $restart == false && ( $was_gateway == true || $was_steward == true || $was_executor == true ) ]]; then
	echo "activate-node-release: --no-restart is unsafe while a Steward service is active" >&2
	echo "  Re-run with --restart, or stop Gateway, Steward, and Executor first." >&2
	exit 2
fi

gateway_env=/etc/steward/executor-gateway.env
executor_env=/etc/steward/executor.env
gateway_env_backup=$(mktemp -d /run/steward-relay-selector.XXXXXX)
trap 'rm -rf -- "$gateway_env_backup"' EXIT
gateway_env_present=false
if [[ -e $gateway_env || -L $gateway_env ]]; then
	cp -a -- "$gateway_env" "$gateway_env_backup/executor-gateway.env"
	gateway_env_present=true
fi
executor_env_present=false
if [[ -e $executor_env || -L $executor_env ]]; then
	cp -a -- "$executor_env" "$gateway_env_backup/executor.env"
	executor_env_present=true
fi
topology_enabled=false
if [[ ( -e $gateway_env || -L $gateway_env ) && ! -r $gateway_env ]]; then
	echo "activate-node-release: live Executor gateway environment is missing or unreadable" >&2
	exit 2
fi
if [[ -r $gateway_env ]]; then
	gateway_line=$(grep -v '^[[:space:]]*#' "$gateway_env" | grep -v '^[[:space:]]*$' || true)
	if [[ -n $gateway_line ]]; then
		if [[ $gateway_line != EXECUTOR_GATEWAY_ARGS=* || $gateway_line == *$'\n'* ]]; then
			echo "activate-node-release: live Executor gateway environment is invalid" >&2
			exit 2
		fi
		[[ -n ${gateway_line#EXECUTOR_GATEWAY_ARGS=} ]] && topology_enabled=true
	fi
fi

admission_mode=unconfigured
if [[ -r /etc/steward/executor.env ]]; then
	set_count=$(awk -F= '
		BEGIN {
			required["EXECUTOR_ADMISSION_POLICY_FILE"] = 1
			required["EXECUTOR_ADMISSION_SITE_ROOT_PUBLIC_KEY_FILE"] = 1
			required["EXECUTOR_ADMISSION_SITE_ROOT_KEY_ID"] = 1
			required["EXECUTOR_ADMISSION_NODE_ID"] = 1
			required["EXECUTOR_ADMISSION_EVIDENCE_KEY_FILE"] = 1
		}
		$1 in required && length(substr($0, index($0, "=") + 1)) > 0 { set++ }
		END { print set + 0 }
	' /etc/steward/executor.env)
	case "$set_count" in
		0) admission_mode=unconfigured ;;
		5) admission_mode=configured ;;
		*) echo "activate-node-release: signed-admission configuration is incomplete" >&2; exit 2 ;;
	esac
fi

services_stopped=false
selectors_switched=false
target_services_started=false
failure_handled=false
executor_setup_changed=false
uplink_delivery_state_created=false
uplink_delivery_state=/var/lib/steward-executor/uplink-delivery-state.json
executor_env_tmp=

start_previous_services() {
	local failed=false
	[[ $was_gateway == false ]] || systemctl start steward-gateway.service || failed=true
	[[ $was_steward == false ]] || systemctl start steward.service || failed=true
	[[ $was_executor == false ]] || systemctl start steward-executor.service || failed=true
	[[ $failed == false ]]
}

stop_active_services() {
	local failed=false state unit
	for unit in steward-gateway.service steward.service steward-executor.service; do
		state=$(read_service_activity "$unit") || { failed=true; continue; }
		if [[ $state == active ]] && ! systemctl stop "$unit"; then
			failed=true
			continue
		fi
		state=$(read_service_activity "$unit") || { failed=true; continue; }
		[[ $state == inactive ]] || failed=true
	done
	[[ $failed == false ]]
}

replace_selector() {
	local temporary=$1 destination=$2
	# Arm rollback before mv can change the destination or be interrupted after it
	# has done so. Restoring an unchanged selector is safe.
	selectors_switched=true
	mv -Tf -- "$temporary" "$destination"
}

restore_selectors() {
	local current_tmp failed=false
	if [[ $gateway_env_present == true ]]; then
		rm -f "$gateway_env" || failed=true
		cp -a -- "$gateway_env_backup/executor-gateway.env" "$gateway_env" || failed=true
	else
		rm -f "$gateway_env" || failed=true
	fi
	current_tmp="/opt/steward/.current.rollback.$$"
	rm -f "$current_tmp" || failed=true
	if [[ -n $previous_current ]]; then
		ln -s "$previous_current" "$current_tmp" || failed=true
		mv -Tf "$current_tmp" /opt/steward/current || failed=true
	else
		rm -f /opt/steward/current || failed=true
	fi
	systemctl daemon-reload || failed=true
	[[ $failed == false ]]
}

restore_executor_setup() {
	local failed=false
	[[ $executor_setup_changed == true ]] || return 0
	rm -f -- "${executor_env_tmp:-}" || failed=true
	executor_env_tmp=
	if [[ $executor_env_present == true ]]; then
		rm -f -- "$executor_env" || failed=true
		cp -a -- "$gateway_env_backup/executor.env" "$executor_env" || failed=true
	else
		rm -f -- "$executor_env" || failed=true
	fi
	[[ $uplink_delivery_state_created == false ]] || rm -f -- "$uplink_delivery_state" || failed=true
	if [[ $failed == false ]]; then
		executor_setup_changed=false
		uplink_delivery_state_created=false
	fi
	[[ $failed == false ]]
}

activation_exit() {
	local status=$?
	trap - EXIT ERR HUP INT TERM
	executor_restore_ok=true
	if (( status != 0 )) && [[ $target_services_started == false && $executor_setup_changed == true ]]; then
		set +e
		if ! restore_executor_setup; then
			executor_restore_ok=false
			echo "activate-node-release: target validation failed and Executor delivery setup could not be restored" >&2
			echo "  Steward services remain stopped. Repair $executor_env and $uplink_delivery_state before starting them." >&2
		fi
		set -e
	fi
	if (( status != 0 )) && [[ $failure_handled == false && ( $services_stopped == true || $selectors_switched == true ) ]]; then
		failure_handled=true
		set +e
		if [[ $selectors_switched == true ]]; then
			services_quiesced=false
			if stop_active_services; then services_quiesced=true; fi
			safe_restore=$services_quiesced
			if [[ $services_quiesced == true && $target_services_started == true ]]; then
				safe_restore=false
				if [[ -n $previous_current && -f $previous_current/release.json ]]; then
					if "$release_dir/integration/scripts/node-removal-guard.sh" >/dev/null && \
						"$release_dir/stewardctl" upgrade inspect-formats \
						-signed-admission "$admission_mode" \
						-gateway-config /etc/steward/gateway.json \
						-release-manifest "$previous_current/release.json" >/dev/null; then
						safe_restore=true
					fi
				fi
			fi
			if [[ $safe_restore == true ]]; then
				restore_ok=false
				if restore_selectors; then restore_ok=true; fi
				if [[ $restore_ok == true && $executor_restore_ok == true ]] && start_previous_services; then
					echo "activate-node-release: activation failed; restored the prior release and relay binding" >&2
				elif [[ $restore_ok == false ]]; then
					echo "activate-node-release: activation failed and prior selectors could not be restored completely" >&2
					echo "  Steward services remain stopped. Repair /opt/steward/current and $gateway_env before starting them." >&2
				elif [[ $executor_restore_ok == true ]]; then
					echo "activate-node-release: activation failed; restored prior selectors, but one or more prior services did not restart" >&2
				fi
			elif [[ $services_quiesced == false ]]; then
				echo "activate-node-release: activation failed and one or more target services could not be proven stopped" >&2
				echo "  Target selectors remain selected. Stop all Steward services and verify they are inactive before repairing selectors." >&2
			else
				echo "activate-node-release: activation failed after target services started; durable formats are not proven readable by the prior release" >&2
				echo "  Target selectors remain selected and Steward services are stopped. Repair the target or follow an approved state migration; do not force a binary rollback." >&2
			fi
		else
			if [[ $executor_restore_ok == true ]] && start_previous_services; then
				echo "activate-node-release: target validation failed; restored the prior service state" >&2
			elif [[ $executor_restore_ok == true ]]; then
				echo "activate-node-release: target validation failed and a prior service did not restart" >&2
			fi
		fi
		set -e
	fi
	rm -f -- "${executor_env_tmp:-}"
	rm -rf -- "$gateway_env_backup"
	exit "$status"
}
trap activation_exit EXIT
trap 'exit 130' HUP INT TERM

activation_error() {
	echo "activate-node-release: $1" >&2
	return 2
}

read_executor_setting() {
	local key=$1
	awk -F= -v key="$key" '
		$1 == key {
			seen++
			value = substr($0, index($0, "=") + 1)
		}
		END {
			if (seen > 1) exit 2
			if (seen == 1) print value
		}
	' "$executor_env"
}

executor_setting_count() {
	local key=$1
	awk -F= -v key="$key" '
		$1 == key { count++ }
		END { print count + 0 }
	' "$executor_env"
}

write_executor_uplink_setup() {
	local protocol_version=$1 delivery_file=$2
	executor_env_tmp=$(mktemp "${executor_env%/*}/.executor.env.XXXXXX")
	awk -v protocol="$protocol_version" -v delivery="$delivery_file" '
		/^EXECUTOR_UPLINK_PROTOCOL_VERSION=/ {
			if (found_protocol++) exit 3
			print "EXECUTOR_UPLINK_PROTOCOL_VERSION=" protocol
			next
		}
		/^EXECUTOR_UPLINK_DELIVERY_STATE_FILE=/ {
			if (found_delivery++) exit 3
			print "EXECUTOR_UPLINK_DELIVERY_STATE_FILE=" delivery
			next
		}
		{ print }
		END {
			if (!found_protocol) print "EXECUTOR_UPLINK_PROTOCOL_VERSION=" protocol
			if (!found_delivery) print "EXECUTOR_UPLINK_DELIVERY_STATE_FILE=" delivery
		}
	' "$executor_env" >"$executor_env_tmp"
	chown root:root "$executor_env_tmp"
	chmod 0600 "$executor_env_tmp"
	executor_setup_changed=true
	mv -f "$executor_env_tmp" "$executor_env"
	executor_env_tmp=
}

prepare_uplink_delivery_state() {
	local credential_file metadata scope credential_node configured_node delivery_file
	local protocol_count protocol_version write_setup=false
	[[ -r $executor_env ]] || return 0
	protocol_count=$(executor_setting_count EXECUTOR_UPLINK_PROTOCOL_VERSION)
	case "$protocol_count" in
		0)
			# A node running an older package selected protocol 3 implicitly when a
			# delivery ledger was present. Persisting 0 preserves that behavior and
			# does not silently move an active node to protocol 4 during activation.
			protocol_version=0
			write_setup=true
			;;
		1) protocol_version=$(read_executor_setting EXECUTOR_UPLINK_PROTOCOL_VERSION) ;;
		*) activation_error "Executor uplink protocol setting is duplicated" ;;
	esac
	case "$protocol_version" in
		0 | 3 | 4) ;;
		*) activation_error "EXECUTOR_UPLINK_PROTOCOL_VERSION must be 0, 3, or 4" ;;
	esac
	delivery_file=$(read_executor_setting EXECUTOR_UPLINK_DELIVERY_STATE_FILE)
	credential_file=$(read_executor_setting EXECUTOR_UPLINK_CREDENTIAL_FILE)
	if [[ -z $credential_file ]]; then
		if [[ $protocol_version != 0 ]]; then
			activation_error "Executor uplink protocol $protocol_version requires an uplink credential"
		fi
		if [[ -n $delivery_file ]]; then
			activation_error "Executor delivery state requires an uplink credential"
		fi
		[[ $write_setup == false ]] || write_executor_uplink_setup 0 ""
		return 0
	fi
	metadata=$(runuser -u steward-executor -- "$release_dir/steward-executor" \
		-inspect-uplink-credential -uplink-credential-file "$credential_file")
	if [[ $metadata != *$'\n'* ]]; then
		activation_error "Executor credential inspection returned invalid metadata"
	fi
	scope=${metadata%%$'\n'*}
	credential_node=${metadata#*$'\n'}
	if [[ $credential_node == *$'\n'* || ( $scope != tenant && $scope != node ) ]]; then
		activation_error "Executor credential inspection returned invalid metadata"
	fi
	if [[ $scope == tenant ]]; then
		if [[ $protocol_version != 0 ]]; then
			activation_error "tenant-scoped Executor credentials require uplink protocol setting 0"
		fi
		if [[ -n $delivery_file ]]; then
			activation_error "tenant-scoped Executor credentials cannot use delivery state"
		fi
		[[ $write_setup == false ]] || write_executor_uplink_setup 0 ""
		return 0
	fi
	if [[ $admission_mode != configured ]]; then
		activation_error "a node-scoped Executor credential requires complete signed admission"
	fi
	configured_node=$(read_executor_setting EXECUTOR_ADMISSION_NODE_ID)
	if [[ -z $configured_node || $configured_node != "$credential_node" ]]; then
		activation_error "node-scoped Executor credential node ID does not match signed admission"
	fi
	if [[ -n $delivery_file ]]; then
		[[ $write_setup == false ]] || write_executor_uplink_setup "$protocol_version" "$delivery_file"
		return 0
	fi
	if [[ ! -f $executor_env || -L $executor_env ]]; then
		activation_error "Executor environment must be a regular non-symlink file before delivery setup"
	fi
	if [[ ! -e $uplink_delivery_state && ! -L $uplink_delivery_state ]]; then
		runuser -u steward-executor -- "$release_dir/steward-executor" \
			-initialize-uplink-delivery-state \
			-uplink-delivery-state-file "$uplink_delivery_state" \
			-admission-node-id "$configured_node"
		uplink_delivery_state_created=true
		executor_setup_changed=true
	fi
	write_executor_uplink_setup "$protocol_version" "$uplink_delivery_state"
}

if [[ $restart == true && ( $was_gateway == true || $was_steward == true || $was_executor == true ) ]]; then
	services_stopped=true
	# Stop writers and capability entry points in a fixed order before checking
	# drain state or durable-format compatibility.
	[[ $was_gateway == false ]] || systemctl stop steward-gateway.service
	[[ $was_steward == false ]] || systemctl stop steward.service
	[[ $was_executor == false ]] || systemctl stop steward-executor.service
fi

if [[ $transition == true ]]; then
	# Docker objects are checked by label and include stopped containers. The CLI
	# additionally rejects live signed-admission fences, pending journal entries,
	# and retained Gateway grants, then validates observed formats against the
	# target manifest without changing any state.
	"$release_dir/integration/scripts/node-removal-guard.sh"
	"$release_dir/stewardctl" upgrade check-drained \
		-signed-admission "$admission_mode" \
		-gateway-config /etc/steward/gateway.json \
		-release-manifest "$manifest"
fi

target_gateway_env=$gateway_env
if [[ $topology_enabled == true ]]; then
	if [[ $transition == false ]]; then
		# A same-release repair can still change the relay image binding. Apply the
		# same drain proof as a version transition before building or selecting it.
		"$release_dir/integration/scripts/node-removal-guard.sh"
		"$release_dir/stewardctl" upgrade check-drained \
			-signed-admission "$admission_mode" \
			-gateway-config /etc/steward/gateway.json \
			-release-manifest "$manifest"
	fi
	# Preparation writes only the target's per-release binding. The live selector
	# remains unchanged until target preflight has accepted the binding.
	"$release_dir/integration/scripts/build-relay-image.sh" --release-dir "$release_dir" --replace-missing
	target_gateway_env="/var/lib/steward-node/relay-images/$version.env"
fi

# Preserve an existing explicit protocol selection. An older configuration with no
# selection receives 0, which keeps its prior credential-driven behavior instead of
# silently switching it to protocol 4. Prepare node delivery state after writers are
# stopped and compatibility is proven, but before target preflight.
prepare_uplink_delivery_state

STEWARD_BIN="$release_dir/steward" \
	STEWARD_CONTROL_BIN="$release_dir/steward-control" \
	STEWARD_CTL_BIN="$release_dir/stewardctl" \
	STEWARD_MCP_BIN="$release_dir/steward-mcp" \
	STEWARD_EXECUTOR_BIN="$release_dir/steward-executor" \
	STEWARD_GATEWAY_BIN="$release_dir/steward-gateway" \
	STEWARD_RELAY_BIN="$release_dir/steward-relay" \
	STEWARD_EXECUTOR_GATEWAY_ENV_FILE="$target_gateway_env" \
	STEWARD_UNIT_DIR="$release_dir/integration/deploy/systemd" \
	"$release_dir/integration/scripts/node-preflight.sh"

check_managed_symlink() {
	local path=$1 target
	if [[ ! -e $path && ! -L $path ]]; then return 0; fi
	if [[ -L $path ]]; then
		target=$(readlink "$path")
		case "$target" in /opt/steward/current/* | /opt/steward/releases/*) return 0 ;; esac
	fi
	echo "activate-node-release: refusing unmanaged $path" >&2
	return 2
}

check_legacy_regular() {
	local path=$1 mode owner
	[[ -f $path && ! -L $path ]] || return 1
	owner=$(stat -c '%u' "$path")
	mode=$(stat -c '%a' "$path")
	[[ $owner == 0 ]] || return 1
	(( (8#$mode & 0022) == 0 ))
}

for binary in steward steward-control stewardctl steward-mcp steward-executor steward-gateway steward-relay; do
	check_managed_symlink "/usr/local/bin/$binary"
done
for mapping in \
	activate-node-release:/opt/steward/current/integration/scripts/activate-node-release.sh \
	node-doctor:/opt/steward/current/integration/scripts/node-doctor.sh \
	node-preflight:/opt/steward/current/integration/scripts/node-preflight.sh \
	configure-node:/opt/steward/current/integration/scripts/configure-node.sh \
	configure-admission:/opt/steward/current/integration/scripts/configure-admission.sh \
	uninstall-node:/opt/steward/current/integration/scripts/uninstall-node.sh \
	node-removal-guard:/opt/steward/current/integration/scripts/node-removal-guard.sh \
	build-hermes-adapter:/opt/steward/current/integration/scripts/build-hermes-adapter.sh \
	build-relay-image:/opt/steward/current/integration/scripts/build-relay-image.sh \
	hermes-steward-acceptance:/opt/steward/current/integration/scripts/hermes-steward-acceptance.sh; do
	name=${mapping%%:*}
	path="/usr/local/libexec/steward/$name"
	if [[ -e $path || -L $path ]]; then
		if [[ -L $path ]]; then check_managed_symlink "$path"
		elif ! check_legacy_regular "$path"; then
			echo "activate-node-release: refusing unmanaged $path" >&2
			exit 2
		fi
	fi
done
for unit in steward.service steward-executor.service steward-gateway.service; do
	path="/usr/local/lib/systemd/system/$unit"
	if [[ -e $path || -L $path ]]; then
		if [[ -L $path ]]; then check_managed_symlink "$path"
		elif ! check_legacy_regular "$path"; then
			echo "activate-node-release: refusing unmanaged $path" >&2
			exit 2
		fi
	fi
	legacy="/etc/systemd/system/$unit"
	if [[ -e $legacy || -L $legacy ]]; then
		legacy_owned=false
		if [[ -f $legacy && ! -L $legacy ]]; then
			if [[ -n $previous_current && -f $previous_current/integration/deploy/systemd/$unit ]] &&
				cmp -s "$legacy" "$previous_current/integration/deploy/systemd/$unit"; then
				legacy_owned=true
			elif [[ -f $path && ! -L $path ]] && cmp -s "$legacy" "$path"; then
				legacy_owned=true
			elif cmp -s "$legacy" "$release_dir/integration/deploy/systemd/$unit"; then
				legacy_owned=true
			fi
		fi
		if [[ $legacy_owned != true ]]; then
			echo "activate-node-release: refusing modified $legacy because it shadows the packaged vendor unit" >&2
			echo "  Preserve local settings in /etc/systemd/system/$unit.d/*.conf, then remove the full-unit override and re-run." >&2
			exit 2
		fi
	fi
done

install -d -o root -g root -m 0755 /opt/steward /usr/local/bin \
	/usr/local/libexec/steward /usr/local/lib/systemd/system
for binary in steward steward-control stewardctl steward-mcp steward-executor steward-gateway steward-relay; do
	tmp="/usr/local/bin/.${binary}.new.$$"
	rm -f "$tmp"
	ln -s "/opt/steward/current/$binary" "$tmp"
	mv -Tf "$tmp" "/usr/local/bin/$binary"
done
for mapping in \
	activate-node-release:/opt/steward/current/integration/scripts/activate-node-release.sh \
	node-doctor:/opt/steward/current/integration/scripts/node-doctor.sh \
	node-preflight:/opt/steward/current/integration/scripts/node-preflight.sh \
	configure-node:/opt/steward/current/integration/scripts/configure-node.sh \
	configure-admission:/opt/steward/current/integration/scripts/configure-admission.sh \
	uninstall-node:/opt/steward/current/integration/scripts/uninstall-node.sh \
	node-removal-guard:/opt/steward/current/integration/scripts/node-removal-guard.sh \
	build-hermes-adapter:/opt/steward/current/integration/scripts/build-hermes-adapter.sh \
	build-relay-image:/opt/steward/current/integration/scripts/build-relay-image.sh \
	hermes-steward-acceptance:/opt/steward/current/integration/scripts/hermes-steward-acceptance.sh; do
	name=${mapping%%:*}
	target=${mapping#*:}
	tmp="/usr/local/libexec/steward/.${name}.new.$$"
	rm -f "$tmp"
	ln -s "$target" "$tmp"
	mv -Tf "$tmp" "/usr/local/libexec/steward/$name"
done
for unit in steward.service steward-executor.service steward-gateway.service; do
	legacy="/etc/systemd/system/$unit"
	if [[ -e $legacy || -L $legacy ]]; then
		rm -f "$legacy"
		echo "activate-node-release: migrated legacy installer-owned $legacy"
	fi
	tmp="/usr/local/lib/systemd/system/.${unit}.new.$$"
	rm -f "$tmp"
	ln -s "/opt/steward/current/integration/deploy/systemd/$unit" "$tmp"
	mv -Tf "$tmp" "/usr/local/lib/systemd/system/$unit"
done

if [[ $topology_enabled == true ]]; then
	selector_tmp="/etc/steward/.executor-gateway.env.new.$$"
	rm -f "$selector_tmp"
	ln -s "$target_gateway_env" "$selector_tmp"
	replace_selector "$selector_tmp" "$gateway_env"
fi
current_tmp="/opt/steward/.current.new.$$"
rm -f "$current_tmp"
ln -s "$release_dir" "$current_tmp"
replace_selector "$current_tmp" /opt/steward/current
systemctl daemon-reload

if [[ $restart == true ]]; then
	target_services_started=true
	[[ $was_gateway == false ]] || systemctl start steward-gateway.service
	[[ $was_steward == false ]] || systemctl start steward.service
	[[ $was_executor == false ]] || systemctl start steward-executor.service
	[[ $was_gateway == false ]] || systemctl is-active --quiet steward-gateway.service
	[[ $was_steward == false ]] || systemctl is-active --quiet steward.service
	[[ $was_executor == false ]] || systemctl is-active --quiet steward-executor.service
fi

rm -rf -- "$gateway_env_backup"
trap - EXIT
echo "activate-node-release: active version is $version"
