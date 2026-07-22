#!/bin/bash -p
# Inspect one installed Steward node without changing its configuration or state.
set -uo pipefail

# Do not inherit an operator shell's PATH, locale, proxy selection, or permissive
# file-creation mask. Tests and appliance variants may replace individual commands
# with the absolute-path overrides documented below; command strings are never eval'd.
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
LC_ALL=C
export PATH LC_ALL
umask 077

# Operator shell networking and Docker selection must not redirect a root-run
# diagnostic or cause a bearer header to be disclosed through client tracing.
# The active Executor socket is loaded from its installed environment below.
unset http_proxy https_proxy ftp_proxy all_proxy no_proxy
unset HTTP_PROXY HTTPS_PROXY FTP_PROXY ALL_PROXY NO_PROXY
unset CURL_HOME DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_TLS_VERIFY DOCKER_CERT_PATH
unset DOCKER_API_VERSION DOCKER_DEFAULT_PLATFORM DOCKER_CUSTOM_HEADERS
unset DOCKER_CONTENT_TRUST DOCKER_CONTENT_TRUST_SERVER

doctor_sourced=false
[[ ${BASH_SOURCE[0]} == "$0" ]] || doctor_sourced=true
readonly doctor_sourced

readonly doctor_schema=steward.node-doctor.v1
readonly max_json_bytes=65536
readonly max_path_bytes=1024
readonly max_message_bytes=512

json_output=false
canary_bundle=
canary_result=
canary_token_file=${STEWARD_DOCTOR_GATEWAY_TOKEN_FILE:-/etc/steward/gateway-service-token}
canary_gateway_url=${STEWARD_DOCTOR_GATEWAY_URL:-http://127.0.0.1:8091}
canary_wait_seconds=${STEWARD_DOCTOR_CANARY_WAIT_SECONDS:-180}
canary_submit_seconds=${STEWARD_DOCTOR_CANARY_SUBMIT_SECONDS:-180}
canary_requested=false
canary_status=skipped

preflight_seconds=${STEWARD_DOCTOR_PREFLIGHT_SECONDS:-120}
command_seconds=${STEWARD_DOCTOR_COMMAND_SECONDS:-10}
http_seconds=${STEWARD_DOCTOR_HTTP_SECONDS:-5}
store_warn_percent=${STEWARD_DOCTOR_STORE_WARN_PERCENT:-80}
store_fail_percent=${STEWARD_DOCTOR_STORE_FAIL_PERCENT:-95}
fs_warn_free_percent=${STEWARD_DOCTOR_FS_WARN_FREE_PERCENT:-15}
fs_fail_free_percent=${STEWARD_DOCTOR_FS_FAIL_FREE_PERCENT:-5}

supervisor_url=${STEWARD_DOCTOR_SUPERVISOR_URL:-http://127.0.0.1:8080}
executor_url=${STEWARD_DOCTOR_EXECUTOR_URL:-http://127.0.0.1:8090}
executor_token_file=${STEWARD_DOCTOR_EXECUTOR_TOKEN_FILE:-}
executor_token_overridden=false
[[ -z ${STEWARD_DOCTOR_EXECUTOR_TOKEN_FILE:-} ]] || executor_token_overridden=true
executor_operator_token_file=
executor_observer_token_file=
executor_env_file=${STEWARD_DOCTOR_EXECUTOR_ENV_FILE:-/etc/steward/executor.env}
executor_docker_socket=
gateway_control_socket=${STEWARD_DOCTOR_GATEWAY_CONTROL_SOCKET:-/run/steward-gateway/control.sock}

fence_file=${STEWARD_DOCTOR_ADMISSION_FENCE_FILE:-/var/lib/steward-executor/admission-fences.bin}
journal_file=${STEWARD_DOCTOR_OPERATION_JOURNAL_FILE:-/var/lib/steward-executor/operation-journal.bin}
evidence_file=${STEWARD_DOCTOR_EVIDENCE_FILE:-/var/lib/steward-executor/evidence.bin}
uplink_state_file=${STEWARD_DOCTOR_UPLINK_STATE_FILE:-}
uplink_state_overridden=false
[[ -z ${STEWARD_DOCTOR_UPLINK_STATE_FILE:-} ]] || uplink_state_overridden=true
uplink_delivery_state_file=${STEWARD_DOCTOR_UPLINK_DELIVERY_STATE_FILE:-}
uplink_delivery_state_overridden=false
[[ -z ${STEWARD_DOCTOR_UPLINK_DELIVERY_STATE_FILE:-} ]] || uplink_delivery_state_overridden=true
connector_receipt_file=${STEWARD_DOCTOR_CONNECTOR_RECEIPT_FILE:-/var/lib/steward-gateway/connector-receipts.ndjson}

declare -a check_ids=() check_statuses=() check_messages=()
declare -a store_names=() store_paths=() store_present=() store_sizes=() store_limits=() store_utilizations=() store_statuses=()
declare -a fs_sources=() fs_probes=() fs_total_bytes=() fs_available_bytes=() fs_free_percents=() fs_statuses=()
# Bash 3.2 treats an empty indexed-array expansion as unbound under `set -u`.
# The impossible sentinel keeps the deduplication loop portable without entering
# the report or matching a Linux filesystem source.
declare -a seen_filesystems=(__steward_node_doctor_no_filesystem__)
pass_count=0
warn_count=0
fail_count=0
capture_sequence=0
filesystem_check_sequence=0
work_dir=
timeout_bin=
mktemp_bin=
docker_bin=
systemctl_bin=
curl_bin=
stat_bin=
df_bin=
wc_bin=
rm_bin=
chmod_bin=
cat_bin=
env_bin=
preflight_bin=
stewardctl_bin=

usage() {
	cat <<'EOF'
Usage: node-doctor.sh [--json]
       node-doctor.sh [--json] --canary-bundle FILE --canary-result FILE
                      [--canary-token-file FILE] [--canary-gateway-url URL]
                      [--canary-wait-seconds SECONDS]
                      [--canary-submit-seconds SECONDS]

By default the doctor is read-only. Supplying a current, one-use signed lifecycle
task bundle opts in to real agent work: Steward submits the task, waits for its
durable terminal result, and creates FILE as a new owner-only result.

Exit status: 0 checks passed (warnings are permitted), 1 a check failed, 2 usage.
EOF
}

usage_error() {
	printf 'node-doctor: %s\n' "$1" >&2
	usage >&2
	return 2
}

parse_options() {
	local canary_option_seen=false
	while (( $# > 0 )); do
		case "$1" in
		--json)
			json_output=true
			shift
			;;
		--canary-bundle)
			(( $# >= 2 )) || { usage_error '--canary-bundle requires a file'; return 2; }
			canary_bundle=$2
			canary_option_seen=true
			shift 2
			;;
		--canary-result)
			(( $# >= 2 )) || { usage_error '--canary-result requires a file'; return 2; }
			canary_result=$2
			canary_option_seen=true
			shift 2
			;;
		--canary-token-file)
			(( $# >= 2 )) || { usage_error '--canary-token-file requires a file'; return 2; }
			canary_token_file=$2
			canary_option_seen=true
			shift 2
			;;
		--canary-gateway-url)
			(( $# >= 2 )) || { usage_error '--canary-gateway-url requires a URL'; return 2; }
			canary_gateway_url=$2
			canary_option_seen=true
			shift 2
			;;
		--canary-wait-seconds)
			(( $# >= 2 )) || { usage_error '--canary-wait-seconds requires a number'; return 2; }
			canary_wait_seconds=$2
			canary_option_seen=true
			shift 2
			;;
		--canary-submit-seconds)
			(( $# >= 2 )) || { usage_error '--canary-submit-seconds requires a number'; return 2; }
			canary_submit_seconds=$2
			canary_option_seen=true
			shift 2
			;;
		-h|--help)
			usage
			return 10
			;;
		*)
			usage_error "unknown option: $1"
			return 2
			;;
		esac
	done
	if [[ -n $canary_bundle || -n $canary_result ]]; then
		if [[ -z $canary_bundle || -z $canary_result ]]; then
			usage_error '--canary-bundle and --canary-result must be supplied together'
			return 2
		fi
		canary_requested=true
	elif [[ $canary_option_seen == true ]]; then
		usage_error 'canary modifiers require --canary-bundle and --canary-result'
		return 2
	fi
	return 0
}

valid_integer_between() {
	local value=$1 minimum=$2 maximum=$3
	[[ $value =~ ^[0-9]+$ && ${#value} -le 6 ]] && (( 10#$value >= minimum && 10#$value <= maximum ))
}

valid_absolute_ascii_path() {
	local value=$1
	[[ -n $value && $value == /* && ${#value} -le $max_path_bytes && $value != *$'\n'* && $value != *$'\r'* && $value != *$'\t'* ]] || return 1
	[[ $value != *[!\ -~]* ]]
}

valid_loopback_origin() {
	local value=$1 port
	if [[ $value =~ ^http://127\.0\.0\.1:([0-9]{1,5})$ ]]; then
		port=${BASH_REMATCH[1]}
	elif [[ $value =~ ^http://\[::1\]:([0-9]{1,5})$ ]]; then
		port=${BASH_REMATCH[1]}
	else
		return 1
	fi
	(( 10#$port >= 1 && 10#$port <= 65535 ))
}

validate_configuration() {
	local value
	for value in "$preflight_seconds" "$command_seconds" "$http_seconds" "$canary_wait_seconds" "$canary_submit_seconds"; do
		valid_integer_between "$value" 1 900 || { usage_error 'timeouts must be integer seconds from 1 through 900'; return 2; }
	done
	if ! valid_integer_between "$store_warn_percent" 1 99 ||
		! valid_integer_between "$store_fail_percent" 2 100 ||
		(( 10#$store_warn_percent >= 10#$store_fail_percent )); then
		usage_error 'durable-store warning percentage must be lower than its failure percentage'
		return 2
	fi
	if ! valid_integer_between "$fs_fail_free_percent" 0 99 ||
		! valid_integer_between "$fs_warn_free_percent" 1 100 ||
		(( 10#$fs_fail_free_percent >= 10#$fs_warn_free_percent )); then
		usage_error 'filesystem failure free percentage must be lower than its warning percentage'
		return 2
	fi
	valid_loopback_origin "$supervisor_url" || { usage_error 'supervisor URL must be an HTTP literal-loopback origin'; return 2; }
	valid_loopback_origin "$executor_url" || { usage_error 'Executor URL must be an HTTP literal-loopback origin'; return 2; }
	if [[ -n $executor_token_file ]]; then
		valid_absolute_ascii_path "$executor_token_file" || { usage_error 'Executor token path must be an absolute printable-ASCII path'; return 2; }
	fi
	valid_absolute_ascii_path "$executor_env_file" || { usage_error 'Executor environment path must be an absolute printable-ASCII path'; return 2; }
	valid_absolute_ascii_path "$gateway_control_socket" || { usage_error 'Gateway control socket must be an absolute printable-ASCII path'; return 2; }
	for value in "$fence_file" "$journal_file" "$evidence_file" "$connector_receipt_file"; do
		valid_absolute_ascii_path "$value" || { usage_error 'durable-store paths must be absolute printable-ASCII paths'; return 2; }
	done
	if [[ -n $uplink_state_file ]]; then
		valid_absolute_ascii_path "$uplink_state_file" || { usage_error 'Executor uplink state path must be an absolute printable-ASCII path'; return 2; }
	fi
	if [[ -n $uplink_delivery_state_file ]]; then
		valid_absolute_ascii_path "$uplink_delivery_state_file" || { usage_error 'Executor uplink delivery-state path must be an absolute printable-ASCII path'; return 2; }
	fi
	if [[ $canary_requested == true ]]; then
		valid_absolute_ascii_path "$canary_bundle" || { usage_error 'canary bundle must be an absolute printable-ASCII path'; return 2; }
		valid_absolute_ascii_path "$canary_result" || { usage_error 'canary result must be an absolute printable-ASCII path'; return 2; }
		valid_absolute_ascii_path "$canary_token_file" || { usage_error 'canary token must be an absolute printable-ASCII path'; return 2; }
		valid_loopback_origin "$canary_gateway_url" || { usage_error 'canary Gateway URL must be an HTTP literal-loopback origin'; return 2; }
		if [[ -e $canary_result || -L $canary_result ]]; then
			usage_error 'canary result path already exists; Steward never overwrites a result'
			return 2
		fi
	fi
	# Arithmetic contexts accept a base prefix while printf and JSON do not.
	# Store one canonical decimal representation after all range checks pass.
	preflight_seconds=$((10#$preflight_seconds))
	command_seconds=$((10#$command_seconds))
	http_seconds=$((10#$http_seconds))
	canary_wait_seconds=$((10#$canary_wait_seconds))
	canary_submit_seconds=$((10#$canary_submit_seconds))
	store_warn_percent=$((10#$store_warn_percent))
	store_fail_percent=$((10#$store_fail_percent))
	fs_warn_free_percent=$((10#$fs_warn_free_percent))
	fs_fail_free_percent=$((10#$fs_fail_free_percent))
	return 0
}

add_check() {
	local id=$1 status=$2 message=$3
	if (( ${#message} > max_message_bytes )); then
		message=${message:0:max_message_bytes}
	fi
	check_ids+=("$id")
	check_statuses+=("$status")
	check_messages+=("$message")
	case "$status" in
	pass) ((pass_count += 1)) ;;
	warn) ((warn_count += 1)) ;;
	fail) ((fail_count += 1)) ;;
	*) return 2 ;;
	esac
}

require_platform() {
	local okay=true
	if (( EUID != 0 )); then
		add_check platform.root fail 'run as root so service-owned credentials and state can be checked without weakening their permissions'
		okay=false
	else
		add_check platform.root pass 'running as root'
	fi
	if [[ ! -x /usr/bin/uname || $(/usr/bin/uname -s 2>/dev/null) != Linux ]]; then
		add_check platform.linux fail 'Linux is required'
		okay=false
	else
		add_check platform.linux pass 'running on Linux'
	fi
	[[ $okay == true ]]
}

resolve_tool() {
	local output_name=$1 environment_name=$2 default_path=$3 label=$4 required=$5 value override metadata owner mode mode_value
	override=${!environment_name:-}
	if [[ $doctor_sourced != true && -n $override ]]; then
		add_check "tool.$label" fail "$label command overrides are accepted only by a sourced test harness"
		printf -v "$output_name" '%s' ''
		return 1
	fi
	value=${override:-$default_path}
	if ! valid_absolute_ascii_path "$value"; then
		add_check "tool.$label" fail "$label command override is not an absolute printable-ASCII path"
		printf -v "$output_name" '%s' ''
		return 1
	fi
	if [[ ! -f $value || ! -x $value ]]; then
		if [[ $required == true ]]; then
			add_check "tool.$label" fail "$label command is unavailable at $value"
			printf -v "$output_name" '%s' ''
			return 1
		fi
		printf -v "$output_name" '%s' ''
		return 0
	fi
	if [[ $doctor_sourced != true ]]; then
		metadata=$(/usr/bin/stat -Lc '%u:%a' -- "$value" 2>/dev/null) || metadata=
		IFS=: read -r owner mode <<<"$metadata"
		if [[ $owner != 0 || ! $mode =~ ^[0-7]{3,4}$ ]]; then
			add_check "tool.$label" fail "$label command is not a trusted root-owned executable"
			printf -v "$output_name" '%s' ''
			return 1
		fi
		mode_value=$((8#$mode))
		if (( (mode_value & 8#022) != 0 )); then
			add_check "tool.$label" fail "$label command is writable by a non-root group or user"
			printf -v "$output_name" '%s' ''
			return 1
		fi
	fi
	printf -v "$output_name" '%s' "$value"
	return 0
}

configure_tools() {
	local okay=true stewardctl_required=false
	[[ $canary_requested == false ]] || stewardctl_required=true
	resolve_tool timeout_bin STEWARD_DOCTOR_TIMEOUT_BIN /usr/bin/timeout timeout true || okay=false
	resolve_tool mktemp_bin STEWARD_DOCTOR_MKTEMP_BIN /usr/bin/mktemp mktemp true || okay=false
	resolve_tool docker_bin STEWARD_DOCTOR_DOCKER_BIN /usr/bin/docker docker true || okay=false
	resolve_tool systemctl_bin STEWARD_DOCTOR_SYSTEMCTL_BIN /usr/bin/systemctl systemctl true || okay=false
	resolve_tool curl_bin STEWARD_DOCTOR_CURL_BIN /usr/bin/curl curl true || okay=false
	resolve_tool stat_bin STEWARD_DOCTOR_STAT_BIN /usr/bin/stat stat true || okay=false
	resolve_tool df_bin STEWARD_DOCTOR_DF_BIN /usr/bin/df df true || okay=false
	resolve_tool wc_bin STEWARD_DOCTOR_WC_BIN /usr/bin/wc wc true || okay=false
	resolve_tool rm_bin STEWARD_DOCTOR_RM_BIN /bin/rm rm true || okay=false
	resolve_tool chmod_bin STEWARD_DOCTOR_CHMOD_BIN /bin/chmod chmod true || okay=false
	resolve_tool cat_bin STEWARD_DOCTOR_CAT_BIN /bin/cat cat true || okay=false
	resolve_tool env_bin STEWARD_DOCTOR_ENV_BIN /usr/bin/env env true || okay=false
	resolve_tool preflight_bin STEWARD_NODE_PREFLIGHT /usr/local/libexec/steward/node-preflight node-preflight true || okay=false
	resolve_tool stewardctl_bin STEWARD_CTL_BIN /usr/local/bin/stewardctl stewardctl "$stewardctl_required" || okay=false
	[[ $okay == true ]]
}

create_work_dir() {
	work_dir=$($mktemp_bin -d /tmp/steward-node-doctor.XXXXXXXX 2>/dev/null) || return 1
	[[ $work_dir == /tmp/steward-node-doctor.* && -d $work_dir && ! -L $work_dir && -O $work_dir ]] || return 1
	"$chmod_bin" 0700 "$work_dir"
}

cleanup() {
	if [[ -n ${work_dir:-} && $work_dir == /tmp/steward-node-doctor.* && -d $work_dir && ! -L $work_dir ]]; then
		"${rm_bin:-/bin/rm}" -rf -- "$work_dir"
	fi
}

exit_on_signal() {
	local status=$1
	trap - EXIT HUP INT TERM
	cleanup
	exit "$status"
}

configure_docker_target() {
	local line key value docker_seen=false token_seen=false operator_token_seen=false observer_token_seen=false uplink_seen=false uplink_delivery_seen=false docker_config_dir
	local environment before after owner mode size device inode mtime ctime mode_value
	if [[ ! -f $executor_env_file || -L $executor_env_file ]]; then
		add_check docker.target fail 'Executor environment is not a regular, non-symlink file'
		return 1
	fi
	capture_bounded before 256 "$command_seconds" "$stat_bin" -Lc '%u:%a:%s:%d:%i:%Y:%Z' -- "$executor_env_file" || before=
	IFS=: read -r owner mode size device inode mtime ctime <<<"$before"
	if [[ $owner != 0 || ! $mode =~ ^[0-7]{3,4}$ || ! $size =~ ^[0-9]+$ || ! $device =~ ^[0-9]+$ || ! $inode =~ ^[0-9]+$ || ! $mtime =~ ^-?[0-9]+$ || ! $ctime =~ ^-?[0-9]+$ ]]; then
		add_check docker.target fail 'Executor environment metadata is invalid or not root-owned'
		return 1
	fi
	mode_value=$((8#$mode))
	if (( (mode_value & 8#022) != 0 || 10#$size > 16384 )); then
		add_check docker.target fail 'Executor environment is writable by a non-root principal or exceeds 16384 bytes'
		return 1
	fi
	if ! capture_bounded environment 16384 "$command_seconds" "$cat_bin" -- "$executor_env_file"; then
		add_check docker.target fail 'Executor environment could not be read within its byte limit'
		return 1
	fi
	capture_bounded after 256 "$command_seconds" "$stat_bin" -Lc '%u:%a:%s:%d:%i:%Y:%Z' -- "$executor_env_file" || after=
	if [[ $before != "$after" ]]; then
		add_check docker.target fail 'Executor environment changed while it was being read'
		return 1
	fi
	while IFS= read -r line || [[ -n $line ]]; do
		[[ -z $line || $line == \#* ]] && continue
		if (( ${#line} > 1024 )) || [[ ! $line =~ ^([A-Z_][A-Z0-9_]*)=(.*)$ ]]; then
			add_check docker.target fail 'Executor environment contains an invalid line'
			return 1
		fi
		key=${BASH_REMATCH[1]}
		value=${BASH_REMATCH[2]}
		case $key in
		EXECUTOR_DOCKER_SOCKET)
			if [[ $docker_seen == true || $value == *[[:space:]]* ]] || ! valid_absolute_ascii_path "$value"; then
				add_check docker.target fail 'Executor Docker socket is duplicate or invalid'
				return 1
			fi
			executor_docker_socket=$value
			docker_seen=true
			;;
		EXECUTOR_TOKEN_FILE)
			if [[ $token_seen == true || $value == *[[:space:]]* ]] || ! valid_absolute_ascii_path "$value"; then
				add_check docker.target fail 'Executor token path is duplicate or invalid'
				return 1
			fi
			[[ $executor_token_overridden == true ]] || executor_token_file=$value
			token_seen=true
			;;
		EXECUTOR_OPERATOR_TOKEN_FILE)
			if [[ $operator_token_seen == true || $value == *[[:space:]]* ]] || { [[ -n $value ]] && ! valid_absolute_ascii_path "$value"; }; then
				add_check docker.target fail 'Executor operator token path is duplicate or invalid'
				return 1
			fi
			executor_operator_token_file=$value
			operator_token_seen=true
			;;
		EXECUTOR_OBSERVER_TOKEN_FILE)
			if [[ $observer_token_seen == true || $value == *[[:space:]]* ]] || { [[ -n $value ]] && ! valid_absolute_ascii_path "$value"; }; then
				add_check docker.target fail 'Executor observer token path is duplicate or invalid'
				return 1
			fi
			executor_observer_token_file=$value
			observer_token_seen=true
			;;
		EXECUTOR_UPLINK_STATE_FILE)
			if [[ $uplink_seen == true || $value == *[[:space:]]* ]] || { [[ -n $value ]] && ! valid_absolute_ascii_path "$value"; }; then
				add_check docker.target fail 'Executor uplink state path is duplicate or invalid'
				return 1
			fi
			[[ $uplink_state_overridden == true ]] || uplink_state_file=$value
			uplink_seen=true
			;;
		EXECUTOR_UPLINK_DELIVERY_STATE_FILE)
			if [[ $uplink_delivery_seen == true || $value == *[[:space:]]* ]] || { [[ -n $value ]] && ! valid_absolute_ascii_path "$value"; }; then
				add_check docker.target fail 'Executor uplink delivery-state path is duplicate or invalid'
				return 1
			fi
			[[ $uplink_delivery_state_overridden == true ]] || uplink_delivery_state_file=$value
			uplink_delivery_seen=true
			;;
		esac
	done <<<"$environment"
	if [[ $docker_seen != true ]]; then
		add_check docker.target fail 'Executor Docker socket is missing from its environment'
		return 1
	fi
	if [[ $token_seen != true && $executor_token_overridden != true ]]; then
		add_check docker.target fail 'Executor token path is missing from its environment'
		return 1
	fi
	docker_config_dir=$work_dir/docker-config
	if ! /bin/mkdir -m 0700 -- "$docker_config_dir"; then
		add_check docker.target fail 'could not create a private Docker client configuration directory'
		return 1
	fi
	DOCKER_HOST=unix://$executor_docker_socket
	DOCKER_CONFIG=$docker_config_dir
	STEWARD_EXECUTOR_ENV_FILE=$executor_env_file
	export DOCKER_HOST DOCKER_CONFIG STEWARD_EXECUTOR_ENV_FILE
	add_check docker.target pass "Docker checks are pinned to the Executor socket at $executor_docker_socket"
	return 0
}

run_quiet() {
	local seconds=$1
	shift
	"$timeout_bin" --signal=TERM --kill-after=2s "${seconds}s" "$@" >/dev/null 2>&1
}

capture_bounded() {
	local output_name=$1 maximum=$2 seconds=$3 output_file data command_status byte_count file_blocks
	shift 3
	((capture_sequence += 1))
	output_file=$work_dir/capture.$capture_sequence
	# Checking the byte count only after a command exits still lets a faulty local
	# service fill the filesystem. RLIMIT_FSIZE bounds the capture while it is
	# being written; Bash specifies -f in 1024-byte blocks on Linux. The exact
	# byte ceiling is enforced again below before any output enters memory.
	file_blocks=$(((maximum + 1023) / 1024))
	# Bash reports a child killed by RLIMIT_FSIZE from the waiting parent shell,
	# outside the child's stderr redirection. Keep that expected diagnostic out
	# of the machine-readable report; the non-zero status below still makes the
	# affected check fail.
	{
		(
			ulimit -f "$file_blocks" || exit 125
			exec "$timeout_bin" --signal=TERM --kill-after=2s "${seconds}s" "$@"
		) >"$output_file" 2>/dev/null
	} 2>/dev/null
	command_status=$?
	if (( command_status != 0 )); then
		"$rm_bin" -f -- "$output_file"
		printf -v "$output_name" '%s' ''
		return "$command_status"
	fi
	byte_count=$($wc_bin -c <"$output_file" 2>/dev/null) || byte_count=
	byte_count=${byte_count//[[:space:]]/}
	if [[ ! $byte_count =~ ^[0-9]+$ ]] || (( 10#$byte_count > maximum )); then
		"$rm_bin" -f -- "$output_file"
		printf -v "$output_name" '%s' ''
		return 125
	fi
	data=$(<"$output_file")
	"$rm_bin" -f -- "$output_file"
	printf -v "$output_name" '%s' "$data"
	return 0
}

check_preflight() {
	local result=1
	run_quiet "$preflight_seconds" "$env_bin" -i \
		PATH="$PATH" LC_ALL=C DOCKER_HOST="$DOCKER_HOST" DOCKER_CONFIG="$DOCKER_CONFIG" \
		STEWARD_EXECUTOR_ENV_FILE="$executor_env_file" "$preflight_bin" && result=0
	if (( result == 0 )); then
		add_check preflight pass 'installed binaries, identities, trust material, configuration, and unit definitions passed node-preflight'
	else
		add_check preflight fail 'node-preflight failed or timed out; run it directly for its bounded diagnostic'
	fi
}

check_docker() {
	local version runtimes major
	if run_quiet "$command_seconds" "$docker_bin" --config "$DOCKER_CONFIG" --host "$DOCKER_HOST" info; then
		add_check docker.reachable pass 'Docker Engine is reachable'
	else
		add_check docker.reachable fail 'Docker Engine is not reachable'
	fi
	if capture_bounded version 128 "$command_seconds" "$docker_bin" --config "$DOCKER_CONFIG" --host "$DOCKER_HOST" version --format '{{.Server.Version}}' &&
		[[ $version =~ ^([0-9]+)\.([0-9]+)(\.[0-9]+)?([+-][A-Za-z0-9._-]+)?$ ]]; then
		major=${BASH_REMATCH[1]}
		if (( 10#$major >= 28 )); then
			add_check docker.version pass "Docker server $version satisfies the version 28 minimum"
		else
			add_check docker.version fail "Docker server $version is older than the required version 28"
		fi
	else
		add_check docker.version fail 'Docker server returned no bounded, valid semantic version'
	fi
	# Docker 29 includes a large OCI feature document under each runtime. Keep
	# the response bounded, but allow the registered runsc key to survive that
	# legitimate expansion (17 KiB on the qualified Docker 29 host).
	if capture_bounded runtimes 65536 "$command_seconds" "$docker_bin" --config "$DOCKER_CONFIG" --host "$DOCKER_HOST" info --format '{{json .Runtimes}}' &&
		[[ $runtimes =~ \"runsc\"[[:space:]]*: ]]; then
		add_check docker.runsc pass 'Docker runtime runsc is registered'
	else
		add_check docker.runsc fail 'Docker runtime runsc is not registered or could not be inspected'
	fi
}

check_units() {
	local unit active_status failed_status
	for unit in steward.service steward-executor.service steward-gateway.service; do
		active_status=0
		failed_status=0
		run_quiet "$command_seconds" "$systemctl_bin" is-active --quiet "$unit" || active_status=$?
		run_quiet "$command_seconds" "$systemctl_bin" is-failed --quiet "$unit" || failed_status=$?
		if (( active_status == 0 && (failed_status == 1 || failed_status == 3) )); then
			add_check "systemd.${unit%.service}" pass "$unit is active and not failed"
		else
			add_check "systemd.${unit%.service}" fail "$unit is not proven active and non-failed"
		fi
	done
}

run_curl_200() {
	local http_code
	capture_bounded http_code 16 "$((http_seconds + 2))" \
		"$curl_bin" --disable --silent --show-error --fail --noproxy '*' --proto '=http' \
		--connect-timeout "$http_seconds" --max-time "$http_seconds" --output /dev/null \
		--write-out '%{http_code}' "$@" && [[ $http_code == 200 ]]
}

check_health() {
	if run_curl_200 "$supervisor_url/v1/healthz"; then
		add_check health.supervisor pass 'Supervisor unauthenticated health endpoint returned success'
	else
		add_check health.supervisor fail 'Supervisor unauthenticated health endpoint did not return success'
	fi
	if run_curl_200 "$supervisor_url/v1/readiness"; then
		add_check readiness.supervisor pass 'Supervisor readiness returned success'
	else
		add_check readiness.supervisor fail 'Supervisor readiness returned non-ready or was unreachable'
	fi
	if run_curl_200 "$executor_url/v1/healthz"; then
		add_check health.executor pass 'Executor unauthenticated health endpoint returned success'
	else
		add_check health.executor fail 'Executor unauthenticated health endpoint did not return success'
	fi
}

create_bearer_header() {
	local token_path=$1 header_path=$2 before after owner group mode size device inode mtime ctime token remainder mode_value
	[[ -f $token_path && ! -L $token_path ]] || return 1
	capture_bounded before 256 "$command_seconds" "$stat_bin" -Lc '%u:%g:%a:%s:%d:%i:%Y:%Z' -- "$token_path" || return 1
	IFS=: read -r owner group mode size device inode mtime ctime <<<"$before"
	[[ $owner =~ ^[0-9]+$ && $group =~ ^[0-9]+$ && $mode =~ ^[0-7]{3,4}$ && $size =~ ^[0-9]+$ && $device =~ ^[0-9]+$ && $inode =~ ^[0-9]+$ && $mtime =~ ^-?[0-9]+$ && $ctime =~ ^-?[0-9]+$ ]] || return 1
	mode_value=$((8#$mode))
	(( (mode_value & 8#077) == 0 && 10#$size >= 1 && 10#$size <= 4096 )) || return 1
	token=
	remainder=
	exec 9<"$token_path" || return 1
	IFS= read -r -u 9 -n 4097 token || :
	if (( ${#token} > 4096 )); then
		exec 9<&-
		unset token
		return 1
	fi
	if IFS= read -r -u 9 -n 1 remainder || [[ -n $remainder ]]; then
		exec 9<&-
		unset token
		return 1
	fi
	exec 9<&-
	capture_bounded after 256 "$command_seconds" "$stat_bin" -Lc '%u:%g:%a:%s:%d:%i:%Y:%Z' -- "$token_path" || { unset token; return 1; }
	[[ $before == "$after" && $token =~ ^[\!-~]+$ && ${#token} -le 4096 ]] || { unset token; return 1; }
	printf 'Authorization: Bearer %s\n' "$token" >"$header_path" || { unset token; return 1; }
	unset token
	"$chmod_bin" 0600 "$header_path" || return 1
	return 0
}

check_executor_readiness() {
	local header=$work_dir/executor-auth.header
	if ! create_bearer_header "$executor_token_file" "$header"; then
		add_check readiness.executor_token fail 'Executor token is not a stable, non-empty, owner-only regular file'
		add_check readiness.executor fail 'authenticated Executor readiness was not attempted without a trusted token'
		return
	fi
	add_check readiness.executor_token pass 'Executor readiness token is owner-only and bounded'
	if run_curl_200 --header "@$header" "$executor_url/v1/readiness"; then
		add_check readiness.executor pass 'authenticated Executor readiness returned success'
	else
		add_check readiness.executor fail 'authenticated Executor readiness returned non-ready or was unreachable'
	fi
	"$rm_bin" -f -- "$header"
}

check_scoped_executor_tokens() {
	local role path header
	for role in operator observer; do
		if [[ $role == operator ]]; then
			path=$executor_operator_token_file
		else
			path=$executor_observer_token_file
		fi
		[[ -n $path ]] || continue
		header="$work_dir/executor-$role-auth.header"
		if create_bearer_header "$path" "$header"; then
			add_check "identity.executor_${role}_token" pass "Executor $role token is owner-only and bounded"
		else
			add_check "identity.executor_${role}_token" fail "Executor $role token is not a stable, non-empty, owner-only regular file"
		fi
		"$rm_bin" -f -- "$header"
	done
}

check_gateway_health() {
	if run_curl_200 --unix-socket "$gateway_control_socket" http://localhost/v1/healthz; then
		add_check health.gateway pass 'Gateway Unix control health endpoint returned success'
	else
		add_check health.gateway fail 'Gateway Unix control health endpoint did not return success'
	fi
}

utilization_text() {
	local used=$1 limit=$2 hundredths whole fraction multiples remainder
	multiples=$((used / limit))
	remainder=$((used % limit))
	hundredths=$((multiples * 10000 + remainder * 10000 / limit))
	whole=$((hundredths / 100))
	fraction=$((hundredths % 100))
	printf '%d.%02d' "$whole" "$fraction"
}

inspect_store() {
	local name=$1 path=$2 limit=$3 present=false size=0 utilization=0.00 status=pass message threshold_percent
	if [[ -e $path || -L $path ]]; then
		present=true
		if [[ -L $path || ! -f $path ]]; then
			status=fail
			message="$name is not a regular, non-symlink file at $path"
		elif ! capture_bounded size 64 "$command_seconds" "$stat_bin" -Lc '%s' -- "$path" ||
			! [[ $size =~ ^[0-9]+$ ]] || (( ${#size} > 15 || 10#$size > 9000000000000000 )); then
			status=fail
			size=0
			message="$name size could not be read safely at $path"
		else
			utilization=$(utilization_text "$size" "$limit")
			threshold_percent=$(((size * 100 + limit - 1) / limit))
			if (( size > limit || threshold_percent >= 10#$store_fail_percent )); then
				status=fail
			elif (( threshold_percent >= 10#$store_warn_percent )); then
				status=warn
			fi
			message="$name uses $size of $limit bytes ($utilization%) at $path"
		fi
	else
		message="$name is not present; its fixed capacity is $limit bytes at $path"
	fi
	store_names+=("$name")
	store_paths+=("$path")
	store_present+=("$present")
	store_sizes+=("$size")
	store_limits+=("$limit")
	store_utilizations+=("$utilization")
	store_statuses+=("$status")
	add_check "store.$name" "$status" "$message"
}

nearest_existing_path() {
	local path=$1
	while [[ ! -e $path && ! -L $path && $path != / ]]; do
		path=${path%/*}
		[[ -n $path ]] || path=/
	done
	printf '%s' "$path"
}

inspect_filesystem_for() {
	local store_path=$1 probe output line source blocks used available capacity _mount used_percent free_percent status total available_bytes existing check_id
	check_id=filesystem.$filesystem_check_sequence
	((filesystem_check_sequence += 1))
	probe=$(nearest_existing_path "$store_path")
	if ! capture_bounded output 8192 "$command_seconds" "$df_bin" -Pk -- "$probe"; then
		add_check "$check_id" fail "filesystem capacity could not be read for $probe"
		return
	fi
	line=
	while IFS= read -r line_candidate; do
		[[ -z $line_candidate ]] || line=$line_candidate
	done <<<"$output"
	read -r source blocks used available capacity _mount <<<"$line"
	if [[ -z $source || ${#source} -gt 256 || $source == *[!\ -~]* || ! $blocks =~ ^[0-9]+$ || ! $used =~ ^[0-9]+$ || ! $available =~ ^[0-9]+$ || ! $capacity =~ ^[0-9]+%$ || ${#blocks} -gt 15 || ${#used} -gt 15 || ${#available} -gt 15 ]]; then
		add_check "$check_id" fail "filesystem returned an invalid bounded capacity record for $probe"
		return
	fi
	if (( 10#$blocks <= 0 || 10#$blocks > 9000000000000000 || 10#$used > 10#$blocks || 10#$available > 10#$blocks )); then
		add_check "$check_id" fail "filesystem returned an impossible capacity record for $probe"
		return
	fi
	for existing in "${seen_filesystems[@]}"; do
		[[ $existing != "$source" ]] || return
	done
	seen_filesystems+=("$source")
	used_percent=${capacity%\%}
	if ! valid_integer_between "$used_percent" 0 100; then
		add_check "$check_id" fail "filesystem returned an invalid utilization percentage for $probe"
		return
	fi
	free_percent=$((10#$available * 100 / 10#$blocks))
	total=$((10#$blocks * 1024))
	available_bytes=$((10#$available * 1024))
	status=pass
	if (( free_percent <= 10#$fs_fail_free_percent )); then
		status=fail
	elif (( free_percent <= 10#$fs_warn_free_percent )); then
		status=warn
	fi
	fs_sources+=("$source")
	fs_probes+=("$probe")
	fs_total_bytes+=("$total")
	fs_available_bytes+=("$available_bytes")
	fs_free_percents+=("$free_percent")
	fs_statuses+=("$status")
	add_check "$check_id" "$status" "filesystem $source has $available_bytes of $total bytes available ($free_percent% free) for $probe"
}

check_capacity() {
	inspect_store admission_fences "$fence_file" $((4 << 20))
	inspect_store operation_journal "$journal_file" $((16 << 20))
	inspect_store executor_evidence "$evidence_file" $((64 << 20))
	if [[ -n $uplink_state_file ]]; then
		inspect_store executor_uplink_state "$uplink_state_file" $((1 << 20))
	fi
	if [[ -n $uplink_delivery_state_file ]]; then
		inspect_store executor_uplink_delivery_state "$uplink_delivery_state_file" $((8 << 20))
	fi
	inspect_store connector_receipts "$connector_receipt_file" $((64 << 20))
	inspect_filesystem_for "$fence_file"
	inspect_filesystem_for "$journal_file"
	inspect_filesystem_for "$evidence_file"
	if [[ -n $uplink_state_file ]]; then
		inspect_filesystem_for "$uplink_state_file"
	fi
	if [[ -n $uplink_delivery_state_file ]]; then
		inspect_filesystem_for "$uplink_delivery_state_file"
	fi
	inspect_filesystem_for "$connector_receipt_file"
}

validate_canary_result() {
	local metadata owner mode size mode_value
	[[ -f $canary_result && ! -L $canary_result && -O $canary_result ]] || return 1
	capture_bounded metadata 128 "$command_seconds" "$stat_bin" -Lc '%u:%a:%s' -- "$canary_result" || return 1
	IFS=: read -r owner mode size <<<"$metadata"
	[[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ && $size =~ ^[0-9]+$ && ${#size} -le 15 ]] || return 1
	mode_value=$((8#$mode))
	(( (mode_value & 8#077) == 0 && 10#$size >= 1 && 10#$size <= (1 << 20) ))
}

validate_canary_parent() {
	local path metadata owner mode mode_value
	[[ $doctor_sourced != true ]] || return 0
	path=${canary_result%/*}
	[[ -n $path ]] || path=/
	while :; do
		[[ -d $path && ! -L $path ]] || return 1
		capture_bounded metadata 64 "$command_seconds" "$stat_bin" -Lc '%u:%a' -- "$path" || return 1
		IFS=: read -r owner mode <<<"$metadata"
		[[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] || return 1
		mode_value=$((8#$mode))
		(( (mode_value & 8#022) == 0 )) || return 1
		[[ $path != / ]] || break
		path=${path%/*}
		[[ -n $path ]] || path=/
	done
	return 0
}

run_canary() {
	local submit_status=0 wait_status=0 outer_wait
	[[ $canary_requested == true ]] || return
	canary_status=fail
	if ! validate_canary_parent; then
		add_check canary.result_path fail 'canary result parent and its ancestors must be existing, root-owned, non-symlink directories that are not group- or world-writable'
		return
	fi
	add_check canary.result_path pass 'canary result parent is protected from non-root replacement'
	if run_quiet "$canary_submit_seconds" "$stewardctl_bin" task submit \
		-bundle "$canary_bundle" -gateway-url "$canary_gateway_url" -token-file "$canary_token_file"; then
		add_check canary.submit pass 'signed canary task submission returned a durable dispatch identity'
	else
		submit_status=$?
		add_check canary.submit warn 'canary submission did not return success; task wait will resolve any post-dispatch timeout without issuing new authority'
	fi
	outer_wait=$((10#$canary_wait_seconds + 10))
	if run_quiet "$outer_wait" "$stewardctl_bin" task wait \
		-bundle "$canary_bundle" -gateway-url "$canary_gateway_url" -token-file "$canary_token_file" \
		-result-out "$canary_result" -wait-timeout "${canary_wait_seconds}s"; then
		wait_status=0
	else
		wait_status=$?
	fi
	if (( wait_status == 0 )) && validate_canary_result; then
		canary_status=pass
		add_check canary.work pass 'agent reported completed work and Steward wrote one non-empty owner-only verified result'
	else
		add_check canary.work fail 'canary produced no verified result before its deadline; the exact task may still run, so retry wait with the same bundle and do not mint replacement authority until it resolves'
	fi
	# Keep shellcheck and reviewers honest: a failed submit is intentionally only a
	# warning when the subsequent durable wait proves the exact task completed.
	: "$submit_status"
}

json_escape() {
	local value=$1 output='' character code index
	for ((index = 0; index < ${#value}; index++)); do
		character=${value:index:1}
		# The second branch is a literal backslash pattern and a two-backslash
		# JSON escape, not a single-quote escape.
		# shellcheck disable=SC1003
		case "$character" in
		'"') output+='\"' ;;
		'\') output+='\\' ;;
		*)
			printf -v code '%d' "'$character"
			if (( code < 32 || code == 127 )); then
				printf -v character '\\u%04x' "$code"
			fi
			output+=$character
			;;
		esac
	done
	JSON_ESCAPED=$output
}

json_string() {
	json_escape "$1"
	JSON_BUFFER+='"'
	JSON_BUFFER+=$JSON_ESCAPED
	JSON_BUFFER+='"'
}

overall_status() {
	if (( fail_count > 0 )); then
		printf fail
	elif (( warn_count > 0 )); then
		printf warn
	else
		printf pass
	fi
}

emit_json() {
	local overall index separator='' present
	overall=$(overall_status)
	JSON_BUFFER='{"schema":"steward.node-doctor.v1","overall":"'
	JSON_BUFFER+=$overall
	JSON_BUFFER+='","thresholds":{"durable_store_warn_percent":'
	JSON_BUFFER+="$store_warn_percent"
	JSON_BUFFER+=',"durable_store_fail_percent":'
	JSON_BUFFER+="$store_fail_percent"
	JSON_BUFFER+=',"filesystem_warn_free_percent":'
	JSON_BUFFER+="$fs_warn_free_percent"
	JSON_BUFFER+=',"filesystem_fail_free_percent":'
	JSON_BUFFER+="$fs_fail_free_percent"
	JSON_BUFFER+='},"checks":['
	for index in "${!check_ids[@]}"; do
		JSON_BUFFER+=$separator
		JSON_BUFFER+='{"id":'
		json_string "${check_ids[$index]}"
		JSON_BUFFER+=',"status":'
		json_string "${check_statuses[$index]}"
		JSON_BUFFER+=',"message":'
		json_string "${check_messages[$index]}"
		JSON_BUFFER+='}'
		separator=,
	done
	JSON_BUFFER+='],"durable_stores":['
	separator=
	for index in "${!store_names[@]}"; do
		JSON_BUFFER+=$separator
		JSON_BUFFER+='{"name":'
		json_string "${store_names[$index]}"
		JSON_BUFFER+=',"path":'
		json_string "${store_paths[$index]}"
		present=${store_present[$index]}
		JSON_BUFFER+=',"present":'
		JSON_BUFFER+=$present
		JSON_BUFFER+=',"size_bytes":'
		JSON_BUFFER+=${store_sizes[$index]}
		JSON_BUFFER+=',"limit_bytes":'
		JSON_BUFFER+=${store_limits[$index]}
		JSON_BUFFER+=',"utilization_percent":'
		JSON_BUFFER+=${store_utilizations[$index]}
		JSON_BUFFER+=',"status":'
		json_string "${store_statuses[$index]}"
		JSON_BUFFER+='}'
		separator=,
	done
	JSON_BUFFER+='],"filesystems":['
	separator=
	for index in "${!fs_sources[@]}"; do
		JSON_BUFFER+=$separator
		JSON_BUFFER+='{"source":'
		json_string "${fs_sources[$index]}"
		JSON_BUFFER+=',"probe":'
		json_string "${fs_probes[$index]}"
		JSON_BUFFER+=',"total_bytes":'
		JSON_BUFFER+=${fs_total_bytes[$index]}
		JSON_BUFFER+=',"available_bytes":'
		JSON_BUFFER+=${fs_available_bytes[$index]}
		JSON_BUFFER+=',"free_percent":'
		JSON_BUFFER+=${fs_free_percents[$index]}
		JSON_BUFFER+=',"status":'
		json_string "${fs_statuses[$index]}"
		JSON_BUFFER+='}'
		separator=,
	done
	JSON_BUFFER+='],"canary":{"requested":'
	JSON_BUFFER+=$canary_requested
	JSON_BUFFER+=',"status":'
	json_string "$canary_status"
	JSON_BUFFER+='},"summary":{"passed":'
	JSON_BUFFER+="$pass_count"
	JSON_BUFFER+=',"warnings":'
	JSON_BUFFER+="$warn_count"
	JSON_BUFFER+=',"failed":'
	JSON_BUFFER+="$fail_count"
	JSON_BUFFER+='}}'
	if (( ${#JSON_BUFFER} > max_json_bytes )); then
		printf '{"schema":"%s","overall":"fail","error":"bounded report exceeded %d bytes"}\n' "$doctor_schema" "$max_json_bytes"
		return 1
	fi
	printf '%s\n' "$JSON_BUFFER"
}

emit_human() {
	local index label overall
	printf 'Steward node doctor\n'
	printf 'Thresholds: durable stores warn at %d%% and fail at %d%%; filesystems warn at %d%% free and fail at %d%% free\n' \
		"$store_warn_percent" "$store_fail_percent" "$fs_warn_free_percent" "$fs_fail_free_percent"
	for index in "${!check_ids[@]}"; do
		case ${check_statuses[$index]} in
		pass) label=PASS ;;
		warn) label=WARN ;;
		fail) label=FAIL ;;
		esac
		printf '[%s] %s: %s\n' "$label" "${check_ids[$index]}" "${check_messages[$index]}"
	done
	overall=$(overall_status)
	case $overall in
	pass) overall=PASS ;;
	warn) overall=WARN ;;
	fail) overall=FAIL ;;
	esac
	printf 'Overall: %s (%d passed, %d warnings, %d failed)\n' "$overall" "$pass_count" "$warn_count" "$fail_count"
}

emit_report() {
	if [[ $json_output == true ]]; then
		emit_json
	else
		emit_human
	fi
}

main() {
	local parse_status=0 emit_status=0
	parse_options "$@" || parse_status=$?
	if (( parse_status == 10 )); then
		return 0
	elif (( parse_status != 0 )); then
		return "$parse_status"
	fi
	validate_configuration || return $?
	if ! require_platform; then
		emit_report
		return 1
	fi
	if ! configure_tools; then
		emit_report
		return 1
	fi
	if ! create_work_dir; then
		add_check tool.mktemp fail 'could not create a private bounded-work directory under /tmp'
		emit_report
		return 1
	fi
	trap cleanup EXIT
	trap 'exit_on_signal 129' HUP
	trap 'exit_on_signal 130' INT
	trap 'exit_on_signal 143' TERM

	if configure_docker_target; then
		check_preflight
		check_docker
	else
		add_check preflight fail 'node-preflight was not run without a trusted local Docker target'
		add_check docker.reachable fail 'Docker Engine was not inspected without the Executor socket'
		add_check docker.version fail 'Docker version was not inspected without the Executor socket'
		add_check docker.runsc fail 'Docker runtimes were not inspected without the Executor socket'
	fi
	check_units
	check_health
	check_executor_readiness
	check_scoped_executor_tokens
	check_gateway_health
	check_capacity
	run_canary

	emit_report || emit_status=$?
	if (( fail_count > 0 || emit_status != 0 )); then
		return 1
	fi
	return 0
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
	main "$@"
	exit $?
fi
