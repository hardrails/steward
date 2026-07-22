#!/bin/bash -p
# Verify a deployed Steward Control without reading or printing credentials.
set -uo pipefail
set +x
if ! shopt -qo privileged; then
	echo "control-doctor: invoke this root-facing diagnostic with /bin/bash -p" >&2
	exit 2
fi

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C LANG=C
unset CDPATH ENV BASH_ENV CURL_CA_BUNDLE GLOBIGNORE POSIXLY_CORRECT SSL_CERT_DIR \
	SSL_CERT_FILE TAR_OPTIONS GZIP
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy NO_PROXY no_proxy
umask 077

json=false
probe_url=
probe_ca=
while [[ $# -gt 0 ]]; do
	case "$1" in
		--json) json=true; shift ;;
		--probe-url) probe_url=${2:-}; shift 2 ;;
		--ca-file) probe_ca=${2:-}; shift 2 ;;
		-h | --help)
			echo "usage: sudo $0 [--json] [--probe-url URL] [--ca-file PEM]"
			exit 0
			;;
		*) echo "control-doctor: unknown option $1" >&2; exit 2 ;;
	esac
done
if [[ -n $probe_url ]] &&
	{ (( ${#probe_url} > 512 )) || [[ ! $probe_url =~ ^[[:print:]]+$ ]] || [[ $probe_url =~ [[:space:]] ]] ||
		[[ ! $probe_url =~ ^https?://[^/@?#]+/?$ ]]; }; then
	echo "control-doctor: --probe-url must be an HTTP(S) origin without credentials, query, or fragment" >&2
	exit 2
fi
if (( EUID != 0 )); then
	echo "control-doctor: run this root-facing diagnostic with sudo" >&2
	exit 2
fi

readonly config=/etc/steward-control/control.env
readonly state=/var/lib/steward-control
readonly binary=/usr/local/bin/steward-control
readonly unit=steward-control.service
checks=0
failures=0

pass() {
	((checks += 1))
	if [[ $json == false ]]; then printf 'ok   %s\n' "$1"; fi
}
fail() {
	((checks += 1, failures += 1))
	if [[ $json == false ]]; then printf 'FAIL %s\n' "$1"; fi
}

require_metadata() {
	local path=$1 owner=$2 mode=$3 kind=${4:-any} actual_owner actual_mode actual_links
	if [[ ! -e $path || -L $path ]]; then
		fail "$path is missing or is a symbolic link"
		return
	fi
	case "$kind" in
		regular)
			if [[ ! -f $path ]]; then fail "$path is not a regular file"; return; fi
			actual_links=$(stat -c '%h' -- "$path" 2>/dev/null) || actual_links=unknown
			if [[ $actual_links != 1 ]]; then fail "$path has $actual_links hard links; expected one"; return; fi
			;;
		directory) if [[ ! -d $path ]]; then fail "$path is not a directory"; return; fi ;;
		any) ;;
		*) fail "$path has an unknown diagnostic type requirement"; return ;;
	esac
	actual_owner=$(stat -c '%U:%G' -- "$path" 2>/dev/null) || actual_owner=unknown
	actual_mode=$(stat -c '%a' -- "$path" 2>/dev/null) || actual_mode=unknown
	if [[ $actual_owner == "$owner" && $actual_mode == "$mode" ]]; then
		pass "$path metadata is $owner $mode"
	else
		fail "$path metadata is $actual_owner $actual_mode; expected $owner $mode"
	fi
}

valid_operations_duration() {
	local value=$1 magnitude duration_unit multiplier seconds
	[[ $value =~ ^([1-9][0-9]*)(s|m|h)$ ]] || return 1
	magnitude=${BASH_REMATCH[1]}
	duration_unit=${BASH_REMATCH[2]}
	case "$duration_unit" in
		s) multiplier=1 ;;
		m) multiplier=60 ;;
		h) multiplier=3600 ;;
		*) return 1 ;;
	esac
	(( ${#magnitude} <= 8 )) || return 1
	seconds=$((10#$magnitude * multiplier))
	(( seconds > 0 && seconds <= 31536000 ))
}

valid_capacity_warning_percent() {
	local value=$1
	[[ $value =~ ^[1-9][0-9]*$ ]] && (( 10#$value >= 1 && 10#$value <= 100 ))
}

trusted_root_directory_chain() {
	local directory=$1 current metadata uid mode
	[[ -d $directory && ! -L $directory && $(readlink -e -- "$directory" 2>/dev/null) == "$directory" ]] || return 1
	current=$directory
	while :; do
		metadata=$(stat -c '%u:%a' -- "$current") || return 1
		uid=${metadata%%:*}; mode=${metadata#*:}
		[[ $uid == 0 ]] && (( (8#$mode & 022) == 0 )) || return 1
		[[ $current == / ]] && break
		current=$(dirname -- "$current")
	done
}

snapshot_probe_ca() {
	local source=$1 destination=$2 before after source_size
	[[ $source == /* && $source != / && $(readlink -m -- "$source" 2>/dev/null) == "$source" ]] || return 1
	trusted_root_directory_chain "$(dirname -- "$source")" || return 1
	[[ -f $source && ! -L $source ]] || return 1
	before=$(stat -c '%d:%i:%s:%u:%g:%a:%h:%y:%z' -- "$source") || return 1
	[[ $before =~ ^[^:]+:[^:]+:([0-9]+):0:[0-9]+:([0-7]+):1: ]] || return 1
	source_size=${BASH_REMATCH[1]}
	(( source_size > 0 && source_size <= 1048576 && (8#${BASH_REMATCH[2]} & 022) == 0 )) || return 1
	if ! (
		umask 077
		set -o noclobber
		exec >"$destination"
		ulimit -c 0
		ulimit -f 1024
		exec timeout --signal=TERM --kill-after=2 10 dd if="$source" bs=1048576 count=2 \
			iflag=nofollow,nonblock,fullblock status=none
	); then
		rm -f -- "$destination"
		return 1
	fi
	after=$(stat -c '%d:%i:%s:%u:%g:%a:%h:%y:%z' -- "$source") || return 1
	[[ $after == "$before" && $(stat -c '%u:%g:%a:%h:%s' -- "$destination") == "0:0:600:1:$source_size" ]]
}

bounded_nss_dump() {
	local database=$1 output=$2 error=$3
	if ! (
		ulimit -c 0
		ulimit -f 8192
		exec timeout --signal=TERM --kill-after=2 15 getent "$database"
	) >"$output" 2>"$error"; then
		return 1
	fi
	[[ ! -s $error && -f $output && ! -L $output && $(stat -c '%u:%g:%a:%h' -- "$output") == 0:0:600:1 ]] || return 1
	(( $(stat -c '%s' -- "$output") <= 8388608 ))
}

bounded_systemctl() {
	timeout --signal=TERM --kill-after=2 10 systemctl "$@"
}

for command in awk dd dirname getent id mktemp rm sha256sum stat systemctl runuser curl timeout readlink; do
	if command -v "$command" >/dev/null 2>&1; then pass "$command is available"; else fail "$command is unavailable"; fi
done

doctor_work=$(mktemp -d /run/steward-control-doctor.XXXXXX) || {
	echo "control-doctor: could not create private diagnostic staging" >&2
	exit 1
}
if [[ -L $doctor_work || $(stat -c '%u:%g:%a' -- "$doctor_work") != 0:0:700 ]]; then
	echo "control-doctor: private diagnostic staging has unsafe metadata" >&2
	exit 1
fi
trap 'rm -rf -- "$doctor_work"' EXIT
if [[ -n $probe_ca ]]; then
	if ! snapshot_probe_ca "$probe_ca" "$doctor_work/probe-ca.pem"; then
		echo "control-doctor: --ca-file must be a stable root-owned, one-link PEM of 1 MiB or less below a root-owned non-writable path" >&2
		exit 2
	fi
	probe_ca=$doctor_work/probe-ca.pem
fi

bounded_identity_lookup() {
	local variable=$1 label=$2 metadata size status=0
	local output=$doctor_work/identity.$label.stdout error=$doctor_work/identity.$label.stderr
	local -a lines=()
	shift 2
	printf -v "$variable" '%s' ''
	if (
		ulimit -c 0
		ulimit -f 64
		exec timeout --signal=TERM --kill-after=2 15 "$@"
	) >"$output" 2>"$error"; then
		status=0
	else
		status=$?
	fi
	metadata=$(stat -c '%u:%g:%a:%h:%s' -- "$output" 2>/dev/null) || status=1
	if [[ $status == 0 && $metadata =~ ^0:0:600:1:([0-9]+)$ ]]; then
		size=${BASH_REMATCH[1]}
		(( size > 0 && size <= 65536 )) || status=1
	else
		status=1
	fi
	if [[ $status == 0 ]]; then
		mapfile -t lines <"$output"
		(( ${#lines[@]} == 1 && ${#lines[0]} > 0 )) || status=1
	fi
	if [[ -s $error || ! -f $error || -L $error || $(stat -c '%u:%g:%a:%h' -- "$error" 2>/dev/null) != 0:0:600:1 ]]; then
		status=1
	fi
	rm -f -- "$output" "$error"
	if (( status != 0 )); then return 1; fi
	printf -v "$variable" '%s' "${lines[0]}"
}

identity_valid=false
service_record=
service_group_record=
service_shadow=
service_numeric_groups=
service_group_name=
service_named_groups=
bounded_identity_lookup service_record passwd getent passwd steward-control || true
bounded_identity_lookup service_group_record group getent group steward-control || true
bounded_identity_lookup service_shadow shadow getent shadow steward-control || true
bounded_identity_lookup service_numeric_groups numeric-groups id -G steward-control || true
bounded_identity_lookup service_group_name primary-group-name id -gn steward-control || true
bounded_identity_lookup service_named_groups named-groups id -nG steward-control || true
service_uid=
service_primary_gid=
service_home=
service_shell=
service_gid=
record_name=
group_name=
if [[ -n $service_record ]]; then
	IFS=: read -r record_name _ service_uid service_primary_gid _ service_home service_shell <<<"$service_record"
fi
if [[ -n $service_group_record ]]; then
	IFS=: read -r group_name _ service_gid _ <<<"$service_group_record"
fi
service_password=${service_shadow#*:}; service_password=${service_password%%:*}
service_shell_resolved=$(readlink -f -- "$service_shell" 2>/dev/null || true)
service_shell_allowed=false
for candidate in /usr/sbin/nologin /sbin/nologin /usr/bin/nologin /bin/nologin /usr/bin/false /bin/false; do
	if [[ -x $candidate && $(readlink -f -- "$candidate" 2>/dev/null) == "$service_shell_resolved" ]]; then
		service_shell_allowed=true
		break
	fi
done
service_password_locked=false
case "$service_password" in '!'* | '*'*) service_password_locked=true ;; esac
uid_matches=0
gid_matches=0
docker_gid_collision=0
docker_socket_collision=false
if bounded_nss_dump passwd "$doctor_work/passwd.nss" "$doctor_work/passwd.nss.stderr" &&
	bounded_nss_dump group "$doctor_work/group.nss" "$doctor_work/group.nss.stderr"; then
	uid_matches=$(awk -F: -v id="$service_uid" '$3 == id { count++ } END { print count + 0 }' "$doctor_work/passwd.nss")
	gid_matches=$(awk -F: -v id="$service_gid" '$3 == id { count++ } END { print count + 0 }' "$doctor_work/group.nss")
	docker_gid_collision=$(awk -F: -v id="$service_gid" '$1 == "docker" && $3 == id { found=1 } END { print found + 0 }' "$doctor_work/group.nss")
fi
for docker_socket in /run/docker.sock /var/run/docker.sock; do
	if [[ -n $service_gid && -S $docker_socket && $(stat -c '%g' -- "$docker_socket") == "$service_gid" ]]; then
		docker_socket_collision=true
	fi
done
if [[ -n $service_record && -n $service_group_record && -n $service_uid && -n $service_gid &&
	$service_uid != 0 && $service_gid != 0 && $service_primary_gid == "$service_gid" &&
	$service_numeric_groups == "$service_gid" && $uid_matches == 1 && $gid_matches == 1 &&
	$docker_gid_collision == 0 && $docker_socket_collision == false &&
	$record_name == steward-control && $group_name == steward-control &&
	$service_group_name == steward-control &&
	$service_named_groups == steward-control && $service_home == /nonexistent &&
	$service_shell_allowed == true && $service_password_locked == true ]]; then
	identity_valid=true
fi
if [[ $identity_valid == true ]]; then
	pass "steward-control is an isolated password-locked non-login identity"
else
	fail "steward-control service identity is missing, privileged, login-capable, or not isolated"
fi
if [[ $docker_gid_collision != 0 || $docker_socket_collision == true ]]; then
	fail "steward-control numeric group authority collides with Docker"
else
	pass "steward-control has no Docker group authority"
fi

require_metadata /etc/steward-control root:steward-control 750 directory
require_metadata "$config" root:root 600 regular
require_metadata "$state" steward-control:steward-control 700 directory

declare -A settings=()
config_valid=true
if [[ -r $config && -f $config && ! -L $config && $(stat -c '%h' -- "$config" 2>/dev/null) == 1 ]] &&
	(( $(stat -c '%s' -- "$config" 2>/dev/null) > 0 && $(stat -c '%s' -- "$config" 2>/dev/null) <= 16384 )); then
	while IFS= read -r line || [[ -n $line ]]; do
		case "$line" in
			"" | \#*) continue ;;
		esac
		if [[ ! $line =~ ^(STEWARD_CONTROL_ADDR|STEWARD_CONTROL_STATE_DIR|STEWARD_CONTROL_AUTH_KEY_FILE|STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE|STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE|STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE|STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE|STEWARD_CONTROL_CONTROLLER_KEY_ID|STEWARD_CONTROL_RECONCILE_INTERVAL|STEWARD_CONTROL_AUTHORITY_MODE|STEWARD_CONTROL_TLS_CERT_FILE|STEWARD_CONTROL_TLS_KEY_FILE|STEWARD_CONTROL_ENABLE_METRICS|STEWARD_CONTROL_NODE_STALE_AFTER|STEWARD_CONTROL_EVIDENCE_STALE_AFTER|STEWARD_CONTROL_COMMAND_OVERDUE_AFTER|STEWARD_CONTROL_CAPACITY_WARNING_PERCENT)=([^[:space:]]*)$ ]]; then
			config_valid=false
			continue
		fi
		key=${BASH_REMATCH[1]}
		if [[ ${settings[$key]+present} == present ]]; then config_valid=false; continue; fi
		settings[$key]=${BASH_REMATCH[2]}
	done <"$config"
else
	config_valid=false
fi
for key in STEWARD_CONTROL_ADDR STEWARD_CONTROL_STATE_DIR STEWARD_CONTROL_AUTH_KEY_FILE \
	STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE \
	STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE \
	STEWARD_CONTROL_CONTROLLER_KEY_ID STEWARD_CONTROL_RECONCILE_INTERVAL \
	STEWARD_CONTROL_AUTHORITY_MODE \
	STEWARD_CONTROL_TLS_CERT_FILE STEWARD_CONTROL_TLS_KEY_FILE STEWARD_CONTROL_ENABLE_METRICS \
	STEWARD_CONTROL_NODE_STALE_AFTER STEWARD_CONTROL_EVIDENCE_STALE_AFTER \
	STEWARD_CONTROL_COMMAND_OVERDUE_AFTER STEWARD_CONTROL_CAPACITY_WARNING_PERCENT; do
	[[ ${settings[$key]+present} == present ]] || config_valid=false
done
if [[ ${settings[STEWARD_CONTROL_STATE_DIR]:-} != "$state" ||
	${settings[STEWARD_CONTROL_AUTH_KEY_FILE]:-} != "$state/auth.key" ||
	${settings[STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE]:-} != "$state/witness.private.pem" ||
	${settings[STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE]:-} != "$state/witness.public.pem" ||
	${settings[STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE]:-} != "$state/controller.private.pem" ||
	${settings[STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE]:-} != "$state/controller.public.pem" ||
	${settings[STEWARD_CONTROL_CONTROLLER_KEY_ID]:-} != controller-default ||
	${settings[STEWARD_CONTROL_RECONCILE_INTERVAL]:-} != 5s ]] ||
	{ [[ ${settings[STEWARD_CONTROL_AUTHORITY_MODE]:-} != bounded-autonomous ]] &&
		[[ ${settings[STEWARD_CONTROL_AUTHORITY_MODE]:-} != strict-sovereign ]]; } ||
	{ [[ -z ${settings[STEWARD_CONTROL_TLS_CERT_FILE]:-} ]] && [[ -n ${settings[STEWARD_CONTROL_TLS_KEY_FILE]:-} ]]; } ||
	{ [[ -n ${settings[STEWARD_CONTROL_TLS_CERT_FILE]:-} ]] && [[ -z ${settings[STEWARD_CONTROL_TLS_KEY_FILE]:-} ]]; } ||
	{ [[ ${settings[STEWARD_CONTROL_ENABLE_METRICS]:-} != true ]] &&
		[[ ${settings[STEWARD_CONTROL_ENABLE_METRICS]:-} != false ]]; } ||
	! valid_operations_duration "${settings[STEWARD_CONTROL_NODE_STALE_AFTER]:-}" ||
	! valid_operations_duration "${settings[STEWARD_CONTROL_EVIDENCE_STALE_AFTER]:-}" ||
	! valid_operations_duration "${settings[STEWARD_CONTROL_COMMAND_OVERDUE_AFTER]:-}" ||
	! valid_capacity_warning_percent "${settings[STEWARD_CONTROL_CAPACITY_WARNING_PERCENT]:-}"; then
	config_valid=false
fi
if [[ $config_valid == true ]]; then pass "control.env contains only supported settings"; else fail "control.env is invalid"; fi

if [[ $config_valid == true ]]; then
	require_metadata "${settings[STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE]}" steward-control:steward-control 600 regular
	require_metadata "${settings[STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE]}" steward-control:steward-control 644 regular
	for witness_path in "${settings[STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE]}" \
		"${settings[STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE]}"; do
		if (( $(stat -c '%s' -- "$witness_path" 2>/dev/null || printf '16385') <= 0 ||
			$(stat -c '%s' -- "$witness_path" 2>/dev/null || printf '16385') > 16384 )); then
			fail "$witness_path size is outside the 16 KiB witness-key bound"
		else
			pass "$witness_path size is within the 16 KiB witness-key bound"
		fi
	done
	if [[ ${settings[STEWARD_CONTROL_AUTHORITY_MODE]} == bounded-autonomous ]]; then
		require_metadata "${settings[STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE]}" steward-control:steward-control 600 regular
		require_metadata "${settings[STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE]}" steward-control:steward-control 644 regular
		for controller_path in "${settings[STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE]}" \
			"${settings[STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE]}"; do
			if (( $(stat -c '%s' -- "$controller_path" 2>/dev/null || printf '16385') <= 0 ||
				$(stat -c '%s' -- "$controller_path" 2>/dev/null || printf '16385') > 16384 )); then
				fail "$controller_path size is outside the 16 KiB controller-key bound"
			else
				pass "$controller_path size is within the 16 KiB controller-key bound"
			fi
		done
	else
		if [[ -e ${settings[STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE]} ||
			-L ${settings[STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE]} ||
			-e ${settings[STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE]} ||
			-L ${settings[STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE]} ]]; then
			fail "strict-sovereign mode requires controller signing-key files to be absent"
		else
			pass "strict-sovereign mode has no online controller signing key"
		fi
	fi
fi

if [[ -L $binary && -x $binary && $(readlink -f -- "$binary" 2>/dev/null) == /opt/steward-control/releases/*/steward-control ]]; then
	pass "$binary selects an immutable release"
else
	fail "$binary does not select an immutable release"
fi
if [[ -L /opt/steward-control/current && $(readlink -f -- /opt/steward-control/current 2>/dev/null) == /opt/steward-control/releases/* ]]; then
	pass "current release link is valid"
else
	fail "current release link is invalid"
fi

if [[ -n ${settings[STEWARD_CONTROL_TLS_KEY_FILE]:-} ]]; then
	require_metadata "${settings[STEWARD_CONTROL_TLS_CERT_FILE]}" root:steward-control 640 regular
	require_metadata "${settings[STEWARD_CONTROL_TLS_KEY_FILE]}" steward-control:steward-control 600 regular
	for tls_path in "${settings[STEWARD_CONTROL_TLS_CERT_FILE]}" "${settings[STEWARD_CONTROL_TLS_KEY_FILE]}"; do
		if (( $(stat -c '%s' -- "$tls_path" 2>/dev/null || printf '1048577') <= 0 ||
			$(stat -c '%s' -- "$tls_path" 2>/dev/null || printf '1048577') > 1048576 )); then
			fail "$tls_path size is outside the 1 MiB TLS input bound"
		else
			pass "$tls_path size is within the 1 MiB TLS input bound"
		fi
	done
fi

if [[ $(bounded_systemctl show "$unit" -p User --value 2>/dev/null) == steward-control &&
	$(bounded_systemctl show "$unit" -p Group --value 2>/dev/null) == steward-control ]]; then
	pass "systemd runs the controller as steward-control"
else
	fail "systemd service identity is not steward-control"
fi
if [[ $(bounded_systemctl show "$unit" -p NoNewPrivileges --value 2>/dev/null) == yes &&
	-z $(bounded_systemctl show "$unit" -p SupplementaryGroups --value 2>/dev/null) ]]; then
	pass "systemd privilege boundary is active"
else
	fail "systemd privilege boundary is incomplete"
fi

if bounded_systemctl is-active --quiet "$unit"; then
	pass "steward-control is active"
	if [[ $config_valid == true ]]; then
		address=${settings[STEWARD_CONTROL_ADDR]}
		host=${address%:*}
		port=${address##*:}
		host=${host#[}; host=${host%]}
		tls_enabled=false
		[[ -z ${settings[STEWARD_CONTROL_TLS_CERT_FILE]} ]] || tls_enabled=true
		if [[ -n $probe_url ]]; then
			origin=${probe_url%/}
		elif [[ $tls_enabled == true && ( $host == 0.0.0.0 || $host == :: ) ]]; then
			if [[ $host == :: ]]; then local_host=::1; else local_host=127.0.0.1; fi
			# shellcheck disable=SC2016 # $1/$2 are intentionally expanded by the bounded child shell.
			if timeout 5 /bin/bash -p -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$local_host" "$port" 2>/dev/null; then
				pass "TLS wildcard listener accepts a local TCP connection; pass --probe-url for authenticated HTTP readiness"
			else
				fail "TLS wildcard listener does not accept a local TCP connection"
			fi
			origin=
		else
			case "$host" in 0.0.0.0) host=127.0.0.1 ;; ::) host=::1 ;; esac
			if [[ $host == *:* ]]; then url_host="[$host]"; else url_host=$host; fi
			if [[ $tls_enabled == true ]]; then scheme=https; else scheme=http; fi
			origin="${scheme}://${url_host}:${port}"
		fi
		if [[ -n $origin ]]; then
			if [[ $tls_enabled == true && $origin != https://* ]] || [[ $tls_enabled == false && $origin != http://* ]]; then
				fail "probe URL scheme does not match the configured transport"
			else
				url="${origin}/v1/readiness"
				curl_args=(-q --fail --silent --show-error --max-redirs 0 --max-time 5 --max-filesize 4096)
				if [[ $origin == https://* ]]; then curl_args+=(--proto '=https'); else curl_args+=(--proto '=http'); fi
				if [[ -n $probe_ca ]]; then curl_args+=(--cacert "$probe_ca"); fi
				response=$(curl "${curl_args[@]}" "$url" 2>/dev/null || true)
				if [[ $response == '{"status":"ready"}' ]]; then pass "readiness endpoint reports ready"; else fail "readiness endpoint did not report ready"; fi
			fi
		fi
	fi
else
	fail "steward-control is not active"
	if [[ $config_valid == true && -x $binary ]]; then
		args=(-check-config -addr "${settings[STEWARD_CONTROL_ADDR]}" -state-dir "$state" \
			-auth-key-file "$state/auth.key" \
			-witness-private-key-file "${settings[STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE]}" \
			-witness-public-key-file "${settings[STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE]}" \
			-controller-private-key-file "${settings[STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE]}" \
			-controller-public-key-file "${settings[STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE]}" \
			-controller-key-id "${settings[STEWARD_CONTROL_CONTROLLER_KEY_ID]}" \
			-reconcile-interval "${settings[STEWARD_CONTROL_RECONCILE_INTERVAL]}" \
			-authority-mode "${settings[STEWARD_CONTROL_AUTHORITY_MODE]}" \
			-enable-metrics="${settings[STEWARD_CONTROL_ENABLE_METRICS]}" \
			-node-stale-after "${settings[STEWARD_CONTROL_NODE_STALE_AFTER]}" \
			-evidence-stale-after "${settings[STEWARD_CONTROL_EVIDENCE_STALE_AFTER]}" \
			-command-overdue-after "${settings[STEWARD_CONTROL_COMMAND_OVERDUE_AFTER]}" \
			-capacity-warning-percent "${settings[STEWARD_CONTROL_CAPACITY_WARNING_PERCENT]}")
		if [[ -n ${settings[STEWARD_CONTROL_TLS_CERT_FILE]} ]]; then
			args+=(-tls-cert-file "${settings[STEWARD_CONTROL_TLS_CERT_FILE]}" -tls-key-file "${settings[STEWARD_CONTROL_TLS_KEY_FILE]}")
		fi
		if timeout --signal=TERM --kill-after=2 15 runuser -u steward-control -- \
			"$binary" "${args[@]}" >/dev/null 2>&1; then
			pass "stopped controller state and configuration are valid"
		else
			fail "stopped controller state or configuration is invalid"
		fi
	fi
fi

if (( failures == 0 )); then status=ok; exit_code=0; else status=failed; exit_code=1; fi
if [[ $json == true ]]; then
	printf '{"schema":"steward.control-doctor.v1","status":"%s","checks":%d,"failures":%d}\n' "$status" "$checks" "$failures"
else
	printf '\ncontrol-doctor: %s (%d checks, %d failures)\n' "$status" "$checks" "$failures"
fi
exit "$exit_code"
