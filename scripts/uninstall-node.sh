#!/bin/bash -p
# Remove generic-archive Steward integration without deleting state by default.
set -euo pipefail
if ! shopt -qo privileged; then
	echo "uninstall-node: execute this root helper directly or invoke it with /bin/bash -p" >&2
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
IFS=$' \t\n'
umask 077

usage() {
	cat <<'EOF'
Usage: uninstall-node.sh [--purge-config --purge-data]

Stops and removes Steward's generic-archive service integration. Versioned
binaries, configuration, credentials, audit data, and fence state are retained
by default. Node identity can be retired only by supplying both purge options;
Steward refuses a partial purge that would separate receipt keys from evidence
or configuration from anti-replay state.

For a DEB or RPM installation, use the operating system package manager instead.
EOF
}

purge_config=false
purge_data=false
while [[ $# -gt 0 ]]; do
	case "$1" in
		--purge-config) purge_config=true; shift ;;
		--purge-data) purge_data=true; shift ;;
		-h | --help) usage; exit 0 ;;
		*) echo "uninstall-node: unknown option $1" >&2; usage >&2; exit 2 ;;
	esac
done
if [[ $purge_config != "$purge_data" ]]; then
	echo "uninstall-node: --purge-config and --purge-data must be supplied together" >&2
	echo "  A partial purge would leave an incomplete node identity that cannot be reopened safely." >&2
	exit 2
fi
if [[ ${EUID} -ne 0 ]]; then
	echo "uninstall-node: run as root" >&2
	exit 2
fi

# BEGIN UNINSTALL_TRUST_BOUNDARY
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

trusted_root_executable() {
	local requested=$1 resolved metadata uid mode links
	resolved=$(readlink -e -- "$requested" 2>/dev/null) || return 1
	[[ -f $resolved && ! -L $resolved && -x $resolved ]] || return 1
	trusted_root_directory_chain "$(dirname -- "$resolved")" || return 1
	metadata=$(stat -c '%u:%a:%h' -- "$resolved") || return 1
	IFS=: read -r uid mode links <<<"$metadata"
	[[ $uid == 0 && $links == 1 ]] && (( (8#$mode & 022) == 0 )) || return 1
	printf '%s\n' "$resolved"
}

script_file=$(trusted_root_executable "${BASH_SOURCE[0]}") || {
	echo "uninstall-node: this helper must come from a trusted immutable Steward release" >&2
	exit 2
}
script_relative=${script_file#/opt/steward/releases/}
script_version=${script_relative%%/*}
case "$script_file" in
	/usr/lib/steward-node/release/scripts/uninstall-node.sh) ;;
	/opt/steward/releases/*/integration/scripts/uninstall-node.sh)
		if ! valid_release_version "$script_version" ||
			[[ $script_file != "/opt/steward/releases/$script_version/integration/scripts/uninstall-node.sh" ]]; then
			echo "uninstall-node: execute the helper from an installed immutable Steward release" >&2
			exit 2
		fi
		;;
	*)
		echo "uninstall-node: execute the helper from an installed immutable Steward release or native package payload" >&2
		exit 2
		;;
esac
script_dir=$(dirname -- "$script_file")
guard_bin=$(trusted_root_executable "$script_dir/node-removal-guard.sh") || {
	echo "uninstall-node: installed release has no trusted node-removal guard" >&2
	exit 2
}
# END UNINSTALL_TRUST_BOUNDARY

# BEGIN HOST_ROLE_LOCK_BOUNDARY
readonly host_role_lock_directory=/run/steward-host-role
readonly host_role_lock_file=$host_role_lock_directory/role.lock
prepare_host_role_lock() {
	local metadata uid mode
	[[ -d /run && ! -L /run ]] || {
		echo "uninstall-node: refusing an unsafe /run directory" >&2
		return 2
	}
	metadata=$(stat -c '%u:%a' -- /run) || return 2
	uid=${metadata%%:*}; mode=${metadata#*:}
	if [[ $uid != 0 ]] || (( (8#$mode & 022) != 0 )); then
		echo "uninstall-node: /run must be root-owned and not group- or world-writable" >&2
		return 2
	fi
	if [[ ! -e $host_role_lock_directory && ! -L $host_role_lock_directory ]]; then
		install -d -o root -g root -m 0700 -- "$host_role_lock_directory"
	fi
	if [[ ! -d $host_role_lock_directory || -L $host_role_lock_directory ||
		$(readlink -e -- "$host_role_lock_directory" 2>/dev/null) != "$host_role_lock_directory" ||
		$(stat -c '%u:%g:%a' -- "$host_role_lock_directory" 2>/dev/null) != 0:0:700 ]]; then
		echo "uninstall-node: refusing an unsafe host-role lock directory" >&2
		return 2
	fi
	if [[ ! -e $host_role_lock_file && ! -L $host_role_lock_file ]]; then
		(umask 077; set -o noclobber; : >"$host_role_lock_file") 2>/dev/null || true
	fi
	if [[ ! -f $host_role_lock_file || -L $host_role_lock_file ||
		$(stat -c '%u:%g:%a:%h' -- "$host_role_lock_file" 2>/dev/null) != 0:0:600:1 ]]; then
		echo "uninstall-node: refusing an unsafe host-role lock" >&2
		return 2
	fi
}
acquire_host_role_lock() {
	local path_metadata fd_metadata process_id=${BASHPID:-$$}
	command -v flock >/dev/null 2>&1 || {
		echo "uninstall-node: flock is required to serialize host-role removal" >&2
		return 2
	}
	prepare_host_role_lock || return
	exec 7<>"$host_role_lock_file"
	path_metadata=$(stat -c '%d:%i:%u:%g:%a:%h' -- "$host_role_lock_file") || return 2
	fd_metadata=$(stat -Lc '%d:%i:%u:%g:%a:%h' -- "/proc/$process_id/fd/7") || return 2
	if [[ $path_metadata != "$fd_metadata" || $path_metadata != *:0:0:600:1 ]]; then
		echo "uninstall-node: host-role lock changed while it was opened" >&2
		exec 7>&-
		return 2
	fi
	if ! flock -w 60 7; then
		echo "uninstall-node: another host-role operation did not finish within 60 seconds" >&2
		exec 7>&-
		return 1
	fi
}
# END HOST_ROLE_LOCK_BOUNDARY

# BEGIN NODE_LOCK_BOUNDARY
readonly node_lock_directory=/run/steward-node
readonly node_lock_file=$node_lock_directory/activation.lock
readonly node_lock_error_prefix=uninstall-node

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
		echo "$node_lock_error_prefix: flock is required to serialize node removal" >&2
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
		echo "$node_lock_error_prefix: another node lifecycle operation did not finish within $wait_seconds seconds" >&2
		exec 9>&-
		return 1
	fi
}
# END NODE_LOCK_BOUNDARY

acquire_host_role_lock
acquire_node_lock 60

node_role_claim_directory=/var/lib/steward-node-installer
node_role_claim_file=$node_role_claim_directory/claim
if [[ -e $node_role_claim_directory || -L $node_role_claim_directory ]]; then
	[[ -d $node_role_claim_directory && ! -L $node_role_claim_directory &&
		$(readlink -e -- "$node_role_claim_directory" 2>/dev/null) == "$node_role_claim_directory" &&
		$(stat -c '%u:%g:%a' -- "$node_role_claim_directory" 2>/dev/null) == 0:0:700 ]] || {
		echo "uninstall-node: refusing unsafe node-role reservation directory" >&2
		exit 2
	}
	if [[ -e $node_role_claim_file || -L $node_role_claim_file ]]; then
		[[ -f $node_role_claim_file && ! -L $node_role_claim_file &&
			$(stat -c '%u:%g:%a:%h:%s' -- "$node_role_claim_file" 2>/dev/null) == 0:0:600:1:27 &&
			$(<"$node_role_claim_file") == steward.node-role-claim.v1 ]] || {
			echo "uninstall-node: refusing unsafe node-role reservation" >&2
			exit 2
		}
	fi
fi

# BEGIN QUIESCED_REMOVAL
was_gateway=false
was_steward=false
was_executor=false
systemctl is-active --quiet steward-gateway.service && was_gateway=true
systemctl is-active --quiet steward.service && was_steward=true
systemctl is-active --quiet steward-executor.service && was_executor=true
removal_guard_complete=false
restore_services_after_failed_removal() {
	local status=$?
	trap - EXIT HUP INT TERM
	if [[ $removal_guard_complete != true ]]; then
		[[ $was_gateway == false ]] || systemctl start steward-gateway.service >/dev/null 2>&1 || true
		[[ $was_steward == false ]] || systemctl start steward.service >/dev/null 2>&1 || true
		[[ $was_executor == false ]] || systemctl start steward-executor.service >/dev/null 2>&1 || true
	fi
	exit "$status"
}
trap restore_services_after_failed_removal EXIT HUP INT TERM

[[ $was_gateway == false ]] || systemctl stop steward-gateway.service
[[ $was_steward == false ]] || systemctl stop steward.service
[[ $was_executor == false ]] || systemctl stop steward-executor.service
guard_status=0
if [[ $purge_data == true ]]; then
	"$guard_bin" --purge-data || guard_status=$?
else
	"$guard_bin" || guard_status=$?
fi
if (( guard_status != 0 )); then
	echo "uninstall-node: drain proof failed after services were stopped; restoring their previous active state" >&2
	exit "$guard_status"
fi
removal_guard_complete=true
trap - EXIT HUP INT TERM
# END QUIESCED_REMOVAL

systemctl disable steward-gateway.service steward.service steward-executor.service >/dev/null 2>&1 || true
for binary in steward steward-control stewardctl steward-mcp steward-executor steward-gateway steward-relay; do
	path="/usr/local/bin/$binary"
	target=$(readlink "$path" 2>/dev/null || true)
	case "$target" in
		/opt/steward/current/* | /opt/steward/releases/*) rm -f "$path" ;;
	esac
done
rm -f /usr/local/lib/systemd/system/steward.service \
	/usr/local/lib/systemd/system/steward-executor.service \
	/usr/local/lib/systemd/system/steward-gateway.service
rm -rf /usr/local/libexec/steward
systemctl daemon-reload >/dev/null 2>&1 || true

if [[ $purge_config == true ]]; then rm -rf /etc/steward; fi
if [[ $purge_data == true ]]; then
	rm -rf /opt/steward /var/lib/steward /var/lib/steward-executor /var/lib/steward-gateway \
		/var/lib/steward-node /var/log/steward
fi
if [[ -d $node_role_claim_directory && ! -L $node_role_claim_directory ]]; then
	rm -f -- "$node_role_claim_file"
	rmdir -- "$node_role_claim_directory" 2>/dev/null || true
	sync -f /var/lib
fi
echo "uninstall-node: Steward integration removed"
if [[ $purge_config == false ]]; then
	echo "uninstall-node: retained configuration and/or durable state (see --help for purge options)"
fi
