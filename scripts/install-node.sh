#!/bin/bash -p
# Install one versioned Steward node release without enabling or starting it.
set -euo pipefail
set +x
if ! shopt -qo privileged; then
	echo "install-node: execute this package helper directly or invoke it with /bin/bash -p so caller-controlled shell startup files and exported functions are ignored" >&2
	exit 2
fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C LANG=C
unset BASH_ENV ENV CDPATH GLOBIGNORE CURL_HOME XDG_CONFIG_HOME
unset TAR_OPTIONS GZIP POSIXLY_CORRECT TMPDIR
IFS=$' \t\n'
umask 077

if [[ $# -ne 2 || $1 != --expected-version || -z ${2:-} ]]; then
	echo "usage: install-node.sh --expected-version vX.Y.Z" >&2
	exit 2
fi
expected_version=$2
if [[ -n ${STEWARD_EXPECTED_VERSION:-} && $STEWARD_EXPECTED_VERSION != "$expected_version" ]]; then
	echo "install-node: package expects '$expected_version' but the caller requested '$STEWARD_EXPECTED_VERSION'" >&2
	exit 2
fi

valid_release_version() {
	local candidate=$1 core prerelease identifier
	(( ${#candidate} <= 128 )) || return 1
	[[ $candidate =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$ ]] || return 1
	core=${candidate#v}
	if [[ $core == *-* ]]; then
		prerelease=${core#*-}
		IFS=. read -r -a identifiers <<<"$prerelease"
		for identifier in "${identifiers[@]}"; do
			if [[ $identifier =~ ^[0-9]+$ && $identifier == 0[0-9]* ]]; then
				return 1
			fi
		done
	fi
	return 0
}

# Generate connector receipt trust material without giving staged release code
# root privileges. The root-controlled configuration directory contains a
# random service-owned child only while generation runs. The node transaction
# smoke test exercises this same boundary.
generate_connector_receipt_keypair() (
	set -euo pipefail
	if [[ $# -ne 4 ]]; then
		echo "install-node: internal connector key generation arguments are invalid" >&2
		exit 2
	fi
	local release_dir=$1 gateway_user=$2 gateway_group=$3 config_root=$4
	local gateway_uid gateway_gid key_work staged_private staged_public
	local temporary_private='' temporary_public='' destinations_started=0 committed=0
	local private_destination="$config_root/connector-receipts.private.pem"
	local public_destination="$config_root/connector-receipts.public"

	# shellcheck disable=SC2329 # Invoked by the EXIT trap below.
	cleanup_connector_receipt_keypair() {
		[[ -z ${key_work:-} ]] || rm -rf -- "$key_work"
		[[ -z ${temporary_private:-} ]] || rm -f -- "$temporary_private"
		[[ -z ${temporary_public:-} ]] || rm -f -- "$temporary_public"
		if (( destinations_started == 1 && committed == 0 )); then
			rm -f -- "$private_destination" "$public_destination"
		fi
	}
	trap cleanup_connector_receipt_keypair EXIT
	trap 'exit 2' HUP INT TERM

	if [[ ! -d $config_root || -L $config_root ]]; then
		echo "install-node: connector key configuration path must be an existing regular directory" >&2
		exit 2
	fi
	gateway_uid=$(timeout --signal=TERM --kill-after=2 5 id -u "$gateway_user")
	gateway_gid=$(timeout --signal=TERM --kill-after=2 5 id -g "$gateway_user")
	if [[ $(timeout --signal=TERM --kill-after=2 5 id -gn "$gateway_user") != "$gateway_group" ]]; then
		echo "install-node: connector key identity must use its primary group" >&2
		exit 2
	fi
	if [[ $(stat -c '%u:%g:%a' "$config_root") != "0:0:755" ]]; then
		echo "install-node: connector key configuration directory must be root-owned with mode 0755" >&2
		exit 2
	fi

	key_work="$config_root/.connector-keygen.pending"
	temporary_private="$config_root/.connector-receipts.private.pending"
	temporary_public="$config_root/.connector-receipts.public.pending"
	if [[ -e $key_work || -L $key_work || -e $temporary_private || -L $temporary_private ||
		-e $temporary_public || -L $temporary_public ]]; then
		echo "install-node: refusing stale connector receipt generation state" >&2
		exit 2
	fi
	mkdir -- "$key_work"
	chown "$gateway_user:$gateway_group" "$key_work"
	chmod 0700 "$key_work"
	staged_private="$key_work/private.pem"
	staged_public="$key_work/public"
	if ! timeout --signal=TERM --kill-after=5 20 runuser -u "$gateway_user" -- \
		/bin/sh -c 'umask 022; exec "$@"' steward-keygen \
		"$release_dir/stewardctl" keygen -private-out "$staged_private" \
		-public-out "$staged_public" >/dev/null; then
		echo "install-node: unprivileged connector receipt key generation failed" >&2
		exit 2
	fi
	if [[ ! -f $staged_private || -L $staged_private || ! -f $staged_public || -L $staged_public ]]; then
		echo "install-node: connector key generator did not create regular files" >&2
		exit 2
	fi
	if [[ $(stat -c '%u:%g:%a:%h' "$staged_private") != "$gateway_uid:$gateway_gid:600:1" ||
		$(stat -c '%u:%g:%a:%h' "$staged_public") != "$gateway_uid:$gateway_gid:644:1" ]]; then
		echo "install-node: connector key generator created unsafe ownership, modes, or links" >&2
		exit 2
	fi
	if ! timeout --signal=TERM --kill-after=5 10 runuser -u "$gateway_user" -- \
		"$release_dir/stewardctl" key match \
		-private-key "$staged_private" -public-key "$staged_public" >/dev/null; then
		echo "install-node: generated connector receipt key pair does not match" >&2
		exit 2
	fi
	# The parent is root-owned and not writable by the service identity, so taking
	# ownership of this directory closes the staged-output namespace before root
	# copies from it.
	chown root:root "$key_work"
	chmod 0700 "$key_work"
	if [[ $(stat -c '%u:%g:%a' "$key_work") != "0:0:700" ||
		$(stat -c '%u:%g:%a:%h' "$staged_private") != "$gateway_uid:$gateway_gid:600:1" ||
		$(stat -c '%u:%g:%a:%h' "$staged_public") != "$gateway_uid:$gateway_gid:644:1" ]]; then
		echo "install-node: connector key output namespace could not be sealed" >&2
		exit 2
	fi

	install -o "$gateway_user" -g "$gateway_group" -m 0600 "$staged_private" "$temporary_private"
	install -o root -g root -m 0644 "$staged_public" "$temporary_public"
	if [[ ! -f $temporary_private || -L $temporary_private ||
		$(stat -c '%u:%g:%a:%h' "$temporary_private") != "$gateway_uid:$gateway_gid:600:1" ]]; then
		echo "install-node: installed connector receipt private key is unsafe" >&2
		exit 2
	fi
	if [[ ! -f $temporary_public || -L $temporary_public ||
		$(stat -c '%u:%g:%a:%h' "$temporary_public") != "0:0:644:1" ]]; then
		echo "install-node: installed connector receipt public key is unsafe" >&2
		exit 2
	fi
	if ! timeout --signal=TERM --kill-after=5 10 runuser -u "$gateway_user" -- \
		"$release_dir/stewardctl" key match \
		-private-key "$temporary_private" -public-key "$temporary_public" >/dev/null; then
		echo "install-node: installed connector receipt key pair does not match" >&2
		exit 2
	fi
	if [[ -e $private_destination || -L $private_destination ||
		-e $public_destination || -L $public_destination ]]; then
		echo "install-node: refusing to replace connector receipt trust material" >&2
		exit 2
	fi
	sync -f "$temporary_private"
	sync -f "$temporary_public"
	destinations_started=1
	mv -T "$temporary_private" "$private_destination"
	temporary_private=
	mv -T "$temporary_public" "$public_destination"
	temporary_public=
	sync -f "$config_root"
	committed=1
)

if ! valid_release_version "$expected_version"; then
	echo "install-node: --expected-version must be an installable vX.Y.Z release tag" >&2
	exit 2
fi
if [[ ${EUID} -ne 0 ]]; then
	echo "install-node: run as root" >&2
	exit 2
fi
# BEGIN HOST_ROLE_LOCK_BOUNDARY
readonly host_role_lock_directory=/run/steward-host-role
readonly host_role_lock_file=$host_role_lock_directory/role.lock
readonly node_role_claim_directory=/var/lib/steward-node-installer
readonly node_role_claim_file=$node_role_claim_directory/claim
prepare_host_role_lock() {
	local metadata uid mode
	[[ -d /run && ! -L /run ]] || {
		echo "install-node: refusing an unsafe /run directory" >&2
		return 2
	}
	metadata=$(stat -c '%u:%a' -- /run) || return 2
	uid=${metadata%%:*}; mode=${metadata#*:}
	if [[ $uid != 0 ]] || (( (8#$mode & 022) != 0 )); then
		echo "install-node: /run must be root-owned and not group- or world-writable" >&2
		return 2
	fi
	if [[ ! -e $host_role_lock_directory && ! -L $host_role_lock_directory ]]; then
		install -d -o root -g root -m 0700 -- "$host_role_lock_directory"
	fi
	if [[ ! -d $host_role_lock_directory || -L $host_role_lock_directory ||
		$(readlink -e -- "$host_role_lock_directory" 2>/dev/null) != "$host_role_lock_directory" ||
		$(stat -c '%u:%g:%a' -- "$host_role_lock_directory" 2>/dev/null) != 0:0:700 ]]; then
		echo "install-node: refusing an unsafe host-role lock directory" >&2
		return 2
	fi
	if [[ ! -e $host_role_lock_file && ! -L $host_role_lock_file ]]; then
		(umask 077; set -o noclobber; : >"$host_role_lock_file") 2>/dev/null || true
	fi
	if [[ ! -f $host_role_lock_file || -L $host_role_lock_file ||
		$(stat -c '%u:%g:%a:%h' -- "$host_role_lock_file" 2>/dev/null) != 0:0:600:1 ]]; then
		echo "install-node: refusing an unsafe host-role lock" >&2
		return 2
	fi
}
acquire_host_role_lock() {
	local path_metadata fd_metadata process_id=${BASHPID:-$$}
	command -v flock >/dev/null 2>&1 || {
		echo "install-node: flock is required to serialize host-role installation" >&2
		return 2
	}
	prepare_host_role_lock || return
	exec 7<>"$host_role_lock_file"
	path_metadata=$(stat -c '%d:%i:%u:%g:%a:%h' -- "$host_role_lock_file") || return 2
	fd_metadata=$(stat -Lc '%d:%i:%u:%g:%a:%h' -- "/proc/$process_id/fd/7") || return 2
	if [[ $path_metadata != "$fd_metadata" || $path_metadata != *:0:0:600:1 ]]; then
		echo "install-node: host-role lock changed while it was opened" >&2
		exec 7>&-
		return 2
	fi
	if ! flock -w 60 7; then
		echo "install-node: another host-role installation did not finish within 60 seconds" >&2
		exec 7>&-
		return 1
	fi
}
validate_node_role_claim() {
	[[ -d $node_role_claim_directory && ! -L $node_role_claim_directory &&
		$(readlink -e -- "$node_role_claim_directory" 2>/dev/null) == "$node_role_claim_directory" &&
		$(stat -c '%u:%g:%a' -- "$node_role_claim_directory" 2>/dev/null) == 0:0:700 ]] || return 1
	[[ -f $node_role_claim_file && ! -L $node_role_claim_file &&
		$(stat -c '%u:%g:%a:%h:%s' -- "$node_role_claim_file" 2>/dev/null) == 0:0:600:1:27 ]] || return 1
	[[ $(<"$node_role_claim_file") == steward.node-role-claim.v1 ]]
}
clear_node_role_claim() {
	if [[ ! -e $node_role_claim_directory && ! -L $node_role_claim_directory ]]; then
		return 0
	fi
	validate_node_role_claim || {
		echo "install-node: refusing unsafe durable node-role reservation state" >&2
		return 2
	}
	rm -f -- "$node_role_claim_file"
	sync -f "$node_role_claim_directory"
	rmdir -- "$node_role_claim_directory" 2>/dev/null || true
	sync -f /var/lib
}
# END HOST_ROLE_LOCK_BOUNDARY
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
if [[ $(uname -s) != Linux ]]; then
	echo "install-node: the Steward node appliance supports Linux only" >&2
	exit 2
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

trusted_root_directory_chain() {
	local directory=$1 current metadata uid mode
	[[ -d $directory && ! -L $directory && $(readlink -e -- "$directory" 2>/dev/null) == "$directory" ]] || return 1
	current=$directory
	while :; do
		metadata=$(stat -c '%u:%a' -- "$current") || return 1
		uid=${metadata%%:*}
		mode=${metadata#*:}
		if [[ $uid != 0 ]] || (( (8#$mode & 022) != 0 )); then return 1; fi
		[[ $current == / ]] && break
		current=$(dirname -- "$current")
	done
}

ensure_managed_directory() {
	local directory=$1 owner=$2 group=$3 create_mode=$4 exact_mode=$5
	local parent metadata mode owner_uid group_gid normalized_mode
	parent=$(dirname -- "$directory")
	if [[ ! -e $directory && ! -L $directory ]]; then
		trusted_root_directory_chain "$parent" || return 1
		install -d -o "$owner" -g "$group" -m "$create_mode" -- "$directory" || return 1
	fi
	[[ -d $directory && ! -L $directory && $(readlink -e -- "$directory" 2>/dev/null) == "$directory" ]] || return 1
	metadata=$(stat -c '%u:%g:%a' -- "$directory") || return 1
	if [[ $exact_mode == true ]]; then
		owner_uid=$(timeout --signal=TERM --kill-after=2 5 id -u "$owner") || return 1
		group_gid=$(getent_one group "$group" | cut -d: -f3) || return 1
		normalized_mode=${create_mode#0}
		[[ $metadata == "$owner_uid:$group_gid:$normalized_mode" ]] || return 1
	else
		[[ ${metadata%%:*} == 0 ]] || return 1
		mode=${metadata##*:}
		(( (8#$mode & 022) == 0 )) || return 1
	fi
}

# BEGIN NODE_INSTALL_LOCK_BOUNDARY
readonly node_lock_directory=/run/steward-node
readonly node_lock_file=$node_lock_directory/activation.lock

prepare_node_lock() {
	local metadata uid mode
	if [[ -L /run || ! -d /run ]]; then
		echo "install-node: refusing an unsafe /run directory" >&2
		return 2
	fi
	metadata=$(stat -c '%u:%a' -- /run) || return 2
	uid=${metadata%%:*}; mode=${metadata#*:}
	if [[ $uid != 0 ]] || (( (8#$mode & 022) != 0 )); then
		echo "install-node: /run must be root-owned and not group- or world-writable" >&2
		return 2
	fi
	if [[ ! -e $node_lock_directory && ! -L $node_lock_directory ]]; then
		install -d -o root -g root -m 0700 -- "$node_lock_directory"
	fi
	if [[ -L $node_lock_directory || ! -d $node_lock_directory ||
		$(readlink -e -- "$node_lock_directory" 2>/dev/null) != "$node_lock_directory" ||
		$(stat -c '%u:%g:%a' -- "$node_lock_directory" 2>/dev/null) != 0:0:700 ]]; then
		echo "install-node: refusing an unsafe node lock directory" >&2
		return 2
	fi
	if [[ ! -e $node_lock_file && ! -L $node_lock_file ]]; then
		(umask 077; set -o noclobber; : >"$node_lock_file") 2>/dev/null || true
	fi
	if [[ -L $node_lock_file || ! -f $node_lock_file ||
		$(stat -c '%u:%g:%a:%h' -- "$node_lock_file" 2>/dev/null) != 0:0:600:1 ]]; then
		echo "install-node: refusing an unsafe node activation lock" >&2
		return 2
	fi
}

acquire_node_lock() {
	local path_metadata fd_metadata process_id=${BASHPID:-$$}
	command -v flock >/dev/null 2>&1 || {
		echo "install-node: flock is required to serialize node installation" >&2
		return 2
	}
	prepare_node_lock || return
	exec 9<>"$node_lock_file"
	path_metadata=$(stat -c '%d:%i:%u:%g:%a:%h' -- "$node_lock_file") || return 2
	fd_metadata=$(stat -Lc '%d:%i:%u:%g:%a:%h' -- "/proc/$process_id/fd/9") || return 2
	if [[ $path_metadata != "$fd_metadata" || $path_metadata != *:0:0:600:1 ]]; then
		echo "install-node: node activation lock changed while it was opened" >&2
		exec 9>&-
		return 2
	fi
	if ! flock -w 60 9; then
		echo "install-node: another node lifecycle operation did not finish within 60 seconds" >&2
		exec 9>&-
		return 1
	fi
}
# END NODE_INSTALL_LOCK_BOUNDARY

getent_one() {
	local database=$1 key=$2 output_file output status=0 size
	output_file=$(mktemp "$node_lock_directory/.nss-one.XXXXXX") || return 2
	(ulimit -c 0; ulimit -f 128
		exec timeout --signal=TERM --kill-after=1 10 getent "$database" "$key") \
		>"$output_file" 2>/dev/null || status=$?
	size=$(stat -c %s -- "$output_file") || { rm -f -- "$output_file"; return 2; }
	if (( status == 2 && size == 0 )); then
		rm -f -- "$output_file"
		return 1
	fi
	if (( status != 0 || size == 0 || size > 65536 )); then
		rm -f -- "$output_file"
		return 2
	fi
	output=$(<"$output_file")
	rm -f -- "$output_file"
	[[ $output != *$'\n'* && ${output%%:*} == "$key" ]] || return 2
	printf '%s\n' "$output"
}

validate_unique_nss_id() {
	local database=$1 field=$2 value=$3 output_file status=0
	output_file=$(mktemp "$node_lock_directory/.nss-dump.XXXXXX") || return 2
	(ulimit -c 0; ulimit -f 16384
		exec timeout --signal=TERM --kill-after=1 10 getent "$database") \
		>"$output_file" 2>/dev/null || status=$?
	if (( status != 0 )) || [[ $(stat -c %s -- "$output_file") -gt 8388608 ]]; then
		rm -f -- "$output_file"
		return 2
	fi
	if awk -F: -v field="$field" -v value="$value" '
			$field == value { count++ }
			END { exit(count == 1 ? 0 : 1) }
		' "$output_file"; then
		status=0
	else
		status=$?
	fi
	rm -f -- "$output_file"
	return "$status"
}

validate_managed_group() {
	local group=$1 entry name gid members
	entry=$(getent_one group "$group") || {
		echo "install-node: group '$group' must resolve to exactly one NSS entry" >&2
		return 2
	}
	IFS=: read -r name _ gid members <<<"$entry"
	if [[ $name != "$group" || ! $gid =~ ^[0-9]+$ || $gid == 0 ]] ||
		! validate_unique_nss_id group 3 "$gid"; then
		echo "install-node: group '$group' must have a unique, non-root GID" >&2
		return 2
	fi
	printf '%s\n' "$gid"
}

validate_group_members() {
	local group=$1 expected=${2:-} entry members actual
	entry=$(getent_one group "$group") || return 2
	members=${entry##*:}
	actual=$(tr ',' '\n' <<<"$members" | sed '/^$/d' | sort -u | paste -sd, -)
	expected=$(tr ',' '\n' <<<"$expected" | sed '/^$/d' | sort -u | paste -sd, -)
	if [[ $actual != "$expected" ]]; then
		echo "install-node: group '$group' has unexpected member accounts" >&2
		return 2
	fi
}

validate_primary_group_users() {
	local gid=$1 expected=${2:-} actual output_file status=0
	output_file=$(mktemp "$node_lock_directory/.nss-passwd.XXXXXX") || return 2
	(ulimit -c 0; ulimit -f 16384
		exec timeout --signal=TERM --kill-after=1 10 getent passwd) \
		>"$output_file" 2>/dev/null || status=$?
	if (( status != 0 )) || [[ $(stat -c %s -- "$output_file") -gt 8388608 ]]; then
		rm -f -- "$output_file"
		return 2
	fi
	actual=$(awk -F: -v gid="$gid" '$4 == gid { print $1 }' "$output_file" | sort -u | paste -sd, -)
	rm -f -- "$output_file"
	expected=$(tr ',' '\n' <<<"$expected" | sed '/^$/d' | sort -u | paste -sd, -)
	if [[ $actual != "$expected" ]]; then
		echo "install-node: service GID '$gid' is the primary group of an unexpected account" >&2
		return 2
	fi
}

validate_service_identity() {
	local user=$1 primary_group=$2 expected_home=$3
	shift 3
	local entry shadow_entry name uid gid home shell shadow_name shadow_password
	local primary_gid group group_gid actual_groups expected_groups=
	entry=$(getent_one passwd "$user") || {
		echo "install-node: user '$user' must resolve to exactly one NSS entry" >&2
		return 2
	}
	IFS=: read -r name _ uid gid _ home shell <<<"$entry"
	primary_gid=$(validate_managed_group "$primary_group") || return
	case "$shell" in
		/usr/sbin/nologin | /sbin/nologin | /usr/bin/false | /bin/false) ;;
		*) echo "install-node: user '$user' must use a nologin or false shell" >&2; return 2 ;;
	esac
	if [[ $name != "$user" || ! $uid =~ ^[0-9]+$ || $uid == 0 || $gid != "$primary_gid" || $home != "$expected_home" ]] ||
		! validate_unique_nss_id passwd 3 "$uid"; then
		echo "install-node: user '$user' must have its unique non-root UID, primary group, and fixed home" >&2
		return 2
	fi
	shadow_entry=$(getent_one shadow "$user") || {
		echo "install-node: user '$user' must have one readable locked-password entry" >&2
		return 2
	}
	IFS=: read -r shadow_name shadow_password _ <<<"$shadow_entry"
	if [[ $shadow_name != "$user" || ( $shadow_password != '!'* && $shadow_password != '*'* ) ]]; then
		echo "install-node: user '$user' password must be locked" >&2
		return 2
	fi
	for group in "$@"; do
		group_gid=$(validate_managed_group "$group") || return
		expected_groups+="${expected_groups:+,}$group_gid"
	done
	expected_groups=$(tr ',' '\n' <<<"$expected_groups" | sort -n -u | paste -sd, -)
	actual_groups=$(timeout --signal=TERM --kill-after=2 5 id -G "$user" | tr ' ' '\n' | sort -n -u | paste -sd, -)
	if [[ $actual_groups != "$expected_groups" ]]; then
		echo "install-node: user '$user' has unexpected supplemental groups" >&2
		return 2
	fi
}

validate_install_marker() {
	local marker=$1
	[[ -f $marker && ! -L $marker && $(stat -c '%u:%g:%a:%h' -- "$marker" 2>/dev/null) == 0:0:600:1 ]]
}

create_install_marker() {
	local marker=$1
	if [[ -e $marker || -L $marker ]]; then
		validate_install_marker "$marker" || {
			echo "install-node: refusing unsafe install journal $marker" >&2
			return 2
		}
		return 0
	fi
	(umask 077; set -o noclobber; : >"$marker") || return 2
	validate_install_marker "$marker" || return 2
	sync -f "$marker"
}

remove_pending_regular_file() {
	local path=$1
	if [[ -e $path || -L $path ]]; then
		if [[ ! -f $path || -L $path || $(stat -c %h -- "$path" 2>/dev/null) != 1 ]]; then
			echo "install-node: refusing unsafe pending install path $path" >&2
			return 2
		fi
		rm -f -- "$path"
	fi
}

validate_gateway_service_token() {
	local path=$1 expected_uid=$2 expected_gid=$3 token
	[[ -f $path && ! -L $path &&
		$(stat -c '%u:%g:%a:%h:%s' -- "$path" 2>/dev/null) == "$expected_uid:$expected_gid:600:1:65" ]] || return 1
	token=$(<"$path")
	[[ $token =~ ^[a-f0-9]{64}$ ]]
}

ensure_gateway_service_token() {
	local config_root=$1 state_root=$2 gateway_user=$3 gateway_group=$4
	local final="$config_root/gateway-service-token"
	local pending="$config_root/.gateway-service-token.pending"
	local marker="$state_root/install.gateway-token.pending"
	local gateway_uid gateway_gid
	gateway_uid=$(timeout --signal=TERM --kill-after=2 5 id -u "$gateway_user")
	gateway_gid=$(getent_one group "$gateway_group" | cut -d: -f3)

	if [[ -e $marker || -L $marker ]]; then
		validate_install_marker "$marker" || {
			echo "install-node: refusing unsafe Gateway token install journal" >&2
			return 2
		}
		if [[ -e $final || -L $final ]]; then
			validate_gateway_service_token "$final" "$gateway_uid" "$gateway_gid" || {
				echo "install-node: journaled Gateway service token is invalid" >&2
				return 2
			}
			remove_pending_regular_file "$pending" || return
			rm -f -- "$marker"
			sync -f "$state_root"
			return 0
		fi
		remove_pending_regular_file "$pending" || return
	else
		if [[ -e $pending || -L $pending ]]; then
			echo "install-node: refusing unjournaled pending Gateway service token" >&2
			return 2
		fi
		if [[ -e $final || -L $final ]]; then
			validate_gateway_service_token "$final" "$gateway_uid" "$gateway_gid" || {
				echo "install-node: existing Gateway service token is invalid" >&2
				return 2
			}
			return 0
		fi
		create_install_marker "$marker" || return
	fi

	(umask 077; set -o noclobber
		od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"$pending"
		printf '\n' >>"$pending") || return 2
	chown "$gateway_user:$gateway_group" "$pending"
	chmod 0600 "$pending"
	validate_gateway_service_token "$pending" "$gateway_uid" "$gateway_gid" || {
		echo "install-node: generated Gateway service token is invalid" >&2
		return 2
	}
	sync -f "$pending"
	if [[ -e $final || -L $final ]]; then
		echo "install-node: refusing to replace Gateway service token" >&2
		return 2
	fi
	mv -T "$pending" "$final"
	sync -f "$config_root"
	rm -f -- "$marker"
	sync -f "$state_root"
}

validate_connector_receipt_keypair() {
	local release_dir=$1 config_root=$2 gateway_user=$3 gateway_group=$4
	local private="$config_root/connector-receipts.private.pem"
	local public="$config_root/connector-receipts.public"
	local gateway_uid gateway_gid
	gateway_uid=$(timeout --signal=TERM --kill-after=2 5 id -u "$gateway_user")
	gateway_gid=$(getent_one group "$gateway_group" | cut -d: -f3)
	[[ -f $private && ! -L $private && -f $public && ! -L $public ]] || return 1
	[[ $(stat -c '%u:%g:%a:%h' -- "$private" 2>/dev/null) == "$gateway_uid:$gateway_gid:600:1" ]] || return 1
	[[ $(stat -c '%u:%g:%a:%h' -- "$public" 2>/dev/null) == 0:0:644:1 ]] || return 1
	timeout --signal=TERM --kill-after=5 10 runuser -u "$gateway_user" -- \
		"$release_dir/stewardctl" key match \
		-private-key "$private" -public-key "$public" >/dev/null
}

remove_connector_pending_state() {
	local config_root=$1
	local path key_work="$config_root/.connector-keygen.pending"
	for path in "$config_root/.connector-receipts.private.pending" \
		"$config_root/.connector-receipts.public.pending"; do
		remove_pending_regular_file "$path" || return
	done
	if [[ -e $key_work || -L $key_work ]]; then
		if [[ ! -d $key_work || -L $key_work ||
			$(readlink -e -- "$key_work" 2>/dev/null) != "$key_work" ]]; then
			echo "install-node: refusing unsafe pending connector key directory" >&2
			return 2
		fi
		rm -rf -- "$key_work"
	fi
}

ensure_connector_receipt_keypair() {
	local release_dir=$1 config_root=$2 state_root=$3 gateway_user=$4 gateway_group=$5
	local private="$config_root/connector-receipts.private.pem"
	local public="$config_root/connector-receipts.public"
	local marker="$state_root/install.connector-receipts.pending"
	local private_present=0 public_present=0 marker_present=0
	[[ ! -e $private && ! -L $private ]] || private_present=1
	[[ ! -e $public && ! -L $public ]] || public_present=1
	[[ ! -e $marker && ! -L $marker ]] || marker_present=1

	if (( marker_present == 1 )); then
		validate_install_marker "$marker" || {
			echo "install-node: refusing unsafe connector receipt install journal" >&2
			return 2
		}
	fi
	if (( private_present == 1 && public_present == 1 )); then
		validate_connector_receipt_keypair "$release_dir" "$config_root" "$gateway_user" "$gateway_group" || {
			echo "install-node: existing connector receipt key pair is invalid" >&2
			return 2
		}
		if (( marker_present == 1 )); then
			remove_connector_pending_state "$config_root" || return
			rm -f -- "$marker"
			sync -f "$state_root"
		elif [[ -e $config_root/.connector-keygen.pending || -L $config_root/.connector-keygen.pending ||
			-e $config_root/.connector-receipts.private.pending || -L $config_root/.connector-receipts.private.pending ||
			-e $config_root/.connector-receipts.public.pending || -L $config_root/.connector-receipts.public.pending ]]; then
			echo "install-node: refusing unjournaled pending connector receipt state" >&2
			return 2
		fi
		return 0
	fi
	if (( private_present != public_present && marker_present == 0 )); then
		echo "install-node: connector receipt private and public keys must exist together" >&2
		return 2
	fi
	if (( marker_present == 0 )); then
		if [[ -e $config_root/.connector-keygen.pending || -L $config_root/.connector-keygen.pending ||
			-e $config_root/.connector-receipts.private.pending || -L $config_root/.connector-receipts.private.pending ||
			-e $config_root/.connector-receipts.public.pending || -L $config_root/.connector-receipts.public.pending ]]; then
			echo "install-node: refusing unjournaled pending connector receipt state" >&2
			return 2
		fi
		create_install_marker "$marker" || return
	else
		if (( private_present == 1 )); then
			[[ -f $private && ! -L $private && $(stat -c %h -- "$private" 2>/dev/null) == 1 ]] || {
				echo "install-node: refusing unsafe journaled connector private key" >&2
				return 2
			}
			rm -f -- "$private"
		fi
		if (( public_present == 1 )); then
			[[ -f $public && ! -L $public && $(stat -c %h -- "$public" 2>/dev/null) == 1 ]] || {
				echo "install-node: refusing unsafe journaled connector public key" >&2
				return 2
			}
			rm -f -- "$public"
		fi
		remove_connector_pending_state "$config_root" || return
	fi

	generate_connector_receipt_keypair "$release_dir" "$gateway_user" "$gateway_group" "$config_root"
	validate_connector_receipt_keypair "$release_dir" "$config_root" "$gateway_user" "$gateway_group" || {
		echo "install-node: generated connector receipt key pair failed validation" >&2
		return 2
	}
	rm -f -- "$marker"
	sync -f "$state_root"
}

managed_symlink_pending_path() {
	local path=$1 directory base
	directory=$(dirname -- "$path")
	base=$(basename -- "$path")
	printf '%s/.%s.steward-install\n' "$directory" "$base"
}

validate_managed_symlink_slot() {
	local path=$1 target=$2 pending
	pending=$(managed_symlink_pending_path "$path")
	if [[ -e $path || -L $path ]]; then
		[[ -L $path && $(readlink -- "$path") == "$target" ]] || return 1
	fi
	if [[ -e $pending || -L $pending ]]; then
		[[ -L $pending && $(readlink -- "$pending") == "$target" ]] || return 1
	fi
}

ensure_managed_symlink() {
	local path=$1 target=$2 pending directory
	validate_managed_symlink_slot "$path" "$target" || return 1
	pending=$(managed_symlink_pending_path "$path")
	if [[ -L $path ]]; then
		[[ ! -L $pending ]] || rm -f -- "$pending"
		return 0
	fi
	directory=$(dirname -- "$path")
	if [[ -L $pending ]]; then
		rm -f -- "$pending"
	fi
	(umask 077; set -o noclobber; ln -s -- "$target" "$pending") || return 1
	mv -T -- "$pending" "$path"
	sync -f "$directory"
}

validate_managed_config_file() {
	local path=$1 owner=$2 group=$3 expected_mode=$4 max_size=$5
	local owner_uid group_gid normalized_mode metadata size actual_uid actual_gid actual_mode links
	owner_uid=$(timeout --signal=TERM --kill-after=2 5 id -u "$owner") || return 1
	group_gid=$(getent_one group "$group" | cut -d: -f3) || return 1
	normalized_mode=${expected_mode#0}
	[[ -f $path && ! -L $path ]] || return 1
	metadata=$(stat -c '%u:%g:%a:%h:%s' -- "$path") || return 1
	IFS=: read -r actual_uid actual_gid actual_mode links size <<<"$metadata"
	[[ $actual_uid == "$owner_uid" && $actual_gid == "$group_gid" &&
		$actual_mode == "$normalized_mode" && $links == 1 && $size =~ ^[0-9]+$ ]] || return 1
	(( size > 0 && size <= max_size ))
}

install_default_config_atomic() {
	local source=$1 destination=$2 owner=$3 group=$4 expected_mode=$5
	local directory base pending
	directory=$(dirname -- "$destination")
	base=$(basename -- "$destination")
	pending="$directory/.${base}.steward-install"
	if [[ -e $destination || -L $destination ]]; then
		validate_managed_config_file "$destination" "$owner" "$group" "$expected_mode" 1048576 || {
			echo "install-node: refusing unsafe existing configuration $destination" >&2
			return 2
		}
		remove_pending_regular_file "$pending" || return
		return 0
	fi
	remove_pending_regular_file "$pending" || return
	install -o "$owner" -g "$group" -m "$expected_mode" -- "$source" "$pending"
	validate_managed_config_file "$pending" "$owner" "$group" "$expected_mode" 1048576 || return 2
	cmp -s -- "$source" "$pending" || return 2
	sync -f "$pending"
	if [[ -e $destination || -L $destination ]]; then
		echo "install-node: configuration destination appeared during installation: $destination" >&2
		return 2
	fi
	mv -T -- "$pending" "$destination"
	sync -f "$directory"
}

read_machine_id() {
	local path=/etc/machine-id metadata uid mode links size value
	[[ -f $path && ! -L $path ]] || return 1
	metadata=$(stat -c '%u:%a:%h:%s' -- "$path") || return 1
	IFS=: read -r uid mode links size <<<"$metadata"
	[[ $uid == 0 && $links == 1 && $size =~ ^(32|33)$ ]] || return 1
	(( (8#$mode & 022) == 0 )) || return 1
	value=$(timeout --signal=TERM --kill-after=1 2 head -c 34 -- "$path") || return 1
	[[ $value =~ ^[a-f0-9]{32}$ ]] || return 1
	printf '%s\n' "$value"
}

install_gateway_config_atomic() {
	local source=$1 destination=$2 executor_group_gid=$3 relay_group_gid=$4 machine_id=$5
	local directory base pending status=0
	directory=$(dirname -- "$destination")
	base=$(basename -- "$destination")
	pending="$directory/.${base}.steward-install"
	if [[ -e $destination || -L $destination ]]; then
		validate_managed_config_file "$destination" root steward-gateway 0640 1048576 || {
			echo "install-node: refusing unsafe existing Gateway configuration $destination" >&2
			return 2
		}
		remove_pending_regular_file "$pending" || return
		return 0
	fi
	remove_pending_regular_file "$pending" || return
	(ulimit -c 0; ulimit -f 2048
		exec timeout --signal=TERM --kill-after=1 5 sed \
			-e "s/@EXECUTOR_GID@/$executor_group_gid/g" \
			-e "s/@RELAY_GID@/$relay_group_gid/g" \
			-e "s|@CONNECTOR_RECEIPT_NODE_ID@|steward-$machine_id/gateway|g" \
			-- "$source") >"$pending" || status=$?
	if (( status != 0 )); then
		return 2
	fi
	chown root:steward-gateway "$pending"
	chmod 0640 "$pending"
	validate_managed_config_file "$pending" root steward-gateway 0640 1048576 || return 2
	sync -f "$pending"
	if [[ -e $destination || -L $destination ]]; then
		echo "install-node: Gateway configuration destination appeared during installation" >&2
		return 2
	fi
	mv -T -- "$pending" "$destination"
	sync -f "$directory"
}

validate_release_source_tree() {
	local base=$1
	trusted_root_directory_chain "$base" || return 1
	find "$base" -mindepth 1 -print0 | (
		local entry metadata uid mode links size
		local file_count=0 total_size=0
		while IFS= read -r -d '' entry; do
			if [[ -d $entry && ! -L $entry ]]; then
				metadata=$(stat -c '%u:%a' -- "$entry") || exit 1
				uid=${metadata%%:*}
				mode=${metadata#*:}
				[[ $uid == 0 ]] && (( (8#$mode & 022) == 0 )) || exit 1
			elif [[ -f $entry && ! -L $entry ]]; then
				metadata=$(stat -c '%u:%a:%h:%s' -- "$entry") || exit 1
				IFS=: read -r uid mode links size <<<"$metadata"
				[[ $uid == 0 && $links == 1 ]] || exit 1
				(( (8#$mode & 022) == 0 && size >= 0 && size <= 268435456 )) || exit 1
				((file_count += 1, total_size += size))
				(( file_count <= 4096 && total_size <= 1073741824 )) || exit 1
			else
				exit 1
			fi
		done
		(( file_count > 0 ))
	)
}

case "$(uname -m)" in
	x86_64 | amd64) goarch=amd64 ;;
	aarch64 | arm64) goarch=arm64 ;;
	*) echo "install-node: unsupported architecture $(uname -m)" >&2; exit 2 ;;
esac

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

release_file_path() {
	local base=$1 layout=$2 logical=$3
	if [[ $layout == source && $logical == integration/* ]]; then
		printf '%s/%s\n' "$base" "${logical#integration/}"
	else
		printf '%s/%s\n' "$base" "$logical"
	fi
}

hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		echo "install-node: sha256sum or shasum is required" >&2
		exit 2
	fi
}

write_canonical_manifest() {
	local base=$1 layout=$2 output=$3 logical path suffix index last_index
	{
		printf '{\n'
		printf '  "schema": "steward.release.v2",\n'
		printf '  "version": "%s",\n' "$expected_version"
		printf '  "os": "linux",\n'
		printf '  "arch": "%s",\n' "$goarch"
		printf '  "state_formats": {\n'
		printf '    "admission_fence": {"read_min": 1, "read_max": 2, "write": 2},\n'
		printf '    "connector_receipt_log": {"read_min": 1, "read_max": 6, "write": 6},\n'
		printf '    "evidence_log": {"read_min": 1, "read_max": 2, "write": 2},\n'
		printf '    "gateway_state": {"read_min": 1, "read_max": 6, "write": 6},\n'
		printf '    "operation_journal": {"read_min": 1, "read_max": 1, "write": 1},\n'
		printf '    "supervisor_state": {"read_min": 1, "read_max": 1, "write": 1},\n'
		printf '    "uplink_delivery_state": {"read_min": 2, "read_max": 4, "write": 4},\n'
		printf '    "uplink_state": {"read_min": 2, "read_max": 2, "write": 2}\n'
		printf '  },\n'
		printf '  "files": {\n'
		last_index=$((${#release_files[@]} - 1))
		for index in "${!release_files[@]}"; do
			logical=${release_files[$index]}
			path=$(release_file_path "$base" "$layout" "$logical")
			if [[ ! -f $path || -L $path ]]; then
				echo "install-node: release is missing regular file $logical" >&2
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

verify_release() {
	local base=$1 layout=$2 expected_tmp manifest_version file_count
	local manifest="$base/release.json"
	if [[ ! -f $manifest || -L $manifest ]]; then
		echo "install-node: release is missing regular file release.json" >&2
		return 2
	fi
	manifest_version=$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' "$manifest")
	if [[ $manifest_version != "$expected_version" ]]; then
		echo "install-node: release.json reports '${manifest_version:-<invalid>}', expected '$expected_version'" >&2
		return 2
	fi
	expected_tmp=$(mktemp)
	if ! write_canonical_manifest "$base" "$layout" "$expected_tmp"; then
		rm -f "$expected_tmp"
		return 2
	fi
	if ! cmp -s "$manifest" "$expected_tmp"; then
		rm -f "$expected_tmp"
		echo "install-node: release.json does not match the target or release files" >&2
		return 2
	fi
	rm -f "$expected_tmp"
	if [[ $layout == installed ]]; then
		if find "$base" -mindepth 1 -type l -print -quit | grep -q . || \
			find "$base" -mindepth 1 ! -type f ! -type d -print -quit | grep -q .; then
			echo "install-node: immutable release contains a symlink or special file" >&2
			return 2
		fi
		file_count=$(find "$base" -mindepth 1 -type f | wc -l)
		if [[ $file_count -ne $((${#release_files[@]} + 1)) ]]; then
			echo "install-node: immutable release contains unexpected files" >&2
			return 2
		fi
	fi
}

# Validate the release identity, target, complete file set, and every digest
# before creating users or writing anything to the host.
if ! validate_release_source_tree "$root"; then
	echo "install-node: release source and every ancestor must be root-owned and non-writable; files must be one-link regular files within size bounds" >&2
	exit 2
fi
verify_release "$root" source

acquire_host_role_lock
if [[ -e $node_role_claim_directory || -L $node_role_claim_directory ]]; then
	validate_node_role_claim || {
		echo "install-node: refusing unsafe durable node-role reservation state" >&2
		exit 2
	}
fi
if control_plane_marker=$(find_deployed_control_plane_marker \
	/opt/steward-control \
	/etc/steward-control \
	/var/lib/steward-control-installer \
	/etc/systemd/system/steward-control.service \
	/usr/local/libexec/steward-control); then
	echo "install-node: refusing to install a node over the deployed Steward control plane marker $control_plane_marker" >&2
	echo "  Run Steward Control and Steward nodes on separate management hosts; both products own /usr/local/bin/steward-control." >&2
	exit 2
fi
acquire_node_lock

getent_one group docker >/dev/null || {
	echo "install-node: Docker group is missing; install Docker before Steward" >&2
	exit 2
}
for group in steward steward-executor steward-gateway steward-relay; do
	lookup_status=0
	getent_one group "$group" >/dev/null || lookup_status=$?
	if (( lookup_status == 0 )); then
		continue
	fi
	if (( lookup_status != 1 )); then
		echo "install-node: refusing to create group '$group' after an unsafe or failed NSS lookup" >&2
		exit 2
	fi
	timeout --signal=TERM --kill-after=5 30 groupadd --system "$group"
done

docker_gid=$(validate_managed_group docker)
steward_gid=$(validate_managed_group steward)
executor_gid=$(validate_managed_group steward-executor)
gateway_gid=$(validate_managed_group steward-gateway)
relay_gid=$(validate_managed_group steward-relay)
if [[ $(printf '%s\n' "$docker_gid" "$steward_gid" "$executor_gid" "$gateway_gid" "$relay_gid" | sort -n -u | wc -l) -ne 5 ]]; then
	echo "install-node: Docker and Steward service groups must have distinct GIDs" >&2
	exit 2
fi

if [[ -x /usr/sbin/nologin ]]; then
	nologin_shell=/usr/sbin/nologin
elif [[ -x /sbin/nologin ]]; then
	nologin_shell=/sbin/nologin
elif [[ -x /usr/bin/false ]]; then
	nologin_shell=/usr/bin/false
else
	echo "install-node: a system nologin or false shell is required" >&2
	exit 2
fi

for user_specification in \
	'steward steward /var/lib/steward -' \
	'steward-executor steward-executor /var/lib/steward-executor docker' \
	'steward-gateway steward-gateway /var/lib/steward-gateway steward-executor,steward-relay'; do
	read -r user primary_group user_home supplemental_groups <<<"$user_specification"
	lookup_status=0
	getent_one passwd "$user" >/dev/null || lookup_status=$?
	if (( lookup_status == 0 )); then
		continue
	fi
	if (( lookup_status != 1 )); then
		echo "install-node: refusing to create user '$user' after an unsafe or failed NSS lookup" >&2
		exit 2
	fi
	useradd_arguments=(--system --no-create-home --gid "$primary_group" --home-dir "$user_home" --shell "$nologin_shell")
	if [[ $supplemental_groups != - ]]; then
		useradd_arguments+=(--groups "$supplemental_groups")
	fi
	timeout --signal=TERM --kill-after=5 30 useradd "${useradd_arguments[@]}" "$user"
done

validate_service_identity steward steward /var/lib/steward steward
validate_service_identity steward-executor steward-executor /var/lib/steward-executor \
	steward-executor docker
validate_service_identity steward-gateway steward-gateway /var/lib/steward-gateway \
	steward-gateway steward-executor steward-relay
validate_group_members steward
validate_group_members steward-executor steward-gateway
validate_group_members steward-gateway
validate_group_members steward-relay steward-gateway
validate_group_members docker steward-executor
validate_primary_group_users "$steward_gid" steward
validate_primary_group_users "$executor_gid" steward-executor
validate_primary_group_users "$gateway_gid" steward-gateway
validate_primary_group_users "$relay_gid"
validate_primary_group_users "$docker_gid"
steward_uid=$(timeout --signal=TERM --kill-after=2 5 id -u steward)
executor_uid=$(timeout --signal=TERM --kill-after=2 5 id -u steward-executor)
gateway_uid=$(timeout --signal=TERM --kill-after=2 5 id -u steward-gateway)
if (( steward_uid == 0 || executor_uid == 0 || gateway_uid == 0 )) || \
	(( steward_uid == executor_uid || steward_uid == gateway_uid || executor_uid == gateway_uid )); then
	echo "install-node: Steward service identities must be distinct non-root users" >&2
	exit 2
fi
for docker_socket in /run/docker.sock /var/run/docker.sock; do
	if [[ -e $docker_socket || -L $docker_socket ]]; then
		if [[ ! -S $docker_socket || -L $docker_socket || $(stat -c %g -- "$docker_socket") != "$docker_gid" ]]; then
			echo "install-node: $docker_socket must be a socket owned by the Docker group" >&2
			exit 2
		fi
	fi
done
if [[ -e /run/docker.sock && -e /var/run/docker.sock &&
	$(stat -c '%d:%i' -- /run/docker.sock) != "$(stat -c '%d:%i' -- /var/run/docker.sock)" ]]; then
	echo "install-node: /run/docker.sock and /var/run/docker.sock resolve to different sockets" >&2
	exit 2
fi

# Run the archive's binaries only as the unprivileged lifecycle identity, which is
# forbidden from the Docker group. The installer itself is trusted only after the
# operator's out-of-band bundle check; this still avoids granting a malformed binary
# root merely to read its version.
ensure_managed_directory /opt root root 0755 false || {
	echo "install-node: refusing an unsafe /opt directory" >&2
	exit 2
}
ensure_managed_directory /opt/steward root root 0755 true || {
	echo "install-node: refusing an unsafe /opt/steward directory" >&2
	exit 2
}
ensure_managed_directory /opt/steward/releases root root 0755 true || {
	echo "install-node: refusing an unsafe /opt/steward/releases directory" >&2
	exit 2
}
incoming=$(mktemp -d /opt/steward/.incoming.XXXXXX)
trap 'rm -rf "$incoming"' EXIT
chmod 0755 "$incoming"
for binary in steward steward-control stewardctl steward-mcp steward-executor steward-gateway steward-relay; do
	install -o root -g root -m 0755 "$root/$binary" "$incoming/$binary"
done
install -d -o root -g root -m 0755 "$incoming/integration" \
	"$incoming/integration/adapters" "$incoming/integration/adapters/hermes-agent" \
	"$incoming/integration/adapters/hermes-agent/fixtures" \
	"$incoming/integration/adapters/hermes-agent/fixtures/connector-skill" \
	"$incoming/integration/adapters/hermes-agent/fixtures/skill" \
	"$incoming/integration/deploy" "$incoming/integration/deploy/config" \
	"$incoming/integration/deploy/systemd" "$incoming/integration/scripts"
for file in Dockerfile README.md adapter.json entrypoint.py fixture_connector.py fixture_mcp.py \
	fixture_model.py fixture_secret_scan.py license-inventory.json source-inputs.sha256; do
	install -o root -g root -m 0644 "$root/adapters/hermes-agent/$file" \
		"$incoming/integration/adapters/hermes-agent/$file"
done
for file in SKILL.md connector-fixture-contract.json connector_work.py manifest.json manifest.sig public.pem; do
	install -o root -g root -m 0644 "$root/adapters/hermes-agent/fixtures/connector-skill/$file" \
		"$incoming/integration/adapters/hermes-agent/fixtures/connector-skill/$file"
done
for file in SKILL.md manifest.json manifest.sig public.pem workspace-fixture-contract.json \
	workspace_audit.py; do
	install -o root -g root -m 0644 "$root/adapters/hermes-agent/fixtures/skill/$file" \
		"$incoming/integration/adapters/hermes-agent/fixtures/skill/$file"
done
for file in deploy/config/executor-gateway.env deploy/config/executor.env \
	deploy/config/gateway.json.in deploy/config/steward-local.json deploy/config/steward.json \
	deploy/systemd/steward-executor.service deploy/systemd/steward-gateway.service \
	deploy/systemd/steward.service; do
	install -o root -g root -m 0644 "$root/$file" "$incoming/integration/$file"
done
for script in activate-node-release.sh build-hermes-adapter.sh build-relay-image.sh configure-admission.sh \
	configure-node.sh hermes-feasibility.sh hermes-steward-acceptance.sh install-node.sh node-doctor.sh node-preflight.sh node-removal-guard.sh \
	uninstall-node.sh; do
	install -o root -g root -m 0755 "$root/scripts/$script" "$incoming/integration/scripts/$script"
done
install -o root -g root -m 0644 "$root/release.json" "$incoming/release.json"
verify_release "$incoming" installed

steward_version=$(timeout --signal=TERM --kill-after=2 5 runuser -u steward -- "$incoming/steward" -version | awk '{print $2}')
control_version=$(timeout --signal=TERM --kill-after=2 5 runuser -u steward -- "$incoming/steward-control" -version | awk '{print $2}')
ctl_version=$(timeout --signal=TERM --kill-after=2 5 runuser -u steward -- "$incoming/stewardctl" -version | awk '{print $2}')
executor_version=$(timeout --signal=TERM --kill-after=2 5 runuser -u steward -- "$incoming/steward-executor" -version | awk '{print $2}')
gateway_version=$(timeout --signal=TERM --kill-after=2 5 runuser -u steward -- "$incoming/steward-gateway" -version | awk '{print $2}')
relay_version=$(timeout --signal=TERM --kill-after=2 5 runuser -u steward -- "$incoming/steward-relay" -version | awk '{print $2}')
mcp_version=$(timeout --signal=TERM --kill-after=2 5 runuser -u steward -- "$incoming/steward-mcp" -version | awk '{print $2}')
if [[ -z $steward_version || $steward_version != "$control_version" || $steward_version != "$executor_version" || $steward_version != "$ctl_version" || \
	$steward_version != "$gateway_version" || $steward_version != "$relay_version" || $steward_version != "$mcp_version" ]]; then
	echo "install-node: Steward process versions do not match" >&2
	exit 2
fi
if [[ $steward_version != "$expected_version" ]]; then
	echo "install-node: binaries report '$steward_version', expected '$expected_version'" >&2
	exit 2
fi

release_dir="/opt/steward/releases/$expected_version"
if [[ -e $release_dir || -L $release_dir ]]; then
	[[ -d $release_dir && ! -L $release_dir ]] || {
		echo "install-node: existing release path is not a directory: $release_dir" >&2
		exit 2
	}
	verify_release "$release_dir" installed
	if ! cmp -s "$incoming/release.json" "$release_dir/release.json"; then
		echo "install-node: refusing to rewrite immutable release $expected_version" >&2
		exit 2
	fi
	rm -rf "$incoming"
else
	mv "$incoming" "$release_dir"
fi
trap - EXIT
for specification in \
	'/etc root root 0755 false' \
	'/etc/steward root root 0755 true' \
	'/usr root root 0755 false' \
	'/usr/local root root 0755 false' \
	'/usr/local/bin root root 0755 false' \
	'/usr/local/libexec root root 0755 false' \
	'/usr/local/libexec/steward root root 0755 true' \
	'/usr/local/lib root root 0755 false' \
	'/usr/local/lib/systemd root root 0755 false' \
	'/usr/local/lib/systemd/system root root 0755 true' \
	'/var root root 0755 false' \
	'/var/lib root root 0755 false' \
	'/var/log root root 0755 false' \
	'/var/lib/steward steward steward 0700 true' \
	'/var/log/steward steward steward 0700 true' \
	'/var/lib/steward-executor steward-executor steward-executor 0700 true' \
	'/var/lib/steward-gateway steward-gateway steward-gateway 0700 true' \
	'/var/lib/steward-node root root 0700 true' \
	'/var/lib/steward-node/relay-images root root 0700 true'; do
	read -r directory owner group directory_mode exact_mode <<<"$specification"
	ensure_managed_directory "$directory" "$owner" "$group" "$directory_mode" "$exact_mode" || {
		echo "install-node: refusing unsafe ownership, mode, or links at $directory" >&2
		exit 2
	}
done

release_config="$release_dir/integration/deploy/config"
release_units="$release_dir/integration/deploy/systemd"

install_default_config_atomic "$release_config/steward.json" \
	/etc/steward/steward.json root steward 0640
install_default_config_atomic "$release_config/executor.env" \
	/etc/steward/executor.env root root 0600
install_default_config_atomic "$release_config/executor-gateway.env" \
	/etc/steward/executor-gateway.env root root 0600
ensure_gateway_service_token /etc/steward /var/lib/steward-node \
	steward-gateway steward-gateway
ensure_connector_receipt_keypair "$release_dir" /etc/steward /var/lib/steward-node \
	steward-gateway steward-gateway
machine_id=unused
if [[ ! -e /etc/steward/gateway.json && ! -L /etc/steward/gateway.json ]]; then
	machine_id=$(read_machine_id) || {
		echo "install-node: /etc/machine-id must be a bounded, root-owned regular machine ID" >&2
		exit 2
	}
fi
install_gateway_config_atomic "$release_config/gateway.json.in" \
	/etc/steward/gateway.json "$executor_gid" "$relay_gid" "$machine_id"

reconcile_selected_release=false
first_install=false
if [[ -e /opt/steward/current || -L /opt/steward/current ]]; then
	current_target=$(readlink /opt/steward/current 2>/dev/null || true)
	case "$current_target" in
	/opt/steward/releases/*)
		current_version=${current_target#/opt/steward/releases/}
		[[ $current_version != */* ]] && valid_release_version "$current_version" &&
			[[ -d $current_target && ! -L $current_target &&
				$(readlink -e -- "$current_target" 2>/dev/null) == "$current_target" ]] || {
			echo "install-node: active release target is missing or invalid: $current_target" >&2
			exit 2
		}
		;;
	*)
		echo "install-node: refusing unmanaged /opt/steward/current" >&2
		exit 2
		;;
	esac
	if [[ $current_target == "$release_dir" ]]; then
		reconcile_selected_release=true
		selection="selected; reconciled the active release entry points"
	else
		selection="staged; the active release was not changed"
	fi
else
	reconcile_selected_release=true
	first_install=true
	selection="selected for first-time configuration"
fi

if [[ $reconcile_selected_release == true ]]; then
	# Installation may repair only an already-correct managed symlink. Any
	# unrelated file at a stable entry point belongs to the operator and is not
	# replaced implicitly.
	validate_managed_symlink_slot /opt/steward/current "$release_dir" || {
		echo "install-node: refusing unmanaged /opt/steward/current publication state" >&2
		exit 2
	}
	for binary in steward steward-control stewardctl steward-mcp steward-executor steward-gateway steward-relay; do
		path="/usr/local/bin/$binary"
		validate_managed_symlink_slot "$path" "/opt/steward/current/$binary" || {
			echo "install-node: refusing to replace unmanaged $path" >&2
			exit 2
		}
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
		path="/usr/local/libexec/steward/$name"
		validate_managed_symlink_slot "$path" "$target" || {
			echo "install-node: refusing to replace unmanaged $path" >&2
			exit 2
		}
	done
	for unit in steward.service steward-executor.service steward-gateway.service; do
		path="/usr/local/lib/systemd/system/$unit"
		target="/opt/steward/current/integration/deploy/systemd/$unit"
		validate_managed_symlink_slot "$path" "$target" || {
			echo "install-node: refusing to replace unmanaged $path" >&2
			exit 2
		}
		legacy="/etc/systemd/system/$unit"
		if [[ -e $legacy || -L $legacy ]]; then
			if [[ -f $legacy && ! -L $legacy ]] && cmp -s "$legacy" "$release_units/$unit"; then
				:
			else
				echo "install-node: refusing modified $legacy because it shadows the packaged vendor unit" >&2
				echo "  Preserve local settings in /etc/systemd/system/$unit.d/*.conf, then remove the full-unit override and re-run." >&2
				exit 2
			fi
		fi
	done

	ensure_managed_symlink /opt/steward/current "$release_dir" || {
		echo "install-node: could not publish /opt/steward/current" >&2
		exit 2
	}

	for binary in steward steward-control stewardctl steward-mcp steward-executor steward-gateway steward-relay; do
		ensure_managed_symlink "/usr/local/bin/$binary" "/opt/steward/current/$binary" || {
			echo "install-node: could not publish /usr/local/bin/$binary" >&2
			exit 2
		}
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
		ensure_managed_symlink "/usr/local/libexec/steward/$name" "$target" || {
			echo "install-node: could not publish /usr/local/libexec/steward/$name" >&2
			exit 2
		}
	done
	for unit in steward.service steward-executor.service steward-gateway.service; do
		legacy="/etc/systemd/system/$unit"
		if [[ -e $legacy || -L $legacy ]]; then
			rm -f "$legacy"
			echo "install-node: migrated legacy installer-owned $legacy"
		fi
		ensure_managed_symlink "/usr/local/lib/systemd/system/$unit" \
			"/opt/steward/current/integration/deploy/systemd/$unit" || {
			echo "install-node: could not publish /usr/local/lib/systemd/system/$unit" >&2
			exit 2
		}
	done
	systemctl daemon-reload
fi

clear_node_role_claim
echo "install-node: installed Steward $expected_version ($selection)"
echo "install-node: service enablement and active state were not changed"
if [[ $first_install == true ]]; then
	echo "install-node: install customer credentials and CA material, initialize the Executor fence, then run:"
	echo "  /usr/local/libexec/steward/node-preflight"
	echo "  systemctl enable --now steward-gateway steward steward-executor"
	echo "  /usr/local/libexec/steward/node-doctor"
	elif [[ $selection == staged* ]]; then
	echo "install-node: activate after provisioning trust material (activation runs full preflight):"
	echo "  $release_dir/integration/scripts/activate-node-release.sh $expected_version --restart"
else
	echo "install-node: the active release and its stable entry points are complete"
fi
