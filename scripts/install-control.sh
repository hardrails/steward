#!/bin/bash -p
# Install or transactionally upgrade the Steward fleet control plane.
set -Eeuo pipefail
set +x
if ! shopt -qo privileged; then
	echo "install-control: invoke this installer with /bin/bash -p so caller-controlled shell startup files and exported functions are ignored" >&2
	exit 2
fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C LANG=C
unset BASH_ENV CDPATH CURL_CA_BUNDLE ENV GLOBIGNORE SSL_CERT_DIR SSL_CERT_FILE \
	TAR_OPTIONS GZIP POSIXLY_CORRECT
IFS=$' \t\n'
umask 077

readonly project_url=https://github.com/hardrails/steward
readonly release_url="$project_url/releases"
readonly service_user=steward-control
readonly service_group=steward-control
readonly state_dir=/var/lib/steward-control
readonly witness_private_key=$state_dir/witness.private.pem
readonly witness_public_key=$state_dir/witness.public.pem
readonly controller_private_key=$state_dir/controller.private.pem
readonly controller_public_key=$state_dir/controller.public.pem
readonly controller_key_id=controller-default
readonly reconcile_interval=5s
readonly config_dir=/etc/steward-control
readonly config_file=$config_dir/control.env
readonly releases_dir=/opt/steward-control/releases
readonly current_link=/opt/steward-control/current
readonly binary_link=/usr/local/bin/steward-control
readonly doctor_link=/usr/local/libexec/steward-control/control-doctor
readonly unit_link=/etc/systemd/system/steward-control.service
readonly tls_cert_dest=$config_dir/tls.crt
readonly tls_key_dest=$config_dir/tls.key
readonly installer_state_dir=/var/lib/steward-control-installer
readonly installer_transaction=$installer_state_dir/transaction
readonly installer_runtime_dir=/run/steward-control-installer
readonly installer_lock_file=$installer_runtime_dir/install.lock
readonly host_role_runtime_dir=/run/steward-host-role
readonly host_role_lock_file=$host_role_runtime_dir/role.lock

usage() {
	cat <<'EOF'
Install Steward Control on a systemd Linux server.

Usage:
  curl --proto '=https' --tlsv1.2 -fsSL \
    https://github.com/hardrails/steward/releases/latest/download/install-control.sh | sudo /bin/bash -p
  sudo /bin/bash -p install-control.sh --non-interactive --offline-dir DIR \
    --admin-token-out /root/steward-control-admin.token

Artifact source:
  --version VERSION          Release tag (default: latest)
  --offline-dir DIR          Directory containing checksums.txt and the control archive
  --artifact FILE            Exact steward-control Linux archive
  --checksums FILE           SHA-256 manifest (defaults beside a local archive)

Listener and bootstrap:
  --addr HOST:PORT           Listen address (default: 127.0.0.1:8443)
  --tls-cert FILE            TLS certificate PEM; required with --tls-key
  --tls-key FILE             Owner-only TLS private key PEM
  --clear-tls                Remove preserved TLS configuration on a loopback listener
  --admin-token-out FILE     First-install/recovery token path; never overwritten

Operations:
  --authority-mode MODE       bounded-autonomous (default) or strict-sovereign
  --enable-metrics           Expose authenticated Prometheus metrics
  --disable-metrics          Disable Prometheus metrics (default)
  --node-stale-after DURATION
                             Active-node attention threshold (default: 2m)
  --evidence-stale-after DURATION
                             Evidence-report attention threshold (default: 5m)
  --command-overdue-after DURATION
                             Pending-command attention threshold (default: 5m)
  --capacity-warning-percent PERCENT
                             Capacity attention threshold (default: 80)

Automation and inspection:
  --non-interactive          Never prompt
  --yes, -y                  Accept the interactive confirmation
  --no-start                 Install and validate without starting the service
  --dry-run                  Print the resolved plan without downloads or changes
  -h, --help                 Show this help

Environment equivalents: STEWARD_CONTROL_VERSION, STEWARD_CONTROL_OFFLINE_DIR,
STEWARD_CONTROL_ARTIFACT, STEWARD_CONTROL_CHECKSUMS, STEWARD_CONTROL_ADDR,
STEWARD_CONTROL_TLS_CERT, STEWARD_CONTROL_TLS_KEY, and
STEWARD_CONTROL_ADMIN_TOKEN_OUT. Operations equivalents are
STEWARD_CONTROL_AUTHORITY_MODE, STEWARD_CONTROL_ENABLE_METRICS, STEWARD_CONTROL_NODE_STALE_AFTER,
STEWARD_CONTROL_EVIDENCE_STALE_AFTER, STEWARD_CONTROL_COMMAND_OVERDUE_AFTER,
and STEWARD_CONTROL_CAPACITY_WARNING_PERCENT.

The safe default listens only on loopback. A non-loopback address is rejected
unless both TLS files are supplied or an existing validated TLS configuration is
preserved. There is no insecure remote-listener override.
EOF
}

version=${STEWARD_CONTROL_VERSION:-latest}
offline_dir=${STEWARD_CONTROL_OFFLINE_DIR:-}
artifact=${STEWARD_CONTROL_ARTIFACT:-}
checksums=${STEWARD_CONTROL_CHECKSUMS:-}
address=${STEWARD_CONTROL_ADDR:-}
tls_cert=${STEWARD_CONTROL_TLS_CERT:-}
tls_key=${STEWARD_CONTROL_TLS_KEY:-}
admin_token_out=${STEWARD_CONTROL_ADMIN_TOKEN_OUT:-}
authority_mode=${STEWARD_CONTROL_AUTHORITY_MODE:-}
enable_metrics=${STEWARD_CONTROL_ENABLE_METRICS:-}
node_stale_after=${STEWARD_CONTROL_NODE_STALE_AFTER:-}
evidence_stale_after=${STEWARD_CONTROL_EVIDENCE_STALE_AFTER:-}
command_overdue_after=${STEWARD_CONTROL_COMMAND_OVERDUE_AFTER:-}
capacity_warning_percent=${STEWARD_CONTROL_CAPACITY_WARNING_PERCENT:-}
address_set=false
[[ -z ${STEWARD_CONTROL_ADDR:-} ]] || address_set=true
authority_mode_set=false
[[ ${STEWARD_CONTROL_AUTHORITY_MODE+x} == x ]] && authority_mode_set=true
metrics_set=false
[[ ${STEWARD_CONTROL_ENABLE_METRICS+x} == x ]] && metrics_set=true
node_stale_set=false
[[ ${STEWARD_CONTROL_NODE_STALE_AFTER+x} == x ]] && node_stale_set=true
evidence_stale_set=false
[[ ${STEWARD_CONTROL_EVIDENCE_STALE_AFTER+x} == x ]] && evidence_stale_set=true
command_overdue_set=false
[[ ${STEWARD_CONTROL_COMMAND_OVERDUE_AFTER+x} == x ]] && command_overdue_set=true
capacity_warning_set=false
[[ ${STEWARD_CONTROL_CAPACITY_WARNING_PERCENT+x} == x ]] && capacity_warning_set=true
metrics_cli_choices=0
tls_supplied=false
[[ -z $tls_cert && -z $tls_key ]] || tls_supplied=true
clear_tls=false
non_interactive=false
assume_yes=false
start_service=true
dry_run=false

valid_release_version() {
	local candidate=$1 core prerelease identifier
	(( ${#candidate} <= 128 )) || return 1
	[[ $candidate =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$ ]] || return 1
	core=${candidate#v}
	if [[ $core == *-* ]]; then
		prerelease=${core#*-}
		IFS=. read -r -a identifiers <<<"$prerelease"
		for identifier in "${identifiers[@]}"; do
			if [[ $identifier =~ ^[0-9]+$ && $identifier == 0[0-9]* ]]; then return 1; fi
		done
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

clean_absolute_path() {
	local path=$1
	[[ $path == /* && $path != / && $(readlink -m -- "$path" 2>/dev/null) == "$path" ]]
}

trusted_root_directory_chain() {
	local directory=$1 current metadata uid mode
	[[ -d $directory && ! -L $directory && $(readlink -e -- "$directory" 2>/dev/null) == "$directory" ]] || return 1
	current=$directory
	while :; do
		metadata=$(stat -c '%u:%a' -- "$current") || return 1
		uid=${metadata%%:*}; mode=${metadata#*:}
		if [[ $uid != 0 ]] || (( (8#$mode & 022) != 0 )); then return 1; fi
		[[ $current == / ]] && break
		current=$(dirname -- "$current")
	done
}

ensure_root_managed_directory() {
	local path=$1 gid=$2 mode=$3 parent parent_before parent_after expected_mode
	expected_mode=${mode#0}
	if [[ ! -e $path && ! -L $path ]]; then
		parent=$(dirname -- "$path")
		trusted_root_directory_chain "$parent" || return 1
		parent_before=$(stat -c '%d:%i:%u:%g:%a' -- "$parent") || return 1
		install -d -m "$mode" -o root -g "$gid" -- "$path" || return 1
		parent_after=$(stat -c '%d:%i:%u:%g:%a' -- "$parent") || return 1
		[[ $parent_after == "$parent_before" ]] || return 1
	fi
	trusted_root_directory_chain "$path" &&
		[[ $(stat -c '%u:%g:%a' -- "$path") == "0:$gid:$expected_mode" ]]
}

validate_root_directory_destination() {
	local path=$1 existing=$1 parent
	while [[ ! -e $existing && ! -L $existing ]]; do
		parent=$(dirname -- "$existing")
		[[ $parent != "$existing" ]] || return 1
		existing=$parent
	done
	trusted_root_directory_chain "$existing" || return 1
	if [[ -e $path || -L $path ]]; then
		[[ -d $path && ! -L $path && $(readlink -e -- "$path" 2>/dev/null) == "$path" ]]
	fi
}

bounded_snapshot() {
	local source=$1 destination=$2 max_bytes=$3 timeout_seconds=$4
	local before after source_size output_blocks block_size=1048576 block_count
	[[ $max_bytes =~ ^[0-9]+$ && $timeout_seconds =~ ^[0-9]+$ ]] || return 1
	(( max_bytes > 0 && max_bytes % 1024 == 0 && timeout_seconds > 0 )) || return 1
	if [[ ! -f $source || -L $source ]]; then return 1; fi
	before=$(stat -c '%d:%i:%s:%u:%g:%a:%h:%y:%z' -- "$source") || return 1
	source_size=$(stat -c '%s' -- "$source") || return 1
	(( source_size > 0 && source_size <= max_bytes )) || return 1
	output_blocks=$((max_bytes / 1024))
	block_count=$(((max_bytes + block_size - 1) / block_size + 1))
	rm -f -- "$destination"
	if ! (
		exec 8>&- 9>&-
		set -o noclobber
		exec >"$destination"
		ulimit -c 0
		ulimit -f "$output_blocks"
		exec timeout --signal=TERM --kill-after=5 "$timeout_seconds" \
			dd if="$source" bs="$block_size" count="$block_count" \
			iflag=nofollow,nonblock,fullblock status=none
	); then
		rm -f -- "$destination"
		return 1
	fi
	after=$(stat -c '%d:%i:%s:%u:%g:%a:%h:%y:%z' -- "$source") || { rm -f -- "$destination"; return 1; }
	if [[ $before != "$after" || ! -f $destination || -L $destination ||
		$(stat -c '%u:%g:%a:%h:%s' -- "$destination") != "0:0:600:1:$source_size" ]]; then
		rm -f -- "$destination"
		return 1
	fi
}

bounded_identity_query() {
	local variable=$1 label=$2 output error status=0 metadata size
	local -a lines=()
	shift 2
	[[ $variable =~ ^[A-Za-z_][A-Za-z0-9_]*$ && $label =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
	[[ -d $installer_runtime_dir && ! -L $installer_runtime_dir &&
		$(stat -c '%u:%g:%a' -- "$installer_runtime_dir") == 0:0:700 ]] || return 1
	output=$(mktemp "$installer_runtime_dir/identity.$label.stdout.XXXXXX") || return 1
	error=$(mktemp "$installer_runtime_dir/identity.$label.stderr.XXXXXX") || { rm -f -- "$output"; return 1; }
	if (
		exec 8>&- 9>&-
		ulimit -c 0
		ulimit -f 64
		exec timeout --signal=TERM --kill-after=2 15 "$@"
	) >"$output" 2>"$error"; then
		status=0
	else
		status=$?
	fi
	IDENTITY_QUERY_STATUS=$status
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

validate_local_source() {
	local path=$1 max_bytes=$2 parent metadata uid mode links size
	clean_absolute_path "$path" && [[ -f $path && ! -L $path && $(readlink -e -- "$path" 2>/dev/null) == "$path" ]] || return 1
	parent=$(dirname -- "$path")
	trusted_root_directory_chain "$parent" || return 1
	metadata=$(stat -c '%u:%a:%h:%s' -- "$path") || return 1
	IFS=: read -r uid mode links size <<<"$metadata"
	[[ $uid == 0 && $links == 1 ]] || return 1
	(( size > 0 && size <= max_bytes && (8#$mode & 022) == 0 ))
}

journal_regular() {
	local path=$1 max_bytes=$2 size
	[[ -f $path && ! -L $path && $(stat -c '%u:%g:%a:%h' -- "$path" 2>/dev/null) == 0:0:600:1 ]] || return 1
	size=$(stat -c '%s' -- "$path") || return 1
	(( size >= 0 && size <= max_bytes ))
}

read_journal_value() {
	local path=$1 max_bytes=$2
	local -a lines=()
	journal_regular "$path" "$max_bytes" || return 1
	mapfile -t lines <"$path"
	(( ${#lines[@]} == 1 )) || return 1
	printf '%s' "${lines[0]}"
}

atomic_restore_file() {
	local snapshot=$1 absent=$2 destination=$3 uid=$4 gid=$5 mode=$6 temporary parent
	parent=$(dirname -- "$destination")
	temporary=$parent/.steward-control-recover.$$
	if [[ -e $snapshot || -L $snapshot ]]; then
		[[ ! -e $absent && ! -L $absent && -f $snapshot && ! -L $snapshot && $(stat -c '%h' -- "$snapshot") == 1 ]] || return 1
		rm -f -- "$temporary"
		install -m "$mode" -o "$uid" -g "$gid" "$snapshot" "$temporary" || return 1
		sync -f "$temporary" || return 1
		mv -Tf -- "$temporary" "$destination" || return 1
	elif journal_regular "$absent" 0; then
		rm -f -- "$destination" || return 1
	else
		return 1
	fi
	sync -f "$parent"
}

atomic_restore_link() {
	local name=$1 destination=$2 link_marker
	local absent_marker=$installer_transaction/$name.absent target temporary parent
	link_marker=$installer_transaction/$name.link
	parent=$(dirname -- "$destination")
	temporary=$parent/.steward-control-link.$$
	if [[ -L $link_marker && ! -e $absent_marker && ! -L $absent_marker ]]; then
		target=$(readlink -- "$link_marker") || return 1
		rm -f -- "$temporary"
		ln -s -- "$target" "$temporary" || return 1
		mv -Tf -- "$temporary" "$destination" || return 1
	elif journal_regular "$absent_marker" 0 && [[ ! -e $link_marker && ! -L $link_marker ]]; then
		rm -f -- "$destination" || return 1
	else
		return 1
	fi
	sync -f "$parent"
}

wait_for_control_store_unlock() {
	local expected_uid=$1 expected_gid=$2 lock_file=$state_dir/LOCK
	local metadata
	if [[ ! -e $lock_file && ! -L $lock_file ]]; then return 0; fi
	if [[ ! -f $lock_file || -L $lock_file ]]; then return 1; fi
	metadata=$(stat -c '%u:%g:%a:%h' -- "$lock_file") || return 1
	[[ $metadata == "$expected_uid:$expected_gid:600:1" ]] || return 1
	for _ in {1..400}; do
		if (
			exec 8>&- 9>&-
			exec 7<>"$lock_file" || exit 1
			[[ $(stat -Lc '%u:%g:%a:%h' -- /proc/$BASHPID/fd/7) == "$expected_uid:$expected_gid:600:1" ]] || exit 1
			flock -n 7
		); then
			return 0
		fi
		sleep 0.05
	done
	echo "install-control: timed out waiting for a prior controller writer to release durable state" >&2
	return 1
}

bounded_systemctl() {
	timeout --signal=TERM --kill-after=2 15 systemctl "$@"
}

snapshot_control_service_state() {
	local activity activity_status=0 enablement enablement_status=0
	activity=$(bounded_systemctl is-active steward-control.service 2>/dev/null) || activity_status=$?
	enablement=$(bounded_systemctl is-enabled steward-control.service 2>/dev/null) || enablement_status=$?

	case "$activity" in
		active)
			(( activity_status == 0 )) || {
				echo "install-control: systemd reported an inconsistent active state for steward-control.service" >&2
				return 1
			}
			service_was_active=true
			;;
		inactive)
			(( activity_status != 0 )) || {
				echo "install-control: systemd reported an inconsistent inactive state for steward-control.service" >&2
				return 1
			}
			service_was_active=false
			;;
		unknown)
			(( activity_status != 0 )) || return 1
			service_was_active=false
			;;
		*)
			echo "install-control: could not determine the exact activity state of steward-control.service" >&2
			return 1
			;;
	esac

	case "$enablement" in
		enabled)
			(( enablement_status == 0 )) || {
				echo "install-control: systemd reported an inconsistent enabled state for steward-control.service" >&2
				return 1
			}
			service_was_enabled=true
			;;
		disabled)
			(( enablement_status != 0 )) || {
				echo "install-control: systemd reported an inconsistent disabled state for steward-control.service" >&2
				return 1
			}
			service_was_enabled=false
			;;
		not-found)
			(( enablement_status != 0 )) || return 1
			service_was_enabled=false
			;;
		*)
			echo "install-control: could not determine the exact enablement state of steward-control.service" >&2
			return 1
			;;
	esac

	if [[ $activity == unknown && $enablement != not-found ]] ||
		[[ $enablement == not-found && $activity == active ]]; then
		echo "install-control: systemd reported inconsistent activity and enablement states for steward-control.service" >&2
		return 1
	fi
}

recover_new_admin_token() {
	local destination=$1 expected_digest=${2:-} parent destination_id candidate metadata
	local destination_links destination_inode candidate_inode candidate_digest candidate_size
	local -a candidates=() removals=()
	parent=$(dirname -- "$destination")
	trusted_root_directory_chain "$parent" || return 1
	destination_id=$(printf '%s' "$destination" | sha256sum | awk '{print $1}') || return 1
	[[ $destination_id =~ ^[0-9a-f]{64}$ ]] || return 1
	shopt -s nullglob
	candidates=("$parent/.steward-control-admin-token.$destination_id."*)
	shopt -u nullglob
	(( ${#candidates[@]} <= 1 )) || return 1
	# Token publication starts only after the digest file is durably synced. If
	# there is no digest, no path can be attributed to this transaction. Preserve
	# any root-created path and finish rolling back the state the journal does own.
	if [[ -z $expected_digest ]]; then
		return 0
	fi
	[[ $expected_digest =~ ^[0-9a-f]{64}$ ]] || return 1
	if [[ -e $destination || -L $destination ]]; then
		# Remove the destination only when its metadata and digest prove that it
		# is the token published by this transaction. A destination that raced the
		# exclusive link is caller-owned and must survive rollback.
		if [[ -f $destination && ! -L $destination ]]; then
			metadata=$(stat -c '%u:%g:%a:%h:%s' -- "$destination") || return 1
			if [[ $metadata =~ ^0:0:600:([12]):([0-9]+)$ ]] &&
				(( BASH_REMATCH[2] > 0 && BASH_REMATCH[2] <= 4096 )) &&
				[[ $(sha256sum -- "$destination" | awk '{print $1}') == "$expected_digest" ]]; then
				destination_links=${BASH_REMATCH[1]}
				if [[ $destination_links == 2 ]]; then
					(( ${#candidates[@]} == 1 )) || return 1
					candidate=${candidates[0]}
					[[ -f $candidate && ! -L $candidate ]] || return 1
					metadata=$(stat -c '%u:%g:%a:%h:%s' -- "$candidate") || return 1
					[[ $metadata =~ ^0:0:600:2:([0-9]+)$ ]] || return 1
					(( BASH_REMATCH[1] > 0 && BASH_REMATCH[1] <= 4096 )) || return 1
					candidate_digest=$(sha256sum -- "$candidate" | awk '{print $1}') || return 1
					[[ $candidate_digest == "$expected_digest" ]] || return 1
					destination_inode=$(stat -c '%d:%i' -- "$destination") || return 1
					candidate_inode=$(stat -c '%d:%i' -- "$candidate") || return 1
					[[ $candidate_inode == "$destination_inode" ]] || return 1
					removals+=("$candidate")
				elif (( ${#candidates[@]} != 0 )); then
					return 1
				fi
				removals+=("$destination")
			fi
		fi
		if (( ${#removals[@]} == 0 && ${#candidates[@]} == 1 )); then
			candidate=${candidates[0]}
			[[ -f $candidate && ! -L $candidate ]] || return 1
			metadata=$(stat -c '%u:%g:%a:%h:%s' -- "$candidate") || return 1
			[[ $metadata =~ ^0:0:600:1:([0-9]+)$ ]] || return 1
			candidate_size=${BASH_REMATCH[1]}
			(( candidate_size <= 4096 )) || return 1
			removals+=("$candidate")
		fi
	elif (( ${#candidates[@]} == 1 )); then
		candidate=${candidates[0]}
		[[ -f $candidate && ! -L $candidate ]] || return 1
		metadata=$(stat -c '%u:%g:%a:%h:%s' -- "$candidate") || return 1
		[[ $metadata =~ ^0:0:600:1:([0-9]+)$ ]] || return 1
		candidate_size=${BASH_REMATCH[1]}
		(( candidate_size <= 4096 )) || return 1
		# Before the exclusive destination link exists, this root-owned reserved
		# name is only an incomplete installer staging file. It may be empty or
		# partially copied after SIGKILL and has not been published as authority.
		removals+=("$candidate")
	fi
	if (( ${#removals[@]} > 0 )); then
		rm -f -- "${removals[@]}" || return 1
		sync -f "$parent" || return 1
	fi
}

recover_durable_transaction() {
	local phase ids journal_uid journal_gid current_uid current_gid current_group_record state_kind state_meta
	local state_uid state_gid state_mode token_target token_digest='' new_dir=$installer_state_dir/transaction.new
	if [[ ! -e $installer_state_dir && ! -L $installer_state_dir ]]; then return 0; fi
	if ! trusted_root_directory_chain "$installer_state_dir" ||
		[[ $(stat -c '%u:%g:%a' -- "$installer_state_dir" 2>/dev/null) != 0:0:700 ]]; then
		echo "install-control: durable installer state has unsafe metadata: $installer_state_dir" >&2
		return 1
	fi
	if [[ -e $new_dir || -L $new_dir ]]; then
		if [[ ! -d $new_dir || -L $new_dir || $(stat -c '%u:%g:%a' -- "$new_dir") != 0:0:700 ]]; then
			echo "install-control: incomplete durable transaction staging has unsafe metadata" >&2
			return 1
		fi
		rm -rf -- "$new_dir" || return 1
		sync -f "$installer_state_dir" || return 1
	fi
	if [[ ! -e $installer_transaction && ! -L $installer_transaction ]]; then
		if find "$installer_state_dir" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
			echo "install-control: durable installer state contains unrecognized entries" >&2
			return 1
		fi
		return 0
	fi
	if [[ ! -d $installer_transaction || -L $installer_transaction ||
		$(stat -c '%u:%g:%a' -- "$installer_transaction") != 0:0:700 ]]; then
		echo "install-control: durable transaction journal has unsafe metadata" >&2
		return 1
	fi
	phase=$(read_journal_value "$installer_transaction/phase" 32) || return 1
	if [[ $phase == committed ]]; then
		rm -rf -- "$installer_transaction" || return 1
		sync -f "$installer_state_dir" || return 1
		return 0
	fi
	[[ $phase == prepared ]] || { echo "install-control: durable transaction journal has an unknown phase" >&2; return 1; }
	ids=$(read_journal_value "$installer_transaction/service.ids" 64) || return 1
	[[ $ids =~ ^([0-9]+):([0-9]+)$ ]] || return 1
	journal_uid=${BASH_REMATCH[1]}; journal_gid=${BASH_REMATCH[2]}
	bounded_identity_query current_uid recovery-uid id -u "$service_user" || return 1
	bounded_identity_query current_group_record recovery-group getent group "$service_group" || return 1
	current_gid=${current_group_record#*:*:}
	current_gid=${current_gid%%:*}
	[[ $current_gid =~ ^[0-9]+$ ]] || return 1
	[[ $journal_uid == "$current_uid" && $journal_gid == "$current_gid" ]] || {
		echo "install-control: service identity changed while a durable transaction was pending" >&2; return 1;
	}
	if bounded_systemctl is-active --quiet steward-control.service; then bounded_systemctl stop steward-control.service || return 1; fi
	wait_for_control_store_unlock "$journal_uid" "$journal_gid" || return 1
	atomic_restore_link current "$current_link" || return 1
	atomic_restore_link binary "$binary_link" || return 1
	atomic_restore_link doctor "$doctor_link" || return 1
	atomic_restore_link unit "$unit_link" || return 1
	trusted_root_directory_chain "$config_dir" || return 1
	atomic_restore_file "$installer_transaction/config.file" "$installer_transaction/config.absent" \
		"$config_file" 0 0 0600 || return 1
	atomic_restore_file "$installer_transaction/tls-cert.file" "$installer_transaction/tls-cert.absent" \
		"$tls_cert_dest" 0 "$journal_gid" 0640 || return 1
	atomic_restore_file "$installer_transaction/tls-key.file" "$installer_transaction/tls-key.absent" \
		"$tls_key_dest" "$journal_uid" "$journal_gid" 0600 || return 1
	state_kind=$(read_journal_value "$installer_transaction/state.kind" 32) || return 1
	case "$state_kind" in
		absent)
			rm -rf -- "$state_dir" || return 1
			sync -f "$(dirname -- "$state_dir")" || return 1
			;;
		empty | present)
			state_meta=$(read_journal_value "$installer_transaction/state.meta" 64) || return 1
			[[ $state_meta =~ ^([0-9]+):([0-9]+):([0-7]{3,4})$ ]] || return 1
			state_uid=${BASH_REMATCH[1]}; state_gid=${BASH_REMATCH[2]}; state_mode=${BASH_REMATCH[3]}
			if [[ $state_kind == empty ]]; then
				if [[ -e $state_dir || -L $state_dir ]]; then [[ -d $state_dir && ! -L $state_dir ]] || return 1
				else install -d -m "$state_mode" -o "$state_uid" -g "$state_gid" "$state_dir" || return 1
				fi
				find "$state_dir" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + || return 1
			else
				[[ -d $state_dir && ! -L $state_dir ]] || return 1
			fi
			chown -hR "$state_uid:$state_gid" "$state_dir" || return 1
			chmod "$state_mode" "$state_dir" || return 1
			sync -f "$state_dir" || return 1
			;;
		*) return 1 ;;
	esac
	if [[ -L $installer_transaction/admin-token.intent ]]; then
		token_target=$(readlink -- "$installer_transaction/admin-token.intent") || return 1
		clean_absolute_path "$token_target" || return 1
		if [[ -e $installer_transaction/admin-token.digest || -L $installer_transaction/admin-token.digest ]]; then
			token_digest=$(read_journal_value "$installer_transaction/admin-token.digest" 64) || return 1
			[[ $token_digest =~ ^[0-9a-f]{64}$ ]] || return 1
		elif [[ -L $installer_transaction/admin-token.digest ]]; then
			return 1
		fi
		recover_new_admin_token "$token_target" "$token_digest" || {
			echo "install-control: durable recovery could not classify the administrator token publication" >&2
			return 1
		}
	elif [[ -e $installer_transaction/admin-token.intent ]]; then return 1
	fi
	bounded_systemctl daemon-reload || { echo "install-control: durable recovery daemon-reload failed" >&2; return 1; }
	if journal_regular "$installer_transaction/service.enabled" 0; then
		bounded_systemctl enable steward-control.service >/dev/null || return 1
	elif journal_regular "$installer_transaction/service.disabled" 0; then
		bounded_systemctl disable steward-control.service >/dev/null || return 1
	else echo "install-control: durable recovery has no valid prior service enablement marker" >&2; return 1
	fi
	if journal_regular "$installer_transaction/service.active" 0; then
		bounded_systemctl start steward-control.service || return 1
		bounded_systemctl is-active --quiet steward-control.service || return 1
	elif journal_regular "$installer_transaction/service.inactive" 0; then
		bounded_systemctl stop steward-control.service >/dev/null 2>&1 || true
	else echo "install-control: durable recovery has no valid prior service activity marker" >&2; return 1
	fi
	rm -rf -- "$installer_transaction" || return 1
	sync -f "$installer_state_dir" || return 1
	echo "install-control: recovered the previous controller state from an interrupted durable transaction" >&2
}

acquire_host_role_lock() {
	local run_metadata run_uid run_mode path_metadata fd_metadata process_id=${BASHPID:-$$}
	if [[ ! -d /run || -L /run || $(readlink -e -- /run 2>/dev/null) != /run ]]; then
		echo "install-control: refusing an unsafe /run directory" >&2
		return 1
	fi
	run_metadata=$(stat -c '%u:%a' -- /run) || return 1
	run_uid=${run_metadata%%:*}; run_mode=${run_metadata#*:}
	if [[ $run_uid != 0 ]] || (( (8#$run_mode & 022) != 0 )); then
		echo "install-control: /run must be root-owned and not group- or world-writable" >&2
		return 1
	fi
	if [[ -e $host_role_runtime_dir || -L $host_role_runtime_dir ]]; then
		if [[ ! -d $host_role_runtime_dir || -L $host_role_runtime_dir ||
			$(readlink -e -- "$host_role_runtime_dir" 2>/dev/null) != "$host_role_runtime_dir" ||
			$(stat -c '%u:%g:%a' -- "$host_role_runtime_dir" 2>/dev/null) != 0:0:700 ]]; then
			echo "install-control: shared host-role runtime directory has unsafe metadata" >&2
			return 1
		fi
	else
		install -d -o root -g root -m 0700 "$host_role_runtime_dir" || return 1
	fi
	if [[ -e $host_role_lock_file || -L $host_role_lock_file ]]; then
		if [[ ! -f $host_role_lock_file || -L $host_role_lock_file ||
			$(stat -c '%u:%g:%a:%h' -- "$host_role_lock_file" 2>/dev/null) != 0:0:600:1 ]]; then
			echo "install-control: shared host-role lock has unsafe metadata" >&2
			return 1
		fi
	else
		(umask 077; set -o noclobber; : >"$host_role_lock_file") 2>/dev/null || return 1
	fi
	exec 8<>"$host_role_lock_file"
	path_metadata=$(stat -c '%d:%i:%u:%g:%a:%h' -- "$host_role_lock_file") || return 1
	fd_metadata=$(stat -Lc '%d:%i:%u:%g:%a:%h' -- "/proc/$process_id/fd/8") || return 1
	if [[ $path_metadata != "$fd_metadata" || $path_metadata != *:0:0:600:1 ]]; then
		echo "install-control: opened shared host-role lock has unsafe metadata" >&2
		exec 8>&-
		return 1
	fi
	if ! flock -w 60 8; then
		echo "install-control: another Steward host-role lifecycle operation did not finish within 60 seconds" >&2
		exec 8>&-
		return 1
	fi
}

acquire_installer_lock() {
	local path_metadata fd_metadata process_id=${BASHPID:-$$}
	if [[ -e $installer_runtime_dir || -L $installer_runtime_dir ]]; then
		if [[ ! -d $installer_runtime_dir || -L $installer_runtime_dir ||
			$(readlink -e -- "$installer_runtime_dir" 2>/dev/null) != "$installer_runtime_dir" ||
			$(stat -c '%u:%g:%a' -- "$installer_runtime_dir" 2>/dev/null) != 0:0:700 ]]; then
			echo "install-control: private installer runtime directory has unsafe metadata" >&2
			return 1
		fi
	else
		install -d -o root -g root -m 0700 "$installer_runtime_dir" || return 1
	fi
	if [[ -e $installer_lock_file || -L $installer_lock_file ]]; then
		if [[ ! -f $installer_lock_file || -L $installer_lock_file ||
			$(stat -c '%u:%g:%a:%h' -- "$installer_lock_file" 2>/dev/null) != 0:0:600:1 ]]; then
			echo "install-control: private installer lock has unsafe metadata" >&2
			return 1
		fi
	else
		(umask 077; set -o noclobber; : >"$installer_lock_file") 2>/dev/null || return 1
	fi
	exec 9<>"$installer_lock_file"
	path_metadata=$(stat -c '%d:%i:%u:%g:%a:%h' -- "$installer_lock_file") || return 1
	fd_metadata=$(stat -Lc '%d:%i:%u:%g:%a:%h' -- "/proc/$process_id/fd/9") || return 1
	if [[ $path_metadata != "$fd_metadata" || $path_metadata != *:0:0:600:1 ]]; then
		echo "install-control: opened installer lock has unsafe metadata" >&2
		exec 8>&- 9>&-
		return 1
	fi
	if ! flock -w 45 9; then
		echo "install-control: another controller installation is active" >&2
		exec 8>&- 9>&-
		return 1
	fi
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--version) version=${2:-}; shift 2 ;;
		--offline-dir) offline_dir=${2:-}; shift 2 ;;
		--artifact) artifact=${2:-}; shift 2 ;;
		--checksums) checksums=${2:-}; shift 2 ;;
		--addr) address=${2:-}; address_set=true; shift 2 ;;
		--tls-cert) tls_cert=${2:-}; tls_supplied=true; shift 2 ;;
		--tls-key) tls_key=${2:-}; tls_supplied=true; shift 2 ;;
		--clear-tls) clear_tls=true; shift ;;
		--admin-token-out) admin_token_out=${2:-}; shift 2 ;;
		--authority-mode) authority_mode=${2:-}; authority_mode_set=true; shift 2 ;;
		--enable-metrics) enable_metrics=true; metrics_set=true; ((metrics_cli_choices += 1)); shift ;;
		--disable-metrics) enable_metrics=false; metrics_set=true; ((metrics_cli_choices += 1)); shift ;;
		--node-stale-after) node_stale_after=${2:-}; node_stale_set=true; shift 2 ;;
		--evidence-stale-after) evidence_stale_after=${2:-}; evidence_stale_set=true; shift 2 ;;
		--command-overdue-after) command_overdue_after=${2:-}; command_overdue_set=true; shift 2 ;;
		--capacity-warning-percent) capacity_warning_percent=${2:-}; capacity_warning_set=true; shift 2 ;;
		--non-interactive) non_interactive=true; shift ;;
		--yes | -y) assume_yes=true; shift ;;
		--no-start) start_service=false; shift ;;
		--dry-run) dry_run=true; shift ;;
		-h | --help) usage; exit 0 ;;
		*) echo "install-control: unknown option $1" >&2; usage >&2; exit 2 ;;
	esac
done

if [[ $(uname -s) != Linux ]]; then echo "install-control: Steward Control service installation requires Linux" >&2; exit 2; fi
machine=$(uname -m)
case "$machine" in x86_64 | amd64) goarch=amd64 ;; aarch64 | arm64) goarch=arm64 ;; *) echo "install-control: unsupported architecture $machine" >&2; exit 2 ;; esac
if [[ -n $offline_dir && -n $artifact ]]; then echo "install-control: choose --offline-dir or --artifact, not both" >&2; exit 2; fi
if [[ $clear_tls == true && $tls_supplied == true ]]; then echo "install-control: --clear-tls cannot be combined with TLS files" >&2; exit 2; fi
if (( metrics_cli_choices > 1 )); then echo "install-control: choose --enable-metrics or --disable-metrics, not both" >&2; exit 2; fi
if [[ $version != latest ]] && ! valid_release_version "$version"; then echo "install-control: version must be latest or a vX.Y.Z release tag" >&2; exit 2; fi

installer_lock_held=false
if (( EUID == 0 )) && [[ $dry_run == false ]]; then
	for command in awk chmod chown cut dd dirname find flock getent grep id install ln mktemp mv \
		readlink rm sha256sum sleep stat sync systemctl timeout; do
		command -v "$command" >/dev/null 2>&1 || { echo "install-control: required recovery command is missing: $command" >&2; exit 2; }
	done
	acquire_host_role_lock || exit 1
	for node_marker in /opt/steward/releases /opt/steward /etc/steward/executor.env /etc/steward \
		/var/lib/steward /var/lib/steward-bootstrap /etc/systemd/system/steward-executor.service \
		/usr/local/libexec/steward/node-preflight /usr/local/libexec/steward /usr/lib/steward-node \
		/var/lib/steward-node-installer; do
		if [[ -e $node_marker || -L $node_marker ]]; then
			echo "install-control: controller and Executor node installations must use separate hosts; found node marker $node_marker" >&2
			exit 1
		fi
	done
	acquire_installer_lock || exit 1
	installer_lock_held=true
	recover_durable_transaction || { echo "install-control: could not safely recover an interrupted controller transaction" >&2; exit 1; }
fi
pending_transaction=false
if [[ -e $installer_transaction || -L $installer_transaction ]]; then pending_transaction=true; fi

declare -A existing=()
read_existing_config() {
	local snapshot=$1 line key metadata source_before source_after size
	if [[ ! -e $config_file && ! -L $config_file ]]; then
		if [[ -e $config_dir || -L $config_dir ]] && ! trusted_root_directory_chain "$config_dir"; then
			echo "install-control: existing $config_dir and every ancestor must be real, root-owned, and not group/other writable" >&2
			exit 1
		fi
		return 1
	fi
	if ! trusted_root_directory_chain "$config_dir" || [[ ! -f $config_file || -L $config_file ]]; then
		echo "install-control: refusing unsafe $config_file or parent directory chain" >&2
		exit 1
	fi
	source_before=$(stat -c '%d:%i:%s:%u:%g:%a:%h:%y:%z' -- "$config_file") || exit 1
	metadata=$(stat -c '%u:%g:%a:%h:%s' -- "$config_file") || exit 1
	IFS=: read -r owner_uid owner_gid mode links size <<<"$metadata"
	if [[ $owner_uid != 0 || $owner_gid != 0 || $mode != 600 || $links != 1 ]] ||
		(( size <= 0 || size > 16384 )); then
		echo "install-control: existing $config_file must be a nonempty, one-link root:root mode 0600 file no larger than 16 KiB" >&2
		exit 1
	fi
	if ! bounded_snapshot "$config_file" "$snapshot" 16384 10; then
		echo "install-control: existing $config_file changed or became unsafe while creating its bounded snapshot" >&2
		exit 1
	fi
	source_after=$(stat -c '%d:%i:%s:%u:%g:%a:%h:%y:%z' -- "$config_file") || exit 1
	if [[ $source_before != "$source_after" ]]; then
		echo "install-control: existing $config_file changed while creating its bounded snapshot" >&2
		exit 1
	fi
	while IFS= read -r line || [[ -n $line ]]; do
		case "$line" in "" | \#*) continue ;; esac
		if [[ ! $line =~ ^(STEWARD_CONTROL_ADDR|STEWARD_CONTROL_STATE_DIR|STEWARD_CONTROL_AUTH_KEY_FILE|STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE|STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE|STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE|STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE|STEWARD_CONTROL_CONTROLLER_KEY_ID|STEWARD_CONTROL_RECONCILE_INTERVAL|STEWARD_CONTROL_AUTHORITY_MODE|STEWARD_CONTROL_TLS_CERT_FILE|STEWARD_CONTROL_TLS_KEY_FILE|STEWARD_CONTROL_ENABLE_METRICS|STEWARD_CONTROL_NODE_STALE_AFTER|STEWARD_CONTROL_EVIDENCE_STALE_AFTER|STEWARD_CONTROL_COMMAND_OVERDUE_AFTER|STEWARD_CONTROL_CAPACITY_WARNING_PERCENT)=([^[:space:]]*)$ ]]; then
			echo "install-control: unsupported or malformed setting in $config_file" >&2; exit 1
		fi
		key=${BASH_REMATCH[1]}
		if [[ ${existing[$key]+present} == present ]]; then echo "install-control: duplicate $key in $config_file" >&2; exit 1; fi
		existing[$key]=${BASH_REMATCH[2]}
	done <"$snapshot"
	for key in STEWARD_CONTROL_ADDR STEWARD_CONTROL_STATE_DIR STEWARD_CONTROL_AUTH_KEY_FILE STEWARD_CONTROL_TLS_CERT_FILE STEWARD_CONTROL_TLS_KEY_FILE; do
		[[ ${existing[$key]+present} == present ]] || { echo "install-control: $config_file is missing $key" >&2; exit 1; }
	done
	if [[ ${existing[STEWARD_CONTROL_STATE_DIR]} != "$state_dir" || ${existing[STEWARD_CONTROL_AUTH_KEY_FILE]} != "$state_dir/auth.key" ]]; then
		echo "install-control: existing state paths are not installer-managed" >&2; exit 1
	fi
	if { [[ ${existing[STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE]+present} == present ]] &&
		[[ ${existing[STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE]+present} != present ]]; } ||
		{ [[ ${existing[STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE]+present} != present ]] &&
			[[ ${existing[STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE]+present} == present ]]; }; then
		echo "install-control: existing witness key configuration is partial" >&2
		exit 1
	fi
	if [[ ${existing[STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE]+present} == present ]] &&
		[[ ${existing[STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE]} != "$witness_private_key" ||
			${existing[STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE]} != "$witness_public_key" ]]; then
		echo "install-control: existing witness key paths are not installer-managed" >&2
		exit 1
	fi
	if { [[ ${existing[STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE]+present} == present ]] &&
		[[ ${existing[STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE]+present} != present ]]; } ||
		{ [[ ${existing[STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE]+present} != present ]] &&
			[[ ${existing[STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE]+present} == present ]]; }; then
		echo "install-control: existing controller signing-key configuration is partial" >&2
		exit 1
	fi
	if [[ ${existing[STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE]+present} == present ]] &&
		[[ ${existing[STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE]} != "$controller_private_key" ||
			${existing[STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE]} != "$controller_public_key" ]]; then
		echo "install-control: existing controller signing-key paths are not installer-managed" >&2
		exit 1
	fi
	if [[ ${existing[STEWARD_CONTROL_CONTROLLER_KEY_ID]+present} == present &&
		${existing[STEWARD_CONTROL_CONTROLLER_KEY_ID]} != "$controller_key_id" ]]; then
		echo "install-control: existing controller key ID is not installer-managed" >&2
		exit 1
	fi
	if [[ ${existing[STEWARD_CONTROL_RECONCILE_INTERVAL]+present} == present &&
		${existing[STEWARD_CONTROL_RECONCILE_INTERVAL]} != "$reconcile_interval" ]]; then
		echo "install-control: existing reconciliation interval is not installer-managed" >&2
		exit 1
	fi
	if [[ ${existing[STEWARD_CONTROL_AUTHORITY_MODE]+present} == present &&
		${existing[STEWARD_CONTROL_AUTHORITY_MODE]} != bounded-autonomous &&
		${existing[STEWARD_CONTROL_AUTHORITY_MODE]} != strict-sovereign ]]; then
		echo "install-control: existing authority mode is invalid" >&2
		exit 1
	fi
	if [[ -n ${existing[STEWARD_CONTROL_TLS_CERT_FILE]} || -n ${existing[STEWARD_CONTROL_TLS_KEY_FILE]} ]]; then
		if [[ ${existing[STEWARD_CONTROL_TLS_CERT_FILE]} != "$tls_cert_dest" || ${existing[STEWARD_CONTROL_TLS_KEY_FILE]} != "$tls_key_dest" ]]; then
			echo "install-control: existing TLS paths are not installer-managed" >&2; exit 1
		fi
	fi
	if [[ ${existing[STEWARD_CONTROL_ENABLE_METRICS]+present} == present &&
		${existing[STEWARD_CONTROL_ENABLE_METRICS]} != true &&
		${existing[STEWARD_CONTROL_ENABLE_METRICS]} != false ]]; then
		echo "install-control: existing metrics setting must be true or false" >&2
		exit 1
	fi
	for key in STEWARD_CONTROL_NODE_STALE_AFTER STEWARD_CONTROL_EVIDENCE_STALE_AFTER \
		STEWARD_CONTROL_COMMAND_OVERDUE_AFTER; do
		if [[ ${existing[$key]+present} == present ]] &&
			! valid_operations_duration "${existing[$key]}"; then
			echo "install-control: existing $key is outside the supported duration contract" >&2
			exit 1
		fi
	done
	if [[ ${existing[STEWARD_CONTROL_CAPACITY_WARNING_PERCENT]+present} == present ]] &&
		! valid_capacity_warning_percent "${existing[STEWARD_CONTROL_CAPACITY_WARNING_PERCENT]}"; then
		echo "install-control: existing capacity warning percent is invalid" >&2
		exit 1
	fi
	return 0
}

config_inspect_dir=$(mktemp -d /tmp/steward-control-config.XXXXXX)
trap 'rm -rf -- "${config_inspect_dir:-}"' EXIT
have_existing_config=false
if read_existing_config "$config_inspect_dir/control.env"; then have_existing_config=true; fi
rm -rf -- "$config_inspect_dir"
config_inspect_dir=
trap - EXIT
if [[ $address_set == false ]]; then
	if [[ $have_existing_config == true ]]; then address=${existing[STEWARD_CONTROL_ADDR]}; else address=127.0.0.1:8443; fi
fi
if [[ $metrics_set == false ]]; then
	if [[ $have_existing_config == true &&
		${existing[STEWARD_CONTROL_ENABLE_METRICS]+present} == present ]]; then
		enable_metrics=${existing[STEWARD_CONTROL_ENABLE_METRICS]}
	else
		enable_metrics=false
	fi
fi
if [[ $authority_mode_set == false ]]; then
	if [[ $have_existing_config == true &&
		${existing[STEWARD_CONTROL_AUTHORITY_MODE]+present} == present ]]; then
		authority_mode=${existing[STEWARD_CONTROL_AUTHORITY_MODE]}
	else
		authority_mode=bounded-autonomous
	fi
fi
if [[ $node_stale_set == false ]]; then
	if [[ $have_existing_config == true &&
		${existing[STEWARD_CONTROL_NODE_STALE_AFTER]+present} == present ]]; then
		node_stale_after=${existing[STEWARD_CONTROL_NODE_STALE_AFTER]}
	else
		node_stale_after=2m
	fi
fi
if [[ $evidence_stale_set == false ]]; then
	if [[ $have_existing_config == true &&
		${existing[STEWARD_CONTROL_EVIDENCE_STALE_AFTER]+present} == present ]]; then
		evidence_stale_after=${existing[STEWARD_CONTROL_EVIDENCE_STALE_AFTER]}
	else
		evidence_stale_after=5m
	fi
fi
if [[ $command_overdue_set == false ]]; then
	if [[ $have_existing_config == true &&
		${existing[STEWARD_CONTROL_COMMAND_OVERDUE_AFTER]+present} == present ]]; then
		command_overdue_after=${existing[STEWARD_CONTROL_COMMAND_OVERDUE_AFTER]}
	else
		command_overdue_after=5m
	fi
fi
if [[ $capacity_warning_set == false ]]; then
	if [[ $have_existing_config == true &&
		${existing[STEWARD_CONTROL_CAPACITY_WARNING_PERCENT]+present} == present ]]; then
		capacity_warning_percent=${existing[STEWARD_CONTROL_CAPACITY_WARNING_PERCENT]}
	else
		capacity_warning_percent=80
	fi
fi
preserve_tls=false
if [[ $have_existing_config == true && $tls_supplied == false && $clear_tls == false && -n ${existing[STEWARD_CONTROL_TLS_CERT_FILE]} ]]; then
	preserve_tls=true
fi

prompt() {
	local message=$1 default=${2:-} answer
	if [[ $non_interactive == true ]]; then return 1; fi
	read -r -p "$message" answer </dev/tty
	printf '%s' "${answer:-$default}"
}
confirm() {
	local message=$1 answer
	if [[ $assume_yes == true ]]; then return 0; fi
	if [[ $non_interactive == true ]]; then return 1; fi
	answer=$(prompt "$message [Y/n] " yes)
	case "$answer" in y | Y | yes | YES | Yes) return 0 ;; *) return 1 ;; esac
}
if [[ $non_interactive == false && ! -r /dev/tty ]]; then echo "install-control: no interactive terminal; pass --non-interactive" >&2; exit 2; fi

state_looks_initialized=false
if [[ -f $state_dir/CURRENT && -f $state_dir/auth.key ]]; then state_looks_initialized=true; fi
if [[ $non_interactive == false ]]; then
	echo "Steward Control guided installation"
	version=$(prompt "Release version [$version]: " "$version")
	address=$(prompt "Listen address [$address]: " "$address")
	address_set=true
	if [[ $state_looks_initialized == false && -z $admin_token_out ]]; then
		admin_token_out=$(prompt "Admin token output [/root/steward-control-admin.token]: " /root/steward-control-admin.token)
	fi
fi
if [[ $version != latest ]] && ! valid_release_version "$version"; then echo "install-control: version must be latest or a vX.Y.Z release tag" >&2; exit 2; fi
if [[ $enable_metrics != true && $enable_metrics != false ]]; then
	echo "install-control: metrics setting must be true or false" >&2
	exit 2
fi
if [[ $authority_mode != bounded-autonomous && $authority_mode != strict-sovereign ]]; then
	echo "install-control: authority mode must be bounded-autonomous or strict-sovereign" >&2
	exit 2
fi
if ! valid_operations_duration "$node_stale_after" ||
	! valid_operations_duration "$evidence_stale_after" ||
	! valid_operations_duration "$command_overdue_after"; then
	echo "install-control: operations durations must be positive canonical s, m, or h values no greater than 8760h" >&2
	exit 2
fi
if ! valid_capacity_warning_percent "$capacity_warning_percent"; then
	echo "install-control: capacity warning percent must be an integer from 1 through 100" >&2
	exit 2
fi

validate_address() {
	local value=$1 host port octet
	(( ${#value} <= 512 )) || return 1
	if [[ $value =~ ^\[([0-9A-Fa-f:.]+)\]:([0-9]{1,5})$ ]]; then host=${BASH_REMATCH[1]}; port=${BASH_REMATCH[2]}
	elif [[ $value =~ ^([A-Za-z0-9.-]+):([0-9]{1,5})$ ]]; then host=${BASH_REMATCH[1]}; port=${BASH_REMATCH[2]}
	else return 1; fi
	(( 10#$port >= 1 && 10#$port <= 65535 )) || return 1
	if [[ $host == 127.* ]]; then
		IFS=. read -r -a octets <<<"$host"
		(( ${#octets[@]} == 4 )) || return 1
		for octet in "${octets[@]}"; do [[ $octet =~ ^[0-9]{1,3}$ ]] && (( 10#$octet <= 255 )) || return 1; done
	fi
	LISTEN_HOST=$host
}
LISTEN_HOST=
if ! validate_address "$address"; then echo "install-control: --addr must be a valid HOST:PORT" >&2; exit 2; fi
loopback=false
case "$LISTEN_HOST" in ::1 | 127.*) loopback=true ;; esac

if [[ $non_interactive == false && $preserve_tls == false && $tls_supplied == false && $clear_tls == false && $loopback == false ]]; then
	tls_cert=$(prompt "TLS certificate PEM: " "")
	tls_key=$(prompt "Owner-only TLS private key PEM: " "")
	tls_supplied=true
fi
if [[ $tls_supplied == true && ( -z $tls_cert || -z $tls_key ) ]]; then echo "install-control: --tls-cert and --tls-key must be set together" >&2; exit 2; fi
if [[ $loopback == false && $tls_supplied == false && $preserve_tls == false ]]; then
	echo "install-control: a non-loopback listener requires a TLS certificate and owner-only key" >&2; exit 2
fi

validate_supplied_tls() {
	local path=$1 kind=$2 parent metadata uid mode links size
	clean_absolute_path "$path" && [[ -f $path && ! -L $path && $(readlink -e -- "$path" 2>/dev/null) == "$path" ]] || return 1
	parent=$(dirname -- "$path")
	trusted_root_directory_chain "$parent" || return 1
	metadata=$(stat -c '%u:%a:%h:%s' -- "$path") || return 1
	IFS=: read -r uid mode links size <<<"$metadata"
	[[ $uid == 0 && $links == 1 ]] || return 1
	(( size > 0 && size <= 1048576 )) || return 1
	if [[ $kind == key ]]; then
		(( (8#$mode & 077) == 0 ))
	else
		(( (8#$mode & 022) == 0 ))
	fi
}
recover_token_publication() {
	local parent=$1 destination=$2 destination_id=$3 candidate metadata final_links=0 final_inode='' twin=''
	local -a candidates=() orphans=()
	[[ $destination_id =~ ^[0-9a-f]{64}$ ]] || return 1
	shopt -s nullglob
	candidates=("$parent/.steward-control-admin-token.$destination_id."*)
	shopt -u nullglob
	if [[ -e $destination || -L $destination ]]; then
		if [[ ! -f $destination || -L $destination ]]; then return 1; fi
		metadata=$(stat -c '%u:%g:%a:%h' -- "$destination")
		if [[ ! $metadata =~ ^0:0:600:([12])$ ]] ||
			(( $(stat -c '%s' -- "$destination") <= 0 || $(stat -c '%s' -- "$destination") > 4096 )); then
			return 1
		fi
		final_links=${BASH_REMATCH[1]}
		final_inode=$(stat -c '%d:%i' -- "$destination")
	fi
	for candidate in "${candidates[@]}"; do
		[[ $candidate != "$destination" ]] || return 1
		if [[ ! -f $candidate || -L $candidate ]] ||
			(( $(stat -c '%s' -- "$candidate") > 4096 )); then
			return 1
		fi
		metadata=$(stat -c '%u:%g:%a:%h' -- "$candidate")
		case "$metadata" in
			0:0:600:1) orphans+=("$candidate") ;;
			0:0:600:2)
				if [[ $final_links != 2 || $(stat -c '%d:%i' -- "$candidate") != "$final_inode" || -n $twin ]]; then
					return 1
				fi
				twin=$candidate
				;;
			*) return 1 ;;
		esac
	done
	if [[ $final_links == 2 && -z $twin ]]; then return 1; fi
	if [[ -n $twin ]]; then rm -f -- "$twin"; fi
	if (( ${#orphans[@]} > 0 )); then rm -f -- "${orphans[@]}"; fi
	if [[ -n $twin || ${#orphans[@]} -gt 0 ]]; then sync -f "$parent"; fi
}
if [[ $tls_supplied == true ]]; then
	if ! validate_supplied_tls "$tls_cert" cert || ! validate_supplied_tls "$tls_key" key; then
		echo "install-control: TLS inputs must be root-owned, one-link regular files no larger than 1 MiB under a root-owned non-writable path; the key must be owner-only" >&2
		exit 2
	fi
fi
if [[ -n $admin_token_out ]] && ! clean_absolute_path "$admin_token_out"; then echo "install-control: --admin-token-out must be a clean absolute non-root path" >&2; exit 2; fi
if [[ -n $admin_token_out && ${admin_token_out##*/} == .steward-control-admin-token.* ]]; then
	echo "install-control: --admin-token-out uses the installer's reserved temporary-file namespace" >&2
	exit 2
fi
if [[ -n $admin_token_out && ( $admin_token_out == "$state_dir" || $admin_token_out == "$state_dir/"* ) ]]; then
	echo "install-control: admin token output must be outside service-owned durable state" >&2; exit 2
fi

if [[ $non_interactive == false && $dry_run == false ]]; then
	echo "Install Steward Control $version on $address ($([[ $tls_supplied == true || $preserve_tls == true ]] && echo TLS || echo loopback-HTTP))."
	if ! confirm "Proceed with installation?"; then echo "install-control: cancelled"; exit 0; fi
fi

if [[ $dry_run == true ]]; then
	echo "Steward Control install plan:"
	echo "  target:       linux/$goarch"
	echo "  version:      $version"
	echo "  artifact:     ${artifact:-steward-control_${version}_linux_${goarch}.tar.gz}"
	echo "  listen:       $address"
	echo "  transport:    $([[ $tls_supplied == true || $preserve_tls == true ]] && echo TLS || echo loopback-HTTP)"
	echo "  state:        $state_dir (preserved)"
	echo "  metrics:      $([[ $enable_metrics == true ]] && echo authenticated || echo disabled)"
	echo "  authority:    $authority_mode"
	echo "  attention:    node=$node_stale_after evidence=$evidence_stale_after command=$command_overdue_after capacity=${capacity_warning_percent}%"
	echo "  token output: ${admin_token_out:-required on first install}"
	echo "  service:      $([[ $start_service == true ]] && echo enable-and-start || echo install-only)"
	echo "  recovery:     $([[ $pending_transaction == true ]] && echo pending-on-next-install || echo none)"
	exit 0
fi

if (( EUID != 0 )); then echo "install-control: run as root (for example, with sudo)" >&2; exit 1; fi
for command in awk cat cp curl dd head sha256sum sync tar stat timeout getent groupadd useradd runuser systemctl systemd-analyze flock install readlink; do
	command -v "$command" >/dev/null 2>&1 || { echo "install-control: required command is missing: $command" >&2; exit 2; }
done
[[ $installer_lock_held == true ]] || { echo "install-control: internal lifecycle lock was not acquired" >&2; exit 1; }
if ! trusted_root_directory_chain "$(dirname -- "$state_dir")"; then
	echo "install-control: durable state parent chain must be real, root-owned, and not group/other writable" >&2
	exit 1
fi

state_nonempty=false
if [[ -e $state_dir || -L $state_dir ]]; then
	if [[ ! -d $state_dir || -L $state_dir ]]; then echo "install-control: durable state path is not a real directory" >&2; exit 1; fi
	if find "$state_dir" -mindepth 1 -print -quit | grep -q .; then state_nonempty=true; fi
fi
if [[ $state_nonempty == false && -z $admin_token_out ]]; then echo "install-control: first install requires --admin-token-out (or guided input)" >&2; exit 2; fi
admin_token_preexisting=false
if [[ -n $admin_token_out ]]; then
	token_parent=$(dirname -- "$admin_token_out")
	if ! trusted_root_directory_chain "$token_parent"; then echo "install-control: admin token parent and every ancestor must be real, root-owned, and not group/other writable" >&2; exit 2; fi
	token_destination_id=$(printf '%s' "$admin_token_out" | sha256sum | awk '{print $1}')
	if ! recover_token_publication "$token_parent" "$admin_token_out" "$token_destination_id"; then
		echo "install-control: admin token output or interrupted publication has unsafe metadata" >&2
		exit 1
	fi
	if [[ -e $admin_token_out || -L $admin_token_out ]]; then
		admin_token_preexisting=true
		if [[ ! -f $admin_token_out || -L $admin_token_out || $(stat -c '%u:%g:%a:%h' -- "$admin_token_out") != 0:0:600:1 ]] ||
			(( $(stat -c '%s' -- "$admin_token_out") <= 0 || $(stat -c '%s' -- "$admin_token_out") > 4096 )); then
			echo "install-control: existing admin token handoff has unsafe metadata" >&2; exit 1
		fi
	fi
	if [[ $state_nonempty == false && $admin_token_preexisting == true ]]; then
		echo "install-control: refusing a pre-existing admin token without durable controller state" >&2; exit 1
	fi
fi

work=$(mktemp -d /tmp/steward-control-install.XXXXXX)
committed=false
transaction_armed=false
service_was_active=false
service_was_enabled=false
admin_token_created=false
handoff_dir=
proof_dir=
proof_wrapper_pid=
proof_child_pid=
publication_tmp=

replace_link() {
	local link=$1 target=$2 temporary=${1}.new.$$
	rm -f -- "$temporary"
	ln -s -- "$target" "$temporary"
	mv -Tf -- "$temporary" "$link"
}
stop_bootstrap_proof() {
	if [[ -n ${proof_child_pid:-} && $proof_child_pid =~ ^[0-9]+$ ]]; then
		kill -TERM "$proof_child_pid" 2>/dev/null || true
		for _ in {1..50}; do kill -0 "$proof_child_pid" 2>/dev/null || break; sleep 0.05; done
		if kill -0 "$proof_child_pid" 2>/dev/null; then kill -KILL "$proof_child_pid" 2>/dev/null || true; fi
	fi
	if [[ -n ${proof_wrapper_pid:-} && $proof_wrapper_pid =~ ^[0-9]+$ ]]; then
		if kill -0 "$proof_wrapper_pid" 2>/dev/null; then
			kill -TERM "$proof_wrapper_pid" 2>/dev/null || true
			for _ in {1..20}; do kill -0 "$proof_wrapper_pid" 2>/dev/null || break; sleep 0.05; done
			if kill -0 "$proof_wrapper_pid" 2>/dev/null; then kill -KILL "$proof_wrapper_pid" 2>/dev/null || true; fi
		fi
		wait "$proof_wrapper_pid" 2>/dev/null || true
	fi
	proof_child_pid=
	proof_wrapper_pid=
	if [[ -n ${proof_dir:-} ]]; then rm -rf -- "$proof_dir" || true; fi
	proof_dir=
}
publish_admin_token() {
	local source=$1 destination=$2 source_size destination_parent destination_id
	source_size=$(stat -c '%s' -- "$source")
	destination_parent=$(dirname -- "$destination")
	destination_id=$(printf '%s' "$destination" | sha256sum | awk '{print $1}')
	[[ $destination_id =~ ^[0-9a-f]{64}$ ]] || return 1
	publication_tmp=$(mktemp "$destination_parent/.steward-control-admin-token.$destination_id.XXXXXX")
	if [[ ! -f $publication_tmp || -L $publication_tmp || $(stat -c '%u:%g:%a:%h' -- "$publication_tmp") != 0:0:600:1 ]]; then
		echo "install-control: could not reserve a safe temporary admin token handoff" >&2
		return 1
	fi
	if ! cat -- "$source" >"$publication_tmp"; then
		rm -f -- "$publication_tmp"
		publication_tmp=
		return 1
	fi
	sync -f "$publication_tmp"
	if [[ $(stat -c '%u:%g:%a:%h:%s' -- "$publication_tmp") != "0:0:600:1:$source_size" ]]; then
		echo "install-control: temporary admin token handoff changed unexpectedly" >&2
		return 1
	fi
	if ! ln -- "$publication_tmp" "$destination"; then
		echo "install-control: admin token output appeared before its exclusive handoff" >&2
		return 1
	fi
	admin_token_created=true
	sync -f "$destination_parent"
	rm -f -- "$publication_tmp"
	publication_tmp=
	sync -f "$destination_parent"
	if [[ ! -f $destination || -L $destination || $(stat -c '%u:%g:%a:%h' -- "$destination") != 0:0:600:1 ]] ||
		[[ $(stat -c '%s' -- "$destination") -ne $source_size ]]; then
		rm -f -- "$destination"
		echo "install-control: admin token handoff metadata changed unexpectedly" >&2
		return 1
	fi
}
validate_state_tree() {
	local expected_uid=$1 expected_gid=$2 entry metadata expected_mode
	while IFS= read -r -d '' entry; do
		if [[ ! -f $entry || -L $entry ]]; then
			echo "install-control: durable state contains a link or special object: $entry" >&2
			return 1
		fi
		expected_mode=600
		[[ $entry != "$witness_public_key" ]] || expected_mode=644
		[[ $entry != "$controller_public_key" ]] || expected_mode=644
		metadata=$(stat -c '%u:%g:%a:%h' -- "$entry")
		if [[ $metadata != "$expected_uid:$expected_gid:$expected_mode:1" ]]; then
			echo "install-control: durable state file has unsafe ownership, mode, or link count: $entry" >&2
			return 1
		fi
	done < <(find "$state_dir" -mindepth 1 -maxdepth 1 -print0)
}
backup_managed_tls() {
	local source=$1 backup=$2 expected_uid=$3 expected_gid=$4 owner=$5 group=$6 mode=$7
	local before after source_size temporary=${backup}.copy.$$
	if [[ ! -f $source || -L $source ]]; then
		echo "install-control: existing TLS material is not a regular file: $source" >&2
		return 1
	fi
	before=$(stat -c '%d:%i:%s:%u:%g:%a:%h:%y:%z' -- "$source")
	source_size=$(stat -c '%s' -- "$source")
	if [[ $(stat -c '%u:%g:%a:%h' -- "$source") != "$expected_uid:$expected_gid:$mode:1" ]] ||
		(( source_size <= 0 || source_size > 1048576 )); then
		echo "install-control: existing TLS material has unsafe ownership, mode, link count, or size: $source" >&2
		return 1
	fi
	if ! bounded_snapshot "$source" "$temporary" 1048576 10; then
		echo "install-control: existing TLS material could not be copied within its bound: $source" >&2
		return 1
	fi
	after=$(stat -c '%d:%i:%s:%u:%g:%a:%h:%y:%z' -- "$source")
	if [[ $before != "$after" || $(stat -c '%s' -- "$temporary") -ne $source_size ]]; then
		rm -f -- "$temporary"
		echo "install-control: existing TLS material changed while it was being copied: $source" >&2
		return 1
	fi
	install -m "$mode" -o "$owner" -g "$group" "$temporary" "$backup"
	rm -f -- "$temporary"
}

write_journal_file() {
	local path=$1 value=${2-}
	printf '%s' "$value" >"$path" || return 1
	chmod 0600 "$path" || return 1
	sync -f "$path"
}

snapshot_journal_link() {
	local name=$1 source=$2 destination=$3 target
	if [[ -L $source ]]; then
		target=$(readlink -- "$source") || return 1
		ln -s -- "$target" "$destination/$name.link" || return 1
	elif [[ ! -e $source ]]; then
		write_journal_file "$destination/$name.absent" || return 1
	else
		return 1
	fi
}

prepare_durable_transaction() {
	local new_dir=$installer_state_dir/transaction.new state_kind state_meta entry
	if [[ ! -e $installer_state_dir && ! -L $installer_state_dir ]]; then
		ensure_root_managed_directory "$installer_state_dir" 0 0700 || return 1
		sync -f "$(dirname -- "$installer_state_dir")" || return 1
	fi
	if ! trusted_root_directory_chain "$installer_state_dir" ||
		[[ $(stat -c '%u:%g:%a' -- "$installer_state_dir") != 0:0:700 ]] ||
		[[ -e $installer_transaction || -L $installer_transaction || -e $new_dir || -L $new_dir ]]; then
		return 1
	fi
	install -d -m 0700 -o root -g root "$new_dir" || return 1
	write_journal_file "$new_dir/service.ids" "$service_uid:$service_gid" || return 1
	if [[ $service_was_active == true ]]; then write_journal_file "$new_dir/service.active" || return 1
	else write_journal_file "$new_dir/service.inactive" || return 1
	fi
	if [[ $service_was_enabled == true ]]; then write_journal_file "$new_dir/service.enabled" || return 1
	else write_journal_file "$new_dir/service.disabled" || return 1
	fi
	snapshot_journal_link current "$current_link" "$new_dir" || return 1
	snapshot_journal_link binary "$binary_link" "$new_dir" || return 1
	snapshot_journal_link doctor "$doctor_link" "$new_dir" || return 1
	snapshot_journal_link unit "$unit_link" "$new_dir" || return 1
	if [[ -e $config_file || -L $config_file ]]; then
		bounded_snapshot "$config_file" "$new_dir/config.file" 16384 10 || return 1
	else write_journal_file "$new_dir/config.absent" || return 1
	fi
	if [[ -e $tls_cert_dest || -L $tls_cert_dest ]]; then
		backup_managed_tls "$tls_cert_dest" "$new_dir/tls-cert.file" 0 "$service_gid" root "$service_group" 640 || return 1
		sync -f "$new_dir/tls-cert.file" || return 1
	else write_journal_file "$new_dir/tls-cert.absent" || return 1
	fi
	if [[ -e $tls_key_dest || -L $tls_key_dest ]]; then
		backup_managed_tls "$tls_key_dest" "$new_dir/tls-key.file" "$service_uid" "$service_gid" "$service_user" "$service_group" 600 || return 1
		sync -f "$new_dir/tls-key.file" || return 1
	else write_journal_file "$new_dir/tls-key.absent" || return 1
	fi
	if [[ ! -e $state_dir && ! -L $state_dir ]]; then
		state_kind=absent
	else
		[[ -d $state_dir && ! -L $state_dir ]] || return 1
		state_meta=$(stat -c '%u:%g:%a' -- "$state_dir") || return 1
		if find "$state_dir" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then state_kind=present
		else state_kind=empty
		fi
		write_journal_file "$new_dir/state.meta" "$state_meta" || return 1
	fi
	write_journal_file "$new_dir/state.kind" "$state_kind" || return 1
	if [[ -n $admin_token_out && $admin_token_preexisting == false ]]; then
		ln -s -- "$admin_token_out" "$new_dir/admin-token.intent" || return 1
	fi
	write_journal_file "$new_dir/phase" prepared || return 1
	while IFS= read -r -d '' entry; do sync -f "$entry" || return 1; done < <(find "$new_dir" -mindepth 1 -maxdepth 1 -type f -print0)
	sync -f "$new_dir" || return 1
	mv -T -- "$new_dir" "$installer_transaction" || return 1
	sync -f "$installer_state_dir" || return 1
	transaction_armed=true
}

commit_durable_transaction() {
	local path entry phase_new=$installer_transaction/phase.new
	for path in "$release_dir" "$releases_dir" /opt/steward-control /usr/local/bin \
		/usr/local/libexec/steward-control /etc/systemd/system "$config_dir"; do
		[[ ! -e $path || -L $path ]] || sync -f "$path" || return 1
	done
	if [[ -d /etc/systemd/system/multi-user.target.wants ]]; then
		sync -f /etc/systemd/system/multi-user.target.wants || return 1
	fi
	for path in "$config_file" "$tls_cert_dest" "$tls_key_dest" "$admin_token_out"; do
		[[ -z $path || ! -f $path || -L $path ]] || sync -f "$path" || return 1
	done
	if [[ -d $state_dir && ! -L $state_dir ]]; then
		while IFS= read -r -d '' entry; do sync -f "$entry" || return 1; done < <(find "$state_dir" -mindepth 1 -maxdepth 1 -type f -print0)
		sync -f "$state_dir" || return 1
	fi
	write_journal_file "$phase_new" committed || return 1
	mv -Tf -- "$phase_new" "$installer_transaction/phase" || return 1
	sync -f "$installer_transaction" || return 1
	committed=true
	rm -rf -- "$installer_transaction" || true
	sync -f "$installer_state_dir" || true
}
prove_admin_token() {
	local token_file=$1 address_line http_status proof_executable proof_uid identity_valid=false
	local -a token_lines=() proof_argv=()
	if [[ ! -f $token_file || -L $token_file || $(stat -c '%u:%g:%a:%h' -- "$token_file") != 0:0:600:1 ]] ||
		(( $(stat -c '%s' -- "$token_file") <= 0 || $(stat -c '%s' -- "$token_file") > 4096 )); then
		echo "install-control: admin token handoff is not a valid owner-only Steward credential" >&2
		return 1
	fi
	mapfile -t token_lines <"$token_file"
	if (( ${#token_lines[@]} != 1 )) || [[ ! ${token_lines[0]} =~ ^steward_cp_v1_[A-Za-z0-9_-]+$ ]]; then
		echo "install-control: admin token handoff is not a valid owner-only Steward credential" >&2
		return 1
	fi
	(
		ulimit -c 0
		ulimit -f 2048
		exec timeout --signal=TERM --kill-after=2 12 runuser -u "$service_user" -- /bin/sh -c \
			'printf "steward-proof-pid=%s\n" "$$"; exec "$@"' _ \
			"$release_dir/steward-control" -addr 127.0.0.1:0 \
			-state-dir "$state_dir" -auth-key-file "$state_dir/auth.key" \
			-authority-mode "$authority_mode"
	) >"$work/proof.stdout" 2>"$work/proof.stderr" &
	proof_wrapper_pid=$!
	address_line=
	for _ in {1..100}; do
		proof_child_pid=$(sed -n 's/^steward-proof-pid=\([0-9][0-9]*\)$/\1/p' "$work/proof.stdout" | head -1)
		address_line=$(sed -n 's/.*"address":"\(127\.0\.0\.1:[0-9][0-9]*\)".*/\1/p' "$work/proof.stderr" | tail -1)
		[[ -n $address_line ]] && break
		kill -0 "$proof_wrapper_pid" 2>/dev/null || break
		sleep 0.05
	done
	if [[ ! ${proof_child_pid:-} =~ ^[0-9]+$ || ! $address_line =~ ^127\.0\.0\.1:[0-9]+$ ]]; then
		echo "install-control: transient bootstrap authentication server did not become ready" >&2
		return 1
	fi
	proof_executable=$(readlink -f -- "/proc/$proof_child_pid/exe" 2>/dev/null || true)
	proof_uid=$(stat -c '%u' -- "/proc/$proof_child_pid" 2>/dev/null || true)
	if [[ $proof_executable == "$release_dir/steward-control" ]]; then
		identity_valid=true
	elif [[ -z $proof_executable && -r /proc/$proof_child_pid/cmdline ]]; then
		mapfile -d '' -t proof_argv <"/proc/$proof_child_pid/cmdline" || true
		if (( ${#proof_argv[@]} == 9 )) && [[ ${proof_argv[0]} == "$release_dir/steward-control" &&
			${proof_argv[1]} == -addr && ${proof_argv[2]} == 127.0.0.1:0 &&
			${proof_argv[3]} == -state-dir && ${proof_argv[4]} == "$state_dir" &&
			${proof_argv[5]} == -auth-key-file && ${proof_argv[6]} == "$state_dir/auth.key" &&
			${proof_argv[7]} == -authority-mode && ${proof_argv[8]} == "$authority_mode" ]]; then
			identity_valid=true
		fi
	fi
	if [[ $identity_valid != true || $proof_uid != "$service_uid" ]]; then
		echo "install-control: transient bootstrap authentication process has an unexpected identity (executable=${proof_executable:-unavailable}, uid=${proof_uid:-unavailable}, argc=${#proof_argv[@]}, argv0=${proof_argv[0]:-unavailable})" >&2
		return 1
	fi
	printf 'Authorization: Bearer %s\n' "${token_lines[0]}" >"$work/proof.header"
	http_status=$(curl -q --noproxy '*' --proto '=http' --max-redirs 0 --silent --show-error --max-time 5 --max-filesize 1048576 \
		--header "@$work/proof.header" --output "$work/proof.response" --write-out '%{http_code}' \
		"http://$address_line/v1/tenants?limit=1")
	rm -f -- "$work/proof.header"
	if [[ $http_status != 200 ]] || ! grep -Eq '^\{"tenants":\[' "$work/proof.response"; then
		echo "install-control: admin token failed authenticated control-plane proof" >&2
		return 1
	fi
	stop_bootstrap_proof
}
rollback() {
	local code=$?
	if [[ $transaction_armed == true && $committed == false ]]; then
		set +e
		stop_bootstrap_proof
		if ! recover_durable_transaction; then
			echo "install-control: automatic rollback was incomplete; the durable journal was preserved for the next recovery attempt" >&2
		fi
	fi
	if [[ -n ${handoff_dir:-} ]]; then rm -rf -- "$handoff_dir"; fi
	if [[ -n ${publication_tmp:-} ]]; then rm -f -- "$publication_tmp"; fi
	rm -rf "$work"
	exit "$code"
}
trap rollback EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ $tls_supplied == true ]]; then
	tls_cert_source=$tls_cert
	tls_key_source=$tls_key
	if ! validate_supplied_tls "$tls_cert_source" cert || ! validate_supplied_tls "$tls_key_source" key ||
		! bounded_snapshot "$tls_cert_source" "$work/supplied.tls.crt" 1048576 10 ||
		! bounded_snapshot "$tls_key_source" "$work/supplied.tls.key" 1048576 10; then
		echo "install-control: TLS inputs changed or became unsafe while creating a bounded root-owned snapshot" >&2
		exit 1
	fi
	tls_cert=$work/supplied.tls.crt
	tls_key=$work/supplied.tls.key
fi

download() {
	local url=$1 output=$2 limit=$3 output_blocks size
	[[ $limit =~ ^[0-9]+$ ]] && (( limit > 0 && limit % 1024 == 0 )) || return 1
	output_blocks=$((limit / 1024))
	rm -f -- "$output"
	if ! (
		exec 8>&- 9>&-
		ulimit -c 0
		ulimit -f "$output_blocks"
		exec timeout --signal=TERM --kill-after=5 190 \
			curl -q --proto '=https' --tlsv1.2 --location --fail --silent --show-error \
			--retry 3 --retry-connrefused --max-time 180 --max-filesize "$limit" --output "$output" "$url"
	); then
		rm -f -- "$output"
		return 1
	fi
	if [[ ! -f $output || -L $output ]]; then rm -f -- "$output"; return 1; fi
	size=$(stat -c '%s' -- "$output") || { rm -f -- "$output"; return 1; }
	if (( size <= 0 || size > limit )) ||
		[[ $(stat -c '%u:%g:%a:%h' -- "$output") != 0:0:600:1 ]]; then
		rm -f -- "$output"
		return 1
	fi
}

run_bounded_command() {
	local stdout=$1 stderr=$2 max_bytes=$3 file_limit_bytes=$4 timeout_seconds=$5 memory_kib=$6
	local output_blocks path size
	shift 6
	[[ $max_bytes =~ ^[0-9]+$ && $file_limit_bytes =~ ^[0-9]+$ && $timeout_seconds =~ ^[0-9]+$ && $memory_kib =~ ^[0-9]+$ ]] || return 1
	(( max_bytes > 0 && file_limit_bytes >= max_bytes && file_limit_bytes % 1024 == 0 && timeout_seconds > 0 && memory_kib > 0 )) || return 1
	output_blocks=$((file_limit_bytes / 1024))
	rm -f -- "$stdout" "$stderr"
	if ! (
		exec 8>&- 9>&-
		ulimit -c 0
		ulimit -f "$output_blocks"
		ulimit -v "$memory_kib"
		exec timeout --signal=TERM --kill-after=5 "$timeout_seconds" "$@"
	) >"$stdout" 2>"$stderr"; then
		rm -f -- "$stdout" "$stderr"
		return 1
	fi
	for path in "$stdout" "$stderr"; do
		if [[ ! -f $path || -L $path || $(stat -c '%u:%g:%a:%h' -- "$path") != 0:0:600:1 ]]; then
			rm -f -- "$stdout" "$stderr"
			return 1
		fi
		size=$(stat -c '%s' -- "$path") || { rm -f -- "$stdout" "$stderr"; return 1; }
		if (( size > max_bytes )); then rm -f -- "$stdout" "$stderr"; return 1; fi
	done
}

if [[ -n $artifact ]]; then
	[[ -f $artifact && ! -L $artifact ]] || { echo "install-control: artifact is not a regular file" >&2; exit 2; }
	artifact=$(readlink -f -- "$artifact")
	[[ -n $checksums ]] || checksums=$(dirname "$artifact")/checksums.txt
	base=${artifact##*/}
	if [[ $base =~ ^steward-control_(v[^_]+)_linux_${goarch}\.tar\.gz$ ]]; then artifact_version=${BASH_REMATCH[1]}; else echo "install-control: artifact filename does not match linux/$goarch" >&2; exit 2; fi
	if [[ $version == latest ]]; then version=$artifact_version; elif [[ $version != "$artifact_version" ]]; then echo "install-control: artifact version does not match --version" >&2; exit 2; fi
elif [[ -n $offline_dir ]]; then
	[[ -d $offline_dir && ! -L $offline_dir ]] || { echo "install-control: offline directory is invalid" >&2; exit 2; }
	offline_dir=$(readlink -e -- "$offline_dir") || { echo "install-control: offline directory could not be resolved" >&2; exit 2; }
	trusted_root_directory_chain "$offline_dir" || {
		echo "install-control: offline directory and every ancestor must be root-owned and not group/other writable" >&2; exit 2;
	}
	[[ -n $checksums ]] || checksums=$offline_dir/checksums.txt
else
	if [[ -n $checksums ]]; then :
	elif [[ $version == latest ]]; then download "$release_url/latest/download/checksums.txt" "$work/checksums.txt" 4194304; checksums=$work/checksums.txt
	else download "$release_url/download/$version/checksums.txt" "$work/checksums.txt" 4194304; checksums=$work/checksums.txt
	fi
fi

if [[ $checksums != "$work/checksums.txt" ]]; then
	[[ -f $checksums && ! -L $checksums ]] || {
		echo "install-control: local checksums manifest must be a regular non-link file" >&2; exit 1;
	}
	checksums=$(readlink -e -- "$checksums") || { echo "install-control: local checksums manifest could not be resolved" >&2; exit 1; }
	if ! validate_local_source "$checksums" 4194304; then
		echo "install-control: local checksums manifest must be a root-owned one-link non-writable file under a trusted root-owned path" >&2
		exit 1
	fi
	if ! bounded_snapshot "$checksums" "$work/checksums.txt" 4194304 30; then
		echo "install-control: checksums manifest is missing, oversized, special, or changed while creating its bounded snapshot" >&2
		exit 1
	fi
	checksums=$work/checksums.txt
fi
[[ -f $checksums && ! -L $checksums ]] || { echo "install-control: checksums manifest is missing or unsafe" >&2; exit 2; }
if (( $(stat -c '%s' -- "$checksums") <= 0 || $(stat -c '%s' -- "$checksums") > 4194304 )); then
	echo "install-control: checksums manifest is empty or too large" >&2
	exit 2
fi

if [[ $version == latest ]]; then
	matches=()
	while read -r _ listed; do
		listed=${listed#\*}; listed=${listed#./}
		if [[ $listed =~ ^steward-control_(v[^_]+)_linux_${goarch}\.tar\.gz$ ]] && valid_release_version "${BASH_REMATCH[1]}"; then matches+=("$listed"); fi
	done <"$checksums"
	if (( ${#matches[@]} != 1 )); then echo "install-control: checksums must name exactly one linux/$goarch control archive" >&2; exit 1; fi
	base=${matches[0]}; version=${base#steward-control_}; version=${version%_linux_"${goarch}".tar.gz}
fi
valid_release_version "$version" || { echo "install-control: resolved artifact has an invalid version" >&2; exit 1; }
expected_name="steward-control_${version}_linux_${goarch}.tar.gz"
if [[ -z $artifact ]]; then
	if [[ -n $offline_dir ]]; then artifact=$offline_dir/$expected_name
	else artifact=$work/$expected_name; download "$release_url/download/$version/$expected_name" "$artifact" 268435456
	fi
fi
[[ ${artifact##*/} == "$expected_name" ]] || { echo "install-control: expected artifact $expected_name is missing or unsafe" >&2; exit 1; }
if [[ $artifact != "$work/$expected_name" ]]; then
	[[ -f $artifact && ! -L $artifact ]] || {
		echo "install-control: local artifact must be a regular non-link file" >&2; exit 1;
	}
	artifact=$(readlink -e -- "$artifact") || { echo "install-control: local artifact could not be resolved" >&2; exit 1; }
	[[ ${artifact##*/} == "$expected_name" ]] || { echo "install-control: resolved local artifact name changed unexpectedly" >&2; exit 1; }
	if ! validate_local_source "$artifact" 268435456; then
		echo "install-control: local artifact must be a root-owned one-link non-writable file under a trusted root-owned path" >&2
		exit 1
	fi
	if ! bounded_snapshot "$artifact" "$work/$expected_name" 268435456 120; then
		echo "install-control: artifact is missing, oversized, special, or changed while creating its bounded snapshot" >&2
		exit 1
	fi
	artifact=$work/$expected_name
fi
[[ -f $artifact && ! -L $artifact ]] || { echo "install-control: expected artifact $expected_name is missing or unsafe" >&2; exit 1; }
if (( $(stat -c '%s' -- "$artifact") <= 0 || $(stat -c '%s' -- "$artifact") > 268435456 )); then
	echo "install-control: artifact is empty or too large" >&2
	exit 1
fi

digest_lines=()
while read -r digest listed; do
	listed=${listed#\*}; listed=${listed#./}
	[[ $listed == "$expected_name" ]] && digest_lines+=("$digest")
done <"$checksums"
if (( ${#digest_lines[@]} != 1 )) || [[ ! ${digest_lines[0]} =~ ^[0-9a-fA-F]{64}$ ]]; then echo "install-control: checksums does not bind exactly one $expected_name" >&2; exit 1; fi
actual_digest=$(sha256sum "$artifact" | awk '{print $1}')
[[ ${actual_digest,,} == "${digest_lines[0],,}" ]] || { echo "install-control: artifact checksum mismatch" >&2; exit 1; }

expected_files=(LICENSE control.env control-doctor.sh steward-control steward-control.service)
if ! run_bounded_command "$work/archive.list" "$work/archive.list.stderr" 65536 65536 30 262144 \
	tar -tzf "$artifact" || [[ -s $work/archive.list.stderr ]]; then
	echo "install-control: archive inventory listing failed, emitted warnings, or exceeded its resource bounds" >&2
	exit 1
fi
mapfile -t archive_files <"$work/archive.list"
mapfile -t sorted_archive < <(printf '%s\n' "${archive_files[@]}" | LC_ALL=C sort)
mapfile -t sorted_expected < <(printf '%s\n' "${expected_files[@]}" | LC_ALL=C sort)
[[ ${#sorted_archive[@]} -eq ${#sorted_expected[@]} ]] || { echo "install-control: archive contains an unexpected file count" >&2; exit 1; }
for index in "${!sorted_expected[@]}"; do [[ ${sorted_archive[$index]} == "${sorted_expected[$index]}" ]] || { echo "install-control: archive inventory is not allowed" >&2; exit 1; }; done
if ! run_bounded_command "$work/archive.verbose" "$work/archive.verbose.stderr" 65536 65536 30 262144 \
	tar --numeric-owner -tvzf "$artifact" || [[ -s $work/archive.verbose.stderr ]]; then
	echo "install-control: archive metadata listing failed, emitted warnings, or exceeded its resource bounds" >&2
	exit 1
fi
verbose_entries=0
while read -r permissions _ size _ _ name; do
	((verbose_entries += 1))
	[[ $permissions == -* && $size =~ ^[0-9]+$ ]] || { echo "install-control: archive entry is not a regular file" >&2; exit 1; }
	case "$name" in
		steward-control) (( size <= 134217728 )) || { echo "install-control: controller binary exceeds 128 MiB" >&2; exit 1; } ;;
		*) (( size <= 1048576 )) || { echo "install-control: controller support file exceeds 1 MiB" >&2; exit 1; } ;;
	esac
done <"$work/archive.verbose"
(( verbose_entries == ${#expected_files[@]} )) || { echo "install-control: archive metadata count does not match its inventory" >&2; exit 1; }
if ! run_bounded_command "$work/archive.extract.stdout" "$work/archive.extract.stderr" 65536 134217728 30 262144 \
	tar --extract --gzip --file "$artifact" --directory "$work" --no-same-owner --no-same-permissions ||
	[[ -s $work/archive.extract.stdout || -s $work/archive.extract.stderr ]]; then
	echo "install-control: archive extraction failed, emitted unexpected output, or exceeded its resource bounds" >&2
	exit 1
fi
for file in "${expected_files[@]}"; do [[ -f $work/$file && ! -L $work/$file ]] || { echo "install-control: archive contains a link or special file" >&2; exit 1; }; done
if ! (exec 8>&- 9>&-; ulimit -c 0; ulimit -f 16; exec timeout 5 "$work/steward-control" -version) >"$work/version.stdout" 2>"$work/version.stderr" ||
	(( $(stat -c '%s' -- "$work/version.stdout") > 4096 )) || (( $(stat -c '%s' -- "$work/version.stderr") > 4096 )); then
	echo "install-control: controller version check failed or exceeded its bound" >&2
	exit 1
fi
IFS= read -r reported <"$work/version.stdout" || true
[[ $reported == "steward-control $version" ]] || { echo "install-control: binary reports '$reported', expected '$version'" >&2; exit 1; }

for managed_directory in /opt/steward-control "$releases_dir" /usr/local/bin \
	/usr/local/libexec /usr/local/libexec/steward-control /etc/systemd/system "$config_dir"; do
	if ! validate_root_directory_destination "$managed_directory"; then
		echo "install-control: managed directory or its parent chain is unsafe: $managed_directory" >&2
		exit 1
	fi
done

service_group_record=
if ! bounded_identity_query service_group_record service-group getent group "$service_group"; then
	if [[ ${IDENTITY_QUERY_STATUS:-} != 2 ]]; then
		echo "install-control: bounded lookup of $service_group failed" >&2
		exit 1
	fi
	if ! timeout --signal=TERM --kill-after=2 15 groupadd --system "$service_group"; then
		echo "install-control: could not create $service_group within the safety bound" >&2
		exit 1
	fi
	bounded_identity_query service_group_record service-group-created getent group "$service_group" || {
		echo "install-control: created group could not be resolved within the safety bound" >&2; exit 1;
	}
fi
service_record=
if ! bounded_identity_query service_record service-user getent passwd "$service_user"; then
	if [[ ${IDENTITY_QUERY_STATUS:-} != 2 ]]; then
		echo "install-control: bounded lookup of $service_user failed" >&2
		exit 1
	fi
	nologin=
	for candidate in /usr/sbin/nologin /sbin/nologin /usr/bin/nologin /bin/nologin /usr/bin/false /bin/false; do
		if [[ -x $candidate ]]; then nologin=$candidate; break; fi
	done
	[[ -n $nologin ]] || { echo "install-control: no nologin or false service shell is installed" >&2; exit 1; }
	if ! timeout --signal=TERM --kill-after=2 15 \
		useradd --system --gid "$service_group" --home-dir /nonexistent --no-create-home --shell "$nologin" "$service_user"; then
		echo "install-control: could not create $service_user within the safety bound" >&2
		exit 1
	fi
	bounded_identity_query service_record service-user-created getent passwd "$service_user" || {
		echo "install-control: created service identity could not be resolved within the safety bound" >&2; exit 1;
	}
fi
IFS=: read -r record_name _ service_uid service_primary_gid _ service_home service_shell <<<"$service_record"
IFS=: read -r group_name _ service_gid _ <<<"$service_group_record"
[[ $record_name == "$service_user" && $group_name == "$service_group" && $service_uid =~ ^[0-9]+$ &&
	$service_primary_gid =~ ^[0-9]+$ && $service_gid =~ ^[0-9]+$ ]] || {
	echo "install-control: service identity records are malformed" >&2; exit 1;
}
service_numeric_groups=
service_group_name=
service_named_groups=
service_shadow=
bounded_identity_query service_numeric_groups service-id-groups id -G "$service_user" || {
	echo "install-control: service group authority lookup failed or exceeded its bound" >&2; exit 1;
}
bounded_identity_query service_group_name service-id-primary-name id -gn "$service_user" || {
	echo "install-control: service primary group lookup failed or exceeded its bound" >&2; exit 1;
}
bounded_identity_query service_named_groups service-id-group-names id -nG "$service_user" || {
	echo "install-control: service named group lookup failed or exceeded its bound" >&2; exit 1;
}
bounded_identity_query service_shadow service-shadow getent shadow "$service_user" || {
	echo "install-control: service password-lock lookup failed or exceeded its bound" >&2; exit 1;
}
service_password=${service_shadow#*:}
service_password=${service_password%%:*}
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
if ! run_bounded_command "$work/passwd.nss" "$work/passwd.nss.stderr" 8388608 8388608 15 262144 \
	getent passwd || [[ -s $work/passwd.nss.stderr ]] ||
	! run_bounded_command "$work/group.nss" "$work/group.nss.stderr" 8388608 8388608 15 262144 \
		getent group || [[ -s $work/group.nss.stderr ]]; then
	echo "install-control: could not enumerate host identities within the safety bound" >&2
	exit 1
fi
uid_matches=$(awk -F: -v id="$service_uid" '$3 == id { count++ } END { print count + 0 }' "$work/passwd.nss")
gid_matches=$(awk -F: -v id="$service_gid" '$3 == id { count++ } END { print count + 0 }' "$work/group.nss")
docker_gid_collision=$(awk -F: -v id="$service_gid" '$1 == "docker" && $3 == id { found=1 } END { print found + 0 }' "$work/group.nss")
docker_socket_collision=false
for docker_socket in /run/docker.sock /var/run/docker.sock; do
	if [[ -S $docker_socket && $(stat -c '%g' -- "$docker_socket") == "$service_gid" ]]; then
		docker_socket_collision=true
	fi
done
if [[ $service_uid == 0 || $service_gid == 0 || -z $service_gid ||
	$service_primary_gid != "$service_gid" || $service_numeric_groups != "$service_gid" ||
	$uid_matches != 1 || $gid_matches != 1 || $docker_gid_collision != 0 || $docker_socket_collision == true ||
	$service_group_name != "$service_group" ||
	$service_named_groups != "$service_group" || $service_home != /nonexistent ||
	$service_shell_allowed != true || $service_password_locked != true ]]; then
	echo "install-control: steward-control must have unique nonzero numeric UID/GID authority, no Docker or supplementary group authority, and a locked non-login identity" >&2; exit 1
fi

for directory_spec in \
	'/opt/steward-control:0:0755' \
	"$releases_dir:0:0755" \
	'/usr/local/bin:0:0755' \
	'/usr/local/libexec:0:0755' \
	'/usr/local/libexec/steward-control:0:0755' \
	'/etc/systemd/system:0:0755' \
	"$config_dir:$service_gid:0750"; do
	IFS=: read -r managed_directory managed_gid managed_mode <<<"$directory_spec"
	if ! ensure_root_managed_directory "$managed_directory" "$managed_gid" "$managed_mode"; then
		echo "install-control: managed directory or its parent chain is unsafe: $managed_directory" >&2
		exit 1
	fi
done

release_dir=$releases_dir/$version
if [[ -e $release_dir ]]; then
	[[ -d $release_dir && ! -L $release_dir ]] || { echo "install-control: existing release path is unsafe" >&2; exit 1; }
	if [[ $(stat -c '%U:%G %a' -- "$release_dir") != 'root:root 755' ]] ||
		[[ $(find "$release_dir" -mindepth 1 -maxdepth 1 -type f | wc -l) -ne ${#expected_files[@]} ]] ||
		find "$release_dir" -mindepth 1 -maxdepth 1 ! -type f -print -quit | grep -q .; then
		echo "install-control: immutable release $version has unsafe metadata or inventory" >&2
		exit 1
	fi
	for file in "${expected_files[@]}"; do
		case "$file" in steward-control | control-doctor.sh) expected_mode=755 ;; *) expected_mode=644 ;; esac
		if [[ $(stat -c '%U:%G %a' -- "$release_dir/$file" 2>/dev/null) != "root:root $expected_mode" ]] ||
			! cmp -s "$work/$file" "$release_dir/$file"; then
			echo "install-control: immutable release $version differs from verified artifact" >&2
			exit 1
		fi
	done
else
	release_tmp=$releases_dir/.${version}.$$
	install -d -m 0755 "$release_tmp"
	install -m 0755 "$work/steward-control" "$release_tmp/steward-control"
	install -m 0755 "$work/control-doctor.sh" "$release_tmp/control-doctor.sh"
	install -m 0644 "$work/steward-control.service" "$release_tmp/steward-control.service"
	install -m 0644 "$work/control.env" "$release_tmp/control.env"
	install -m 0644 "$work/LICENSE" "$release_tmp/LICENSE"
	for file in "${expected_files[@]}"; do sync -f "$release_tmp/$file"; done
	sync -f "$release_tmp"
	mv "$release_tmp" "$release_dir"
	sync -f "$releases_dir"
fi

if [[ -e $current_link && ! -L $current_link ]] || [[ -e $binary_link && ! -L $binary_link ]] || [[ -e $doctor_link && ! -L $doctor_link ]] || [[ -e $unit_link && ! -L $unit_link ]]; then
	echo "install-control: refusing to replace a non-installer file at a managed link path" >&2; exit 1
fi
if [[ $authority_mode == strict-sovereign ]] &&
	{ [[ -e $controller_private_key || -L $controller_private_key ]] ||
		[[ -e $controller_public_key || -L $controller_public_key ]]; }; then
	echo "install-control: strict-sovereign requires both controller signing-key files to be absent; expire every delegation that names the key, archive any required public identity, and remove both files before retrying" >&2
	exit 1
fi
snapshot_control_service_state || exit 1
if ! prepare_durable_transaction; then
	echo "install-control: could not persist the rollback journal before changing controller state" >&2
	exit 1
fi
if [[ $service_was_active == true ]]; then bounded_systemctl stop steward-control.service; fi

if [[ $tls_supplied == true ]]; then
	install -m 0640 -o root -g "$service_group" "$tls_cert" "$config_dir/.tls.crt.$$"
	install -m 0600 -o "$service_user" -g "$service_group" "$tls_key" "$config_dir/.tls.key.$$"
	mv "$config_dir/.tls.crt.$$" "$tls_cert_dest"; mv "$config_dir/.tls.key.$$" "$tls_key_dest"
	desired_cert=$tls_cert_dest; desired_key=$tls_key_dest
elif [[ $preserve_tls == true ]]; then
	if [[ ! -f $tls_cert_dest || -L $tls_cert_dest || $(stat -c '%u:%g:%a:%h' -- "$tls_cert_dest") != "0:$service_gid:640:1" ||
		! -f $tls_key_dest || -L $tls_key_dest || $(stat -c '%u:%g:%a:%h' -- "$tls_key_dest") != "$service_uid:$service_gid:600:1" ]] ||
		(( $(stat -c '%s' -- "$tls_cert_dest") <= 0 || $(stat -c '%s' -- "$tls_cert_dest") > 1048576 ||
			$(stat -c '%s' -- "$tls_key_dest") <= 0 || $(stat -c '%s' -- "$tls_key_dest") > 1048576 )); then
		echo "install-control: preserved TLS files have unsafe ownership, mode, link count, size, or type" >&2
		exit 1
	fi
	desired_cert=$tls_cert_dest; desired_key=$tls_key_dest
else
	rm -f "$tls_cert_dest" "$tls_key_dest"; desired_cert=; desired_key=
fi

config_tmp=$config_dir/.control.env.$$
{
	echo "STEWARD_CONTROL_ADDR=$address"
	echo "STEWARD_CONTROL_STATE_DIR=$state_dir"
	echo "STEWARD_CONTROL_AUTH_KEY_FILE=$state_dir/auth.key"
	echo "STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE=$witness_private_key"
	echo "STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE=$witness_public_key"
	echo "STEWARD_CONTROL_CONTROLLER_PRIVATE_KEY_FILE=$controller_private_key"
	echo "STEWARD_CONTROL_CONTROLLER_PUBLIC_KEY_FILE=$controller_public_key"
	echo "STEWARD_CONTROL_CONTROLLER_KEY_ID=$controller_key_id"
	echo "STEWARD_CONTROL_RECONCILE_INTERVAL=$reconcile_interval"
	echo "STEWARD_CONTROL_AUTHORITY_MODE=$authority_mode"
	echo "STEWARD_CONTROL_TLS_CERT_FILE=$desired_cert"
	echo "STEWARD_CONTROL_TLS_KEY_FILE=$desired_key"
	echo "STEWARD_CONTROL_ENABLE_METRICS=$enable_metrics"
	echo "STEWARD_CONTROL_NODE_STALE_AFTER=$node_stale_after"
	echo "STEWARD_CONTROL_EVIDENCE_STALE_AFTER=$evidence_stale_after"
	echo "STEWARD_CONTROL_COMMAND_OVERDUE_AFTER=$command_overdue_after"
	echo "STEWARD_CONTROL_CAPACITY_WARNING_PERCENT=$capacity_warning_percent"
} >"$config_tmp"
chown root:root "$config_tmp"; chmod 0600 "$config_tmp"; mv "$config_tmp" "$config_file"

state_nonempty=false
if [[ -e $state_dir || -L $state_dir ]]; then
	if [[ ! -d $state_dir || -L $state_dir ]]; then
		echo "install-control: durable state path is not a real directory" >&2
		exit 1
	fi
	if find "$state_dir" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then state_nonempty=true; fi
fi

if [[ $state_nonempty == false ]]; then
	install -d -m 0700 -o "$service_user" -g "$service_group" "$state_dir"
	state_identity=service
else
	if [[ ! -f $state_dir/CURRENT || -L $state_dir/CURRENT ]]; then
		echo "install-control: durable state is partial or unrecognized; refusing automatic recovery" >&2
		exit 1
	fi
	state_metadata=$(stat -c '%u:%g:%a' -- "$state_dir")
	case "$state_metadata" in
		"$service_uid:$service_gid:700") state_identity=service; validate_state_tree "$service_uid" "$service_gid" ;;
		0:0:700) state_identity=root; validate_state_tree 0 0 ;;
		*)
			echo "install-control: durable state must be uniformly root-owned interrupted state or steward-control-owned state" >&2
			exit 1
			;;
	esac
fi

handoff_needed=false
if [[ -n $admin_token_out && $admin_token_preexisting == false ]]; then handoff_needed=true; fi
if [[ ! -f $state_dir/auth.key || -L $state_dir/auth.key ]]; then
	if [[ $handoff_needed == false ]]; then
		echo "install-control: durable state has no usable auth key; recovery requires a new, unused --admin-token-out path" >&2
		exit 1
	fi
fi

if [[ $handoff_needed == true ]]; then
	handoff_dir=/run/steward-control-handoff.$$
	if [[ -e $handoff_dir || -L $handoff_dir ]]; then
		echo "install-control: bootstrap handoff path already exists" >&2
		exit 1
	fi
	if [[ $state_identity == service ]]; then
		install -d -m 0700 -o "$service_user" -g "$service_group" "$handoff_dir"
		handoff_uid=$service_uid; handoff_gid=$service_gid
	else
		install -d -m 0700 -o root -g root "$handoff_dir"
		handoff_uid=0; handoff_gid=0
	fi
	handoff_file=$handoff_dir/admin.token
	initialize_args=(-initialize -addr 127.0.0.1:0 -state-dir "$state_dir" \
		-auth-key-file "$state_dir/auth.key" -admin-token-file "$handoff_file" \
		-witness-private-key-file "$witness_private_key" \
		-witness-public-key-file "$witness_public_key" \
		-controller-private-key-file "$controller_private_key" \
		-controller-public-key-file "$controller_public_key" \
		-authority-mode "$authority_mode")
	if [[ $state_identity == service ]]; then
		if ! timeout --signal=TERM --kill-after=2 30 \
			runuser -u "$service_user" -- "$release_dir/steward-control" "${initialize_args[@]}" >/dev/null; then
			echo "install-control: controller initialization failed or exceeded its 30-second bound" >&2
			exit 1
		fi
	else
		if ! timeout --signal=TERM --kill-after=2 30 \
			"$release_dir/steward-control" "${initialize_args[@]}" >/dev/null; then
			echo "install-control: controller initialization failed or exceeded its 30-second bound" >&2
			exit 1
		fi
	fi
	if [[ ! -f $handoff_file || -L $handoff_file ||
		$(stat -c '%u:%g:%a:%h' -- "$handoff_file") != "$handoff_uid:$handoff_gid:600:1" ]] ||
		(( $(stat -c '%s' -- "$handoff_file") <= 0 || $(stat -c '%s' -- "$handoff_file") > 4096 )); then
		echo "install-control: bootstrap produced an unsafe token handoff" >&2
		exit 1
	fi
fi

if [[ $state_identity == root ]]; then
	validate_state_tree 0 0
	chown -hR "$service_user:$service_group" "$state_dir"
	chmod 0700 "$state_dir"
	state_identity=service
fi
if [[ $(stat -c '%u:%g:%a' -- "$state_dir") != "$service_uid:$service_gid:700" ]]; then
	echo "install-control: durable state migration did not produce the required service ownership" >&2
	exit 1
fi
validate_state_tree "$service_uid" "$service_gid"

if [[ $authority_mode == bounded-autonomous ]]; then
	controller_args=(-initialize-controller-key -addr 127.0.0.1:0 -state-dir "$state_dir" \
		-auth-key-file "$state_dir/auth.key" \
		-controller-private-key-file "$controller_private_key" \
		-controller-public-key-file "$controller_public_key")
	if ! timeout --signal=TERM --kill-after=2 30 \
		runuser -u "$service_user" -- "$release_dir/steward-control" "${controller_args[@]}" >/dev/null; then
		echo "install-control: controller signing-key initialization failed or exceeded its 30-second bound; existing key files were not replaced" >&2
		exit 1
	fi
fi
validate_state_tree "$service_uid" "$service_gid"

witness_args=(-initialize-witness-key -addr 127.0.0.1:0 -state-dir "$state_dir" \
	-auth-key-file "$state_dir/auth.key" \
	-witness-private-key-file "$witness_private_key" \
	-witness-public-key-file "$witness_public_key" \
	-controller-private-key-file "$controller_private_key" \
	-controller-public-key-file "$controller_public_key")
if ! timeout --signal=TERM --kill-after=2 30 \
	runuser -u "$service_user" -- "$release_dir/steward-control" "${witness_args[@]}" >/dev/null; then
	echo "install-control: controller witness-key initialization failed or exceeded its 30-second bound; existing key files were not replaced" >&2
	exit 1
fi
validate_state_tree "$service_uid" "$service_gid"

if [[ $handoff_needed == true ]]; then
	handoff_digest=$(sha256sum "$handoff_file" | awk '{print $1}')
	[[ $handoff_digest =~ ^[0-9a-f]{64}$ ]] || { echo "install-control: could not bind the admin token handoff to the durable journal" >&2; exit 1; }
	write_journal_file "$installer_transaction/admin-token.digest" "$handoff_digest"
	sync -f "$installer_transaction"
	publish_admin_token "$handoff_file" "$admin_token_out"
	rm -rf -- "$handoff_dir"
	handoff_dir=
fi

check_args=(-check-config -addr "$address" -state-dir "$state_dir" \
	-auth-key-file "$state_dir/auth.key" \
	-witness-private-key-file "$witness_private_key" \
	-witness-public-key-file "$witness_public_key" \
	-controller-private-key-file "$controller_private_key" \
	-controller-public-key-file "$controller_public_key" \
	-controller-key-id "$controller_key_id" \
	-reconcile-interval "$reconcile_interval" \
	-authority-mode "$authority_mode")
if [[ -n $desired_cert ]]; then check_args+=(-tls-cert-file "$desired_cert" -tls-key-file "$desired_key"); fi
if ! timeout --signal=TERM --kill-after=2 15 \
	runuser -u "$service_user" -- "$release_dir/steward-control" "${check_args[@]}" >/dev/null; then
	echo "install-control: controller configuration check failed or exceeded its 15-second bound" >&2
	exit 1
fi

if [[ -n $admin_token_out ]]; then
	prove_admin_token "$admin_token_out"
fi

replace_link "$current_link" "$release_dir"
replace_link "$binary_link" "$current_link/steward-control"
replace_link "$doctor_link" "$current_link/control-doctor.sh"
replace_link "$unit_link" "$current_link/steward-control.service"
timeout --signal=TERM --kill-after=2 15 systemd-analyze verify "$unit_link" >/dev/null
bounded_systemctl daemon-reload
bounded_systemctl enable steward-control.service >/dev/null
if [[ $start_service == true ]]; then
	bounded_systemctl restart steward-control.service
	ready=false
	for _ in {1..40}; do
		if bounded_systemctl is-active --quiet steward-control.service; then ready=true; sleep 1; bounded_systemctl is-active --quiet steward-control.service && break; ready=false; fi
		sleep 0.25
	done
	[[ $ready == true ]] || { echo "install-control: service did not become active" >&2; exit 1; }
fi

if ! commit_durable_transaction; then
	echo "install-control: could not durably commit the controller transaction" >&2
	exit 1
fi
trap - EXIT HUP INT TERM
rm -rf "$work"
echo "Steward Control $version is installed."
echo "  listener: $address"
echo "  state:    $state_dir"
echo "  witness public key: $witness_public_key"
echo "  authority mode: $authority_mode"
if [[ $authority_mode == bounded-autonomous ]]; then
	echo "  controller public key: $controller_public_key ($controller_key_id)"
else
	echo "  controller signing key: not loaded or created"
fi
echo "  doctor:   sudo $doctor_link"
if [[ $admin_token_created == true ]]; then echo "  admin token: $admin_token_out (contents shown once in that file only)"; fi
