#!/bin/bash -p
# Provision node trust material, validate it, and optionally start Steward.
set -Eeuo pipefail
set +x
if ! shopt -qo privileged; then
	echo "configure-node: execute this root helper directly or invoke it with /bin/bash -p" >&2
	exit 2
fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C LANG=C
unset BASH_ENV CDPATH ENV GLOBIGNORE POSIXLY_CORRECT
IFS=$' \t\n'
umask 077

usage() {
	cat <<'EOF'
Usage: configure-node.sh OPTIONS

Remote enrollment (omit with --local-only):
  --control-plane-url URL       HTTPS control-plane base URL
  --steward-credential FILE     Optional supervisor uplink credential JSON.
                                Omit with steward-control; the supervisor then
                                stays loopback-only with durable local state.
  --executor-credential FILE    Executor uplink credential JSON
  --ca-file FILE                PEM CA bundle for the control plane

Signed admission (all trust inputs are optional as one group):
  --admission-policy FILE       Site-root-signed site policy DSSE envelope
  --site-root-public-key FILE   Base64 Ed25519 site-root public key
  --site-root-key-id ID         Signature key ID used by the policy
  --node-id ID                  Stable node ID (machine-derived if omitted)
  --executor-evidence-config FILE
                                Enrollment evidence config from stewardctl
  --executor-evidence-private-key FILE
                                Receipt private key used during enrollment
  --executor-evidence-public-key FILE
                                Matching receipt public key
  --allow-host-admin-intent     Let the host-admin token select signed tenant intent
  --allow-unquotaed-state-on-dedicated-host
                                Allow persistent Docker volumes only when the
                                signed policy contains exactly one tenant; no
                                hard byte or inode quota is enforced

Optional:
  --local-only                 Configure loopback HTTP, CLI, and MCP without an uplink
  --executor-token FILE         Existing host-admin bearer token; generated if omitted
  --executor-uplink-protocol-version VERSION
                                Use protocol 3 or 4 for a node-scoped credential.
                                The default is 4; use 3 only for controller
                                compatibility.
  --no-start                    Validate and configure, but leave services stopped
  -h, --help                    Show this help

The operation is transactional through preflight: invalid input restores the
previous files under /etc/steward and removes state files created by this run.
Existing Executor fence, delivery, journal, and evidence state is never reset.
When --steward-credential is omitted, the Executor credential must be
node-scoped and signed admission must already exist or be supplied in this run.
Copy every input file to a protected, root-owned directory before invoking this
command. Input files in /tmp, home directories, or writable parent directories
are rejected.
EOF
}

control_plane_url=
steward_credential=
executor_credential=
ca_file=
executor_token=
executor_uplink_protocol=
selected_uplink_protocol=0
admission_policy=
site_root=
site_root_key_id=
node_id=
executor_evidence_config=
receipt_private=
receipt_public=
allow_host_admin=false
allow_unquotaed_state=false
start_services=true
local_only=false
while [[ $# -gt 0 ]]; do
	case "$1" in
		--control-plane-url) control_plane_url=${2:-}; shift 2 ;;
		--steward-credential) steward_credential=${2:-}; shift 2 ;;
		--executor-credential) executor_credential=${2:-}; shift 2 ;;
		--ca-file) ca_file=${2:-}; shift 2 ;;
		--executor-token) executor_token=${2:-}; shift 2 ;;
		--executor-uplink-protocol-version)
			if (( $# < 2 )); then
				echo "configure-node: --executor-uplink-protocol-version requires 3 or 4" >&2
				exit 2
			fi
			executor_uplink_protocol=$2
			shift 2
			;;
		--admission-policy) admission_policy=${2:-}; shift 2 ;;
		--site-root-public-key) site_root=${2:-}; shift 2 ;;
		--site-root-key-id) site_root_key_id=${2:-}; shift 2 ;;
		--node-id) node_id=${2:-}; shift 2 ;;
		--executor-evidence-config) executor_evidence_config=${2:-}; shift 2 ;;
		--executor-evidence-private-key) receipt_private=${2:-}; shift 2 ;;
		--executor-evidence-public-key) receipt_public=${2:-}; shift 2 ;;
		--allow-host-admin-intent) allow_host_admin=true; shift ;;
		--allow-unquotaed-state-on-dedicated-host) allow_unquotaed_state=true; shift ;;
		--local-only) local_only=true; shift ;;
		--no-start) start_services=false; shift ;;
		-h | --help) usage; exit 0 ;;
		*) echo "configure-node: unknown option $1" >&2; usage >&2; exit 2 ;;
	esac
done

if [[ ${EUID} -ne 0 ]]; then
	echo "configure-node: run as root" >&2
	exit 2
fi
if [[ $(uname -s) != Linux ]]; then
	echo "configure-node: Linux is required" >&2
	exit 2
fi
if [[ -n $executor_uplink_protocol && $executor_uplink_protocol != 3 && $executor_uplink_protocol != 4 ]]; then
	echo "configure-node: --executor-uplink-protocol-version must be 3 or 4" >&2
	exit 2
fi
if [[ $local_only == false && $control_plane_url != https://* ]]; then
	echo "configure-node: --control-plane-url must use HTTPS" >&2
	exit 2
fi
case "$control_plane_url" in
	*[[:space:]]* | *\"* | *\\*)
		echo "configure-node: control-plane URL contains an unsafe character" >&2
		exit 2
		;;
esac
if [[ $local_only == true ]]; then
	if [[ -n $control_plane_url || -n $steward_credential || -n $executor_credential || -n $ca_file ]]; then
		echo "configure-node: --local-only cannot be combined with remote enrollment inputs" >&2
		exit 2
	fi
	if [[ -n $executor_uplink_protocol ]]; then
		echo "configure-node: --executor-uplink-protocol-version requires remote node-scoped enrollment" >&2
		exit 2
	fi
else
	for input in "$executor_credential" "$ca_file"; do
		if [[ -z $input ]]; then
			echo "configure-node: required Executor enrollment input is missing" >&2
			exit 2
		fi
	done
fi
executor_only=false
if [[ $local_only == false && -z $steward_credential ]]; then
	executor_only=true
fi
admission_required=0
for value in "$admission_policy" "$site_root" "$site_root_key_id"; do
	[[ -z $value ]] || ((admission_required += 1))
done
if (( admission_required != 0 && admission_required != 3 )); then
	echo "configure-node: signed admission requires --admission-policy, --site-root-public-key, and --site-root-key-id together" >&2
	exit 2
fi
if (( admission_required == 0 )) && { [[ -n $node_id ]] || [[ $allow_host_admin == true ]]; }; then
	echo "configure-node: --node-id and --allow-host-admin-intent require signed admission trust inputs" >&2
	exit 2
fi
if (( admission_required == 0 )) && [[ $allow_unquotaed_state == true ]]; then
	echo "configure-node: --allow-unquotaed-state-on-dedicated-host requires signed admission trust inputs" >&2
	exit 2
fi
evidence_input_count=0
for value in "$executor_evidence_config" "$receipt_private" "$receipt_public"; do
	[[ -z $value ]] || ((evidence_input_count += 1))
done
if (( evidence_input_count != 0 && evidence_input_count != 3 )); then
	echo "configure-node: Executor evidence enrollment requires config, private key, and public key together" >&2
	exit 2
fi
if (( evidence_input_count == 3 && admission_required != 3 )); then
	echo "configure-node: Executor evidence enrollment requires signed-admission trust inputs in the same transaction" >&2
	exit 2
fi
if (( evidence_input_count == 3 )) && [[ $local_only == true ]]; then
	echo "configure-node: Executor evidence enrollment requires a remote control plane" >&2
	exit 2
fi
if (( admission_required == 3 )); then
	[[ $site_root_key_id =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$ ]] || {
		echo "configure-node: invalid --site-root-key-id" >&2
		exit 2
	}
	if [[ -n $node_id && ! $node_id =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; then
		echo "configure-node: invalid --node-id" >&2
		exit 2
	fi
fi
for identity in steward steward-executor steward-gateway; do
	id "$identity" >/dev/null 2>&1 || {
		echo "configure-node: missing service identity $identity; install Steward first" >&2
		exit 2
	}
done
for path in /etc/steward/steward.json /etc/steward/executor.env \
	/usr/local/bin/stewardctl /usr/local/bin/steward-executor \
	/usr/local/libexec/steward/node-preflight; do
	if [[ ! -e $path ]]; then
		echo "configure-node: missing installed path $path; install Steward first" >&2
		exit 2
	fi
done
if (( admission_required == 3 )) && [[ ! -x /usr/local/libexec/steward/configure-admission ]]; then
	echo "configure-node: missing signed-admission configurator; install Steward first" >&2
	exit 2
fi

# BEGIN TRUSTED_INPUT_BOUNDARY
# Operator-supplied files are hostile until they have been copied into this
# process's private root-owned staging directory. Requiring a protected parent
# chain prevents a non-root writer from replacing a validated path between the
# metadata checks and the no-follow snapshot.
trusted_input_error() {
	echo "configure-node: $1; copy the input to a protected root-owned directory and retry" >&2
	return 2
}

trusted_input_clean_absolute_path() {
	local path=$1
	[[ $path == /* && $path != / && $path != //* && $path != */ && \
		$path != *//* && $path != *[[:cntrl:]]* ]] || return 1
	case "/${path#/}/" in
		*/./* | */../*) return 1 ;;
	esac
}

trusted_input_validate_directory() {
	local directory=$1 label=$2 metadata raw_mode owner raw_value permissions
	if [[ -L $directory ]] || ! metadata=$(stat -c '%f|%u' -- "$directory" 2>/dev/null); then
		trusted_input_error "$label has an unsafe ancestor: $directory"
		return
	fi
	IFS='|' read -r raw_mode owner <<<"$metadata"
	if [[ ! $raw_mode =~ ^[0-9a-fA-F]+$ || ! $owner =~ ^[0-9]+$ ]]; then
		trusted_input_error "$label ancestor metadata is invalid: $directory"
		return
	fi
	raw_value=$((16#$raw_mode))
	permissions=$((raw_value & 07777))
	if (( (raw_value & 0170000) != 0040000 || owner != 0 || (permissions & 0022) != 0 )); then
		trusted_input_error "$label must be beneath root-owned directories that are not group/world-writable: $directory"
		return
	fi
}

trusted_input_validate_ancestors() {
	local path=$1 label=$2 parent current remaining component
	parent=${path%/*}
	[[ -n $parent ]] || parent=/
	trusted_input_validate_directory / "$label" || return
	current=/
	remaining=${parent#/}
	while [[ -n $remaining ]]; do
		component=${remaining%%/*}
		if [[ $remaining == */* ]]; then
			remaining=${remaining#*/}
		else
			remaining=
		fi
		current=${current%/}/$component
		trusted_input_validate_directory "$current" "$label" || return
	done
}

trusted_input_snapshot() {
	local source=$1 destination=$2 label=$3 max_bytes=$4 owner_only=$5
	local before after raw_mode owner group links size rest raw_value permissions
	if ! trusted_input_clean_absolute_path "$source"; then
		trusted_input_error "$label path must be a clean absolute path"
		return
	fi
	trusted_input_validate_ancestors "$source" "$label" || return
	if [[ -L $source ]] || ! before=$(stat -c '%d|%i|%f|%u|%g|%h|%s|%b|%B|%y|%z|%w' -- "$source" 2>/dev/null); then
		trusted_input_error "$label must be a non-symlink regular file"
		return
	fi
	IFS='|' read -r _ _ raw_mode owner group links size rest <<<"$before"
	if [[ ! $raw_mode =~ ^[0-9a-fA-F]+$ || ! $owner =~ ^[0-9]+$ || \
		! $group =~ ^[0-9]+$ || ! $links =~ ^[0-9]+$ || ! $size =~ ^[0-9]+$ ]]; then
		trusted_input_error "$label metadata is invalid"
		return
	fi
	raw_value=$((16#$raw_mode))
	permissions=$((raw_value & 07777))
	if (( (raw_value & 0170000) != 0100000 || owner != 0 || links != 1 || (permissions & 0022) != 0 )); then
		trusted_input_error "$label must be a root-owned, single-link regular file that is not group/world-writable"
		return
	fi
	if [[ $owner_only == true ]] && (( (permissions & 07077) != 0 )); then
		trusted_input_error "$label contains a credential or token and must be accessible only by root"
		return
	fi
	if (( size > max_bytes )); then
		trusted_input_error "$label exceeds the $max_bytes-byte limit"
		return
	fi
	rm -f -- "$destination"
	if ! ( umask 077; set -o noclobber; : >"$destination" ) 2>/dev/null; then
		trusted_input_error "$label snapshot could not be created exclusively"
		return
	fi
	if ! (
		ulimit -c 0
		ulimit -f $((max_bytes / 512))
		ulimit -t 5
		timeout --signal=KILL 10 dd if="$source" of="$destination" bs=4096 \
			iflag=nofollow,nonblock,fullblock oflag=nofollow,nonblock conv=notrunc status=none
	) 2>/dev/null; then
		rm -f -- "$destination"
		trusted_input_error "$label could not be snapshotted within its size and time limits"
		return
	fi
	# Access time is intentionally excluded because this read may update it.
	if ! after=$(stat -c '%d|%i|%f|%u|%g|%h|%s|%b|%B|%y|%z|%w' -- "$source" 2>/dev/null) || \
		[[ $after != "$before" ]]; then
		rm -f -- "$destination"
		trusted_input_error "$label changed while it was being snapshotted"
		return
	fi
	chown root:root "$destination"
	chmod 0600 "$destination"
	if [[ -L $destination ]] || \
		! after=$(stat -c '%f|%u|%g|%h|%s' -- "$destination" 2>/dev/null); then
		rm -f -- "$destination"
		trusted_input_error "$label snapshot could not be secured"
		return
	fi
	IFS='|' read -r raw_mode owner group links rest <<<"$after"
	raw_value=$((16#$raw_mode))
	permissions=$((raw_value & 07777))
	if (( (raw_value & 0170000) != 0100000 || owner != 0 || group != 0 || \
		links != 1 || permissions != 0600 || rest != size )); then
		rm -f -- "$destination"
		trusted_input_error "$label snapshot did not retain the validated file exactly"
		return
	fi
}

create_trusted_input_stage() {
	trusted_input_validate_directory / "input staging" || return
	trusted_input_validate_directory /run "input staging" || return
	input_stage=$(mktemp -d -- "${input_stage_prefix}XXXXXX") || {
		trusted_input_error "could not create the private input staging directory"
		return
	}
	chown root:root "$input_stage"
	chmod 0700 "$input_stage"
	local metadata raw_mode owner group raw_value permissions
	metadata=$(stat -c '%f|%u|%g' -- "$input_stage") || return
	IFS='|' read -r raw_mode owner group <<<"$metadata"
	raw_value=$((16#$raw_mode))
	permissions=$((raw_value & 07777))
	if (( (raw_value & 0170000) != 0040000 || owner != 0 || group != 0 || permissions != 0700 )); then
		trusted_input_error "private input staging directory could not be secured"
		return
	fi
}

stage_node_input_sources() {
	if [[ $local_only == false ]]; then
		if [[ -n $steward_credential ]]; then
			trusted_input_snapshot "$steward_credential" "$input_stage/steward-credential.json" \
				"supervisor credential" 65536 true || return
			steward_credential=$input_stage/steward-credential.json
		fi
		trusted_input_snapshot "$executor_credential" "$input_stage/executor-credential.json" \
			"Executor credential" 65536 true || return
		executor_credential=$input_stage/executor-credential.json
		trusted_input_snapshot "$ca_file" "$input_stage/control-plane-ca.pem" \
			"control-plane CA" 1048576 false || return
		ca_file=$input_stage/control-plane-ca.pem
	fi
	if [[ -n $executor_token ]]; then
		trusted_input_snapshot "$executor_token" "$input_stage/executor-token" \
			"Executor token" 4096 true || return
		executor_token=$input_stage/executor-token
	fi
	if (( admission_required == 3 )); then
		trusted_input_snapshot "$admission_policy" "$input_stage/site-policy.dsse.json" \
			"admission policy" 1048576 false || return
		admission_policy=$input_stage/site-policy.dsse.json
		trusted_input_snapshot "$site_root" "$input_stage/site-root.public" \
			"site-root public key" 4096 false || return
		site_root=$input_stage/site-root.public
	fi
	if (( evidence_input_count == 3 )); then
		trusted_input_snapshot "$executor_evidence_config" "$input_stage/executor-evidence.env" \
			"Executor evidence config" 4096 true || return
		executor_evidence_config=$input_stage/executor-evidence.env
		trusted_input_snapshot "$receipt_private" "$input_stage/node-receipts.private.pem" \
			"receipt private key" 16384 true || return
		receipt_private=$input_stage/node-receipts.private.pem
		trusted_input_snapshot "$receipt_public" "$input_stage/node-receipts.public" \
			"receipt public key" 4096 false || return
		receipt_public=$input_stage/node-receipts.public
	fi
}

cleanup_trusted_input_stage() {
	local status=$?
	trap - EXIT
	if [[ -n ${input_stage:-} && $input_stage == "$input_stage_prefix"* ]]; then
		rm -rf -- "$input_stage"
	fi
	exit "$status"
}
# END TRUSTED_INPUT_BOUNDARY

# BEGIN NODE_LOCK_BOUNDARY
readonly node_lock_directory=/run/steward-node
readonly node_lock_file=$node_lock_directory/activation.lock
readonly node_lock_error_prefix=configure-node

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
		echo "$node_lock_error_prefix: flock is required to serialize node configuration" >&2
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

use_inherited_node_lock() {
	local fd=${1:-}
	prepare_node_lock || return
	if ! node_lock_fd_matches "$fd" || ! flock -n "$fd"; then
		echo "$node_lock_error_prefix: inherited node lock descriptor is missing, unlocked, or does not match $node_lock_file" >&2
		return 2
	fi
}
# END NODE_LOCK_BOUNDARY

acquire_node_lock 60

input_stage_prefix=/run/steward-node-inputs.
input_stage=
trap cleanup_trusted_input_stage EXIT
create_trusted_input_stage
stage_node_input_sources

evidence_controller_instance_id=
evidence_node_id=
evidence_public_key=
evidence_config_error() {
	echo "configure-node: $1" >&2
	return 2
}
parse_executor_evidence_config() {
	local line key value invalid_bytes
	declare -A seen=()
	invalid_bytes=$(LC_ALL=C tr -d '\12\40-\176' <"$executor_evidence_config" | wc -c)
	if [[ $invalid_bytes != 0 ]]; then
		evidence_config_error "Executor evidence config must contain printable ASCII lines"
		return
	fi
	while IFS= read -r line || [[ -n $line ]]; do
		if [[ ! $line =~ ^([A-Z0-9_]+)=(.*)$ ]]; then
			evidence_config_error "Executor evidence config contains an invalid line"
			return
		fi
		key=${BASH_REMATCH[1]}
		value=${BASH_REMATCH[2]}
		if [[ ${seen[$key]+present} == present ]]; then
			evidence_config_error "Executor evidence config contains duplicate settings"
			return
		fi
		seen[$key]=1
		case "$key" in
			STEWARD_EXECUTOR_EVIDENCE_CONFIG_VERSION)
				if [[ $value != 1 ]]; then
					evidence_config_error "unsupported Executor evidence config version"
					return
				fi
				;;
			STEWARD_EXECUTOR_EVIDENCE_CONTROLLER_INSTANCE_ID)
				evidence_controller_instance_id=$value
				;;
			STEWARD_EXECUTOR_EVIDENCE_NODE_ID)
				evidence_node_id=$value
				;;
			STEWARD_EXECUTOR_EVIDENCE_RECEIPT_EPOCH)
				if [[ $value != 1 ]]; then
					evidence_config_error "unsupported Executor receipt epoch"
					return
				fi
				;;
			STEWARD_EXECUTOR_EVIDENCE_PUBLIC_KEY_BASE64)
				evidence_public_key=$value
				;;
			*)
				evidence_config_error "Executor evidence config contains an unknown setting"
				return
				;;
		esac
	done <"$executor_evidence_config"
	if (( ${#seen[@]} != 5 )) ||
		[[ ! $evidence_controller_instance_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
		[[ ! $evidence_node_id =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] ||
		[[ ! $evidence_public_key =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
		evidence_config_error "Executor evidence config is incomplete or invalid"
		return
	fi
}
if (( evidence_input_count == 3 )); then
	parse_executor_evidence_config
	receipt_public_value=$(<"$receipt_public")
	if [[ $receipt_public_value != "$evidence_public_key" ]]; then
		evidence_config_error "receipt public key does not match the enrollment evidence config"
	fi
	/usr/local/bin/stewardctl key match -private-key "$receipt_private" \
		-public-key "$receipt_public" >/dev/null
fi

install -d -o root -g root -m 0755 /etc/steward
backup_dir=$(mktemp -d /etc/steward/.configure-backup.XXXXXX)
targets=(
	/etc/steward/steward.json
	/etc/steward/executor.env
	/etc/steward/executor-gateway.env
	/etc/steward/uplink-credential.json
	/etc/steward/executor-uplink.json
	/etc/steward/executor-token
	/etc/steward/executor-operator-token
	/etc/steward/executor-observer-token
	/etc/steward/control-plane-ca.pem
	/etc/steward/site-policy.dsse.json
	/etc/steward/site-root.public
	/etc/steward/node-receipts.private.pem
	/etc/steward/node-receipts.public
)
for target in "${targets[@]}"; do
	name=${target##*/}
	if [[ -e $target || -L $target ]]; then
		cp -a -- "$target" "$backup_dir/$name"
	else
		: >"$backup_dir/$name.absent"
	fi
done

committed=false
steward_tmp=
executor_tmp=
token_tmp=
scoped_token_tmp=
atomic_tmp=
uplink_fence=/var/lib/steward-executor/uplink-state.json
uplink_delivery_state=/var/lib/steward-executor/uplink-delivery-state.json
admission_fence=/var/lib/steward-executor/admission-fences.bin
operation_journal=/var/lib/steward-executor/operation-journal.bin
evidence_log=/var/lib/steward-executor/evidence.bin
uplink_fence_created=false
uplink_delivery_state_created=false
admission_fence_created=false
operation_journal_created=false
evidence_log_created=false
rollback() {
	status=$?
	trap - ERR INT TERM
	if [[ $committed != true ]]; then
		for target in "${targets[@]}"; do
			name=${target##*/}
			if [[ -e $backup_dir/$name || -L $backup_dir/$name ]]; then
				rm -f -- "$target"
				cp -a -- "$backup_dir/$name" "$target"
			else
				rm -f -- "$target"
			fi
		done
		[[ $uplink_fence_created == false ]] || rm -f -- "$uplink_fence"
		[[ $uplink_delivery_state_created == false ]] || rm -f -- "$uplink_delivery_state"
		[[ $admission_fence_created == false ]] || rm -f -- "$admission_fence"
		[[ $operation_journal_created == false ]] || rm -f -- "$operation_journal"
		[[ $evidence_log_created == false ]] || rm -f -- "$evidence_log"
		echo "configure-node: preflight failed; restored previous configuration" >&2
	fi
	rm -f -- "${steward_tmp:-}" "${executor_tmp:-}" "${token_tmp:-}" "${scoped_token_tmp:-}" "${atomic_tmp:-}"
	rm -rf -- "$backup_dir"
	exit "$status"
}
trap rollback ERR INT TERM

transaction_error() {
	echo "configure-node: $1" >&2
	return 2
}

select_configured_uplink_protocol() {
	local credential_scope=$1 requested=$2
	case "$credential_scope" in
		node)
			case "$requested" in
				"") printf '4\n' ;;
				3 | 4) printf '%s\n' "$requested" ;;
				*) return 2 ;;
			esac
		;;
		tenant | local)
			[[ -z $requested ]] || return 2
			printf '0\n'
			;;
		*) return 2 ;;
	esac
}

write_loopback_supervisor_config() {
	cat <<'EOF'
{
  "addr": "127.0.0.1:8080",
  "disable_inbound_listener": false,
  "enable_process_exec": false,
  "log_level": "info",
  "max_instances": 1024,
  "state_file": "/var/lib/steward/state.json"
}
EOF
}

steward_tmp=$(mktemp /etc/steward/.steward.json.XXXXXX)
if [[ $local_only == true || $executor_only == true ]]; then
	write_loopback_supervisor_config >"$steward_tmp"
	chown root:steward "$steward_tmp"
	chmod 0640 "$steward_tmp"
else
	awk -v url="$control_plane_url" -v ca="/etc/steward/control-plane-ca.pem" '
	/^[[:space:]]*"uplink_url"[[:space:]]*:/ {
		comma = ($0 ~ /,[[:space:]]*$/) ? "," : ""
		printf "  \"uplink_url\": \"%s\"%s\n", url, comma
		found_url = 1
		next
	}
	/^[[:space:]]*"uplink_tls_ca_file"[[:space:]]*:/ {
		comma = ($0 ~ /,[[:space:]]*$/) ? "," : ""
		printf "  \"uplink_tls_ca_file\": \"%s\"%s\n", ca, comma
		found_ca = 1
		next
	}
	{ print }
	END { if (!found_url || !found_ca) exit 3 }
' /etc/steward/steward.json >"$steward_tmp"
	chown root:steward "$steward_tmp"
	chmod 0640 "$steward_tmp"
fi
mv -f "$steward_tmp" /etc/steward/steward.json
steward_tmp=

executor_tmp=$(mktemp /etc/steward/.executor.env.XXXXXX)
awk -v url="$control_plane_url" -v ca="/etc/steward/control-plane-ca.pem" -v local_only="$local_only" \
	-v evidence_enabled="$([[ $evidence_input_count -eq 3 ]] && printf true || printf false)" \
	-v evidence_controller="$evidence_controller_instance_id" '
	/^EXECUTOR_UPLINK_URL=/ {
		print "EXECUTOR_UPLINK_URL=" (local_only == "true" ? "" : url)
		found_url = 1
		next
	}
	/^EXECUTOR_OPERATOR_TOKEN_FILE=/ {
		if (found_operator_token++) exit 3
		print "EXECUTOR_OPERATOR_TOKEN_FILE=/etc/steward/executor-operator-token"
		next
	}
	/^EXECUTOR_OBSERVER_TOKEN_FILE=/ {
		if (found_observer_token++) exit 3
		print "EXECUTOR_OBSERVER_TOKEN_FILE=/etc/steward/executor-observer-token"
		next
	}
	/^EXECUTOR_UPLINK_CREDENTIAL_FILE=/ {
		print "EXECUTOR_UPLINK_CREDENTIAL_FILE=" (local_only == "true" ? "" : "/etc/steward/executor-uplink.json")
		found_credential = 1
		next
	}
	/^EXECUTOR_UPLINK_STATE_FILE=/ {
		print "EXECUTOR_UPLINK_STATE_FILE=" (local_only == "true" ? "" : "/var/lib/steward-executor/uplink-state.json")
		found_state = 1
		next
	}
	/^EXECUTOR_UPLINK_DELIVERY_STATE_FILE=/ {
		if (found_delivery) exit 3
		print "EXECUTOR_UPLINK_DELIVERY_STATE_FILE="
		found_delivery = 1
		next
	}
	/^EXECUTOR_UPLINK_PROTOCOL_VERSION=/ {
		if (found_protocol) exit 3
		print "EXECUTOR_UPLINK_PROTOCOL_VERSION=0"
		found_protocol = 1
		next
	}
	/^EXECUTOR_UPLINK_TLS_CA_FILE=/ {
		print "EXECUTOR_UPLINK_TLS_CA_FILE=" (local_only == "true" ? "" : ca)
		found_ca = 1
		next
	}
	/^EXECUTOR_EVIDENCE_UPLINK_ENABLED=/ {
		if (found_evidence_enabled++) exit 3
		print "EXECUTOR_EVIDENCE_UPLINK_ENABLED=" evidence_enabled
		next
	}
	/^EXECUTOR_EVIDENCE_UPLINK_CONTROLLER_INSTANCE_ID=/ {
		if (found_evidence_controller++) exit 3
		print "EXECUTOR_EVIDENCE_UPLINK_CONTROLLER_INSTANCE_ID=" evidence_controller
		next
	}
	/^EXECUTOR_EVIDENCE_UPLINK_POLL_INTERVAL=/ {
		if (found_evidence_interval++) exit 3
		print
		next
	}
	{ print }
	END {
		if (!found_operator_token) print "EXECUTOR_OPERATOR_TOKEN_FILE=/etc/steward/executor-operator-token"
		if (!found_observer_token) print "EXECUTOR_OBSERVER_TOKEN_FILE=/etc/steward/executor-observer-token"
		if (!found_delivery) print "EXECUTOR_UPLINK_DELIVERY_STATE_FILE="
		if (!found_protocol) print "EXECUTOR_UPLINK_PROTOCOL_VERSION=0"
		if (!found_evidence_enabled) print "EXECUTOR_EVIDENCE_UPLINK_ENABLED=" evidence_enabled
		if (!found_evidence_controller) print "EXECUTOR_EVIDENCE_UPLINK_CONTROLLER_INSTANCE_ID=" evidence_controller
		if (!found_evidence_interval) print "EXECUTOR_EVIDENCE_UPLINK_POLL_INTERVAL=30s"
		if (!found_url || !found_credential || !found_state || !found_ca) exit 3
	}
' /etc/steward/executor.env >"$executor_tmp"
chown root:root "$executor_tmp"
chmod 0600 "$executor_tmp"
mv -f "$executor_tmp" /etc/steward/executor.env
executor_tmp=

install_atomic() {
	local source=$1 target=$2 owner=$3 group=$4 mode=$5
	atomic_tmp=$(mktemp "/etc/steward/.${target##*/}.XXXXXX")
	install -o "$owner" -g "$group" -m "$mode" "$source" "$atomic_tmp"
	mv -f "$atomic_tmp" "$target"
	atomic_tmp=
}
if [[ $local_only == false ]]; then
	if [[ $executor_only == true ]]; then
		# steward-control speaks the signed Executor protocol, not the generic
		# supervisor protocol. Remove any old generic credential so a later edit
		# cannot accidentally reconnect the supervisor to a stale authority.
		rm -f -- /etc/steward/uplink-credential.json
	else
		install_atomic "$steward_credential" /etc/steward/uplink-credential.json \
			steward steward 0600
	fi
	install_atomic "$executor_credential" /etc/steward/executor-uplink.json \
		steward-executor steward-executor 0600
	install_atomic "$ca_file" /etc/steward/control-plane-ca.pem root root 0644
fi
executor_credential_scope=
executor_credential_node_id=
if [[ $local_only == false ]]; then
	credential_metadata=$(runuser -u steward-executor -- /usr/local/bin/steward-executor \
		-inspect-uplink-credential -uplink-credential-file /etc/steward/executor-uplink.json)
	if [[ $credential_metadata != *$'\n'* ]]; then
		transaction_error "Executor credential inspection returned invalid metadata"
	fi
	executor_credential_scope=${credential_metadata%%$'\n'*}
	executor_credential_node_id=${credential_metadata#*$'\n'}
	if [[ $executor_credential_node_id == *$'\n'* ]] || \
		[[ $executor_credential_scope != tenant && $executor_credential_scope != node ]]; then
		transaction_error "Executor credential inspection returned invalid metadata"
	fi
	if ! selected_uplink_protocol=$(select_configured_uplink_protocol \
		"$executor_credential_scope" "$executor_uplink_protocol"); then
		transaction_error "--executor-uplink-protocol-version requires a node-scoped Executor credential and value 3 or 4"
	fi
	if [[ $executor_only == true && $executor_credential_scope != node ]]; then
		transaction_error "steward-control requires a node-scoped Executor credential"
	fi
	if [[ $executor_credential_scope == node && $evidence_input_count -ne 3 ]]; then
		transaction_error "a node-scoped Executor credential requires the enrollment evidence config and receipt key pair"
	fi
	if (( evidence_input_count == 3 )) &&
		[[ $executor_credential_scope != node || $executor_credential_node_id != "$evidence_node_id" ]]; then
		transaction_error "Executor evidence enrollment identity does not match the node credential"
	fi
fi
if [[ -n $executor_token ]]; then
	install_atomic "$executor_token" /etc/steward/executor-token \
		steward-executor steward-executor 0600
elif [[ ! -e /etc/steward/executor-token ]]; then
	token_tmp=$(mktemp /etc/steward/.executor-token.XXXXXX)
	od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"$token_tmp"
	printf '\n' >>"$token_tmp"
	chown steward-executor:steward-executor "$token_tmp"
	chmod 0600 "$token_tmp"
	mv -f "$token_tmp" /etc/steward/executor-token
	token_tmp=
fi

for scoped_role in operator observer; do
	scoped_path="/etc/steward/executor-${scoped_role}-token"
	if [[ ! -e $scoped_path ]]; then
		scoped_token_tmp=$(mktemp "/etc/steward/.executor-${scoped_role}-token.XXXXXX")
		od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"$scoped_token_tmp"
		printf '\n' >>"$scoped_token_tmp"
		chown steward-executor:steward-executor "$scoped_token_tmp"
		chmod 0600 "$scoped_token_tmp"
		mv -f "$scoped_token_tmp" "$scoped_path"
		scoped_token_tmp=
	fi
done

if [[ $local_only == false && ! -e $uplink_fence && ! -L $uplink_fence ]]; then
	uplink_fence_created=true
	runuser -u steward-executor -- /usr/local/bin/steward-executor \
		-initialize-uplink-state -uplink-state-file "$uplink_fence"
fi

# Install admission trust inside this outer transaction when supplied. The
# helper performs its own semantic verification and local rollback; this script
# additionally owns every file it could create so a later failure restores the
# entire node, not just the nested step.
if (( admission_required == 3 )); then
	[[ -e $admission_fence || -L $admission_fence ]] || admission_fence_created=true
	[[ -e $operation_journal || -L $operation_journal ]] || operation_journal_created=true
	[[ -e $evidence_log || -L $evidence_log ]] || evidence_log_created=true
	admission_args=(
		--policy "$admission_policy"
		--site-root-public-key "$site_root"
		--site-root-key-id "$site_root_key_id"
		--node-lock-fd 9
		--no-restart
	)
	[[ -z $node_id ]] || admission_args+=(--node-id "$node_id")
	if (( evidence_input_count == 3 )); then
		admission_args+=(
			--receipt-private-key "$receipt_private"
			--receipt-public-key "$receipt_public"
		)
	fi
	[[ $allow_host_admin == false ]] || admission_args+=(--allow-host-admin-intent)
	[[ $allow_unquotaed_state == false ]] ||
		admission_args+=(--allow-unquotaed-state-on-dedicated-host)
	/usr/local/libexec/steward/configure-admission "${admission_args[@]}"
fi

admission_env_complete() {
	awk -F= '
		BEGIN {
			required["EXECUTOR_ADMISSION_POLICY_FILE"] = 1
			required["EXECUTOR_ADMISSION_SITE_ROOT_PUBLIC_KEY_FILE"] = 1
			required["EXECUTOR_ADMISSION_SITE_ROOT_KEY_ID"] = 1
			required["EXECUTOR_ADMISSION_NODE_ID"] = 1
			required["EXECUTOR_ADMISSION_EVIDENCE_KEY_FILE"] = 1
		}
		$1 in required {
			if (seen[$1]++) bad = 1
			if (length(substr($0, index($0, "=") + 1)) > 0) set++
		}
		END {
			if (bad) exit 2
			exit set == 5 ? 0 : 1
		}
	' /etc/steward/executor.env
}

# Node-scoped credentials select protocol 4 by default. Protocol 3 remains an
# explicit controller-compatibility option. Both require the delivery ledger,
# while tenant-scoped credentials retain protocol 1 with an empty delivery-state
# setting. Initialization is create-only: an existing ledger is never reset, and
# final preflight verifies its
# owner, format, and node binding.
if [[ $executor_credential_scope == node ]]; then
	if ! admission_env_complete; then
		transaction_error "a node-scoped Executor credential requires complete signed admission"
	fi
	configured_node_id=$(awk -F= '
		$1 == "EXECUTOR_ADMISSION_NODE_ID" {
			if (seen++) exit 2
			print substr($0, index($0, "=") + 1)
		}
	' /etc/steward/executor.env)
	if [[ -z $configured_node_id || $configured_node_id != "$executor_credential_node_id" ]]; then
		transaction_error "node-scoped Executor credential node ID does not match signed admission"
	fi
	if (( evidence_input_count == 3 )) && [[ $configured_node_id != "$evidence_node_id" ]]; then
		transaction_error "Executor evidence enrollment identity does not match signed admission"
	fi
	if [[ ! -e $uplink_delivery_state && ! -L $uplink_delivery_state ]]; then
		uplink_delivery_state_created=true
		runuser -u steward-executor -- /usr/local/bin/steward-executor \
			-initialize-uplink-delivery-state \
			-uplink-delivery-state-file "$uplink_delivery_state" \
			-admission-node-id "$configured_node_id"
	fi
	executor_tmp=$(mktemp /etc/steward/.executor.env.XXXXXX)
	awk -v path="$uplink_delivery_state" -v protocol="$selected_uplink_protocol" '
		/^EXECUTOR_UPLINK_DELIVERY_STATE_FILE=/ {
			if (found++) exit 3
			print "EXECUTOR_UPLINK_DELIVERY_STATE_FILE=" path
			next
		}
		/^EXECUTOR_UPLINK_PROTOCOL_VERSION=/ {
			if (found_protocol++) exit 3
			print "EXECUTOR_UPLINK_PROTOCOL_VERSION=" protocol
			next
		}
		{ print }
		END {
			if (!found) print "EXECUTOR_UPLINK_DELIVERY_STATE_FILE=" path
			if (!found_protocol) print "EXECUTOR_UPLINK_PROTOCOL_VERSION=" protocol
		}
	' /etc/steward/executor.env >"$executor_tmp"
	chown root:root "$executor_tmp"
	chmod 0600 "$executor_tmp"
	mv -f "$executor_tmp" /etc/steward/executor.env
	executor_tmp=
fi

# A fresh package ships an empty positive-capability topology. Derive it only
# after all signed-admission inputs exist. Gateway arguments themselves request
# secure admission, so installing them on a legacy or half-enrolled node makes
# the Executor correctly fail closed.
derived_relay=false
if admission_env_complete; then
	[[ -e $operation_journal || -L $operation_journal ]] || operation_journal_created=true
	[[ -e $evidence_log || -L $evidence_log ]] || evidence_log_created=true
	gateway_line=$(grep -v '^[[:space:]]*#' /etc/steward/executor-gateway.env 2>/dev/null | grep -v '^[[:space:]]*$' || true)
	if [[ -z $gateway_line || $gateway_line == EXECUTOR_GATEWAY_ARGS= ]]; then
		/usr/local/libexec/steward/node-preflight
		/usr/local/libexec/steward/build-relay-image --configure
		derived_relay=true
	fi
fi
/usr/local/libexec/steward/node-preflight

committed=true
trap - ERR INT TERM
rm -rf -- "$backup_dir"
if [[ $start_services == true ]]; then
	systemctl enable steward-gateway.service steward.service steward-executor.service
	# enable --now does not reload an already-active service. A configurator run
	# must make the validated files effective, including on a re-enrolled node.
	systemctl restart steward-gateway.service steward.service steward-executor.service
	echo "configure-node: Steward is configured, validated, enabled, and running"
else
	echo "configure-node: Steward is configured and validated; service state was not changed"
fi
if [[ $executor_only == true ]]; then
	echo "configure-node: Executor uses steward-control; the supervisor remains loopback-only with process execution disabled"
fi
if [[ $derived_relay == true ]]; then
	echo "configure-node: trusted relay topology was built offline and pinned automatically"
fi
