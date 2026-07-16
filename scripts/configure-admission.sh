#!/bin/bash -p
# Transactionally install signed-admission trust and establish node-local evidence identity.
set -Eeuo pipefail
set +x
if ! shopt -qo privileged; then
	echo "configure-admission: execute this root helper directly or invoke it with /bin/bash -p" >&2
	exit 2
fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C LANG=C
unset BASH_ENV CDPATH ENV GLOBIGNORE POSIXLY_CORRECT
IFS=$' \t\n'
umask 077

usage() {
	cat <<'EOF'
Usage: configure-admission.sh --policy FILE --site-root-public-key FILE --site-root-key-id ID [OPTIONS]

Required:
  --policy FILE                  Site-root-signed site policy DSSE envelope
  --site-root-public-key FILE    Base64 Ed25519 site-root public key
  --site-root-key-id ID          Signature key ID used by the policy

Optional:
  --node-id ID                   Stable node identity (derived from /etc/machine-id by default)
  --receipt-private-key FILE     Owner-only enrollment receipt private key
  --receipt-public-key FILE      Matching base64 Ed25519 receipt public key
  --allow-host-admin-intent      Allow the host-local token to select signed tenant intent
  --no-restart                   Validate and commit without restarting an active Executor
  -h, --help                     Show this help

Pass both receipt-key files to reuse the exact key that proved possession during
control-plane enrollment. If omitted, a new receipt key is generated on the node.
An imported key must match any evidence identity already installed on the node.
The public key is written to /etc/steward/node-receipts.public for enrollment/audit.
Copy all input files to a protected, root-owned directory first. Inputs in
/tmp, home directories, or writable parent directories are rejected.
EOF
}

policy=
site_root=
site_root_key_id=
node_id=
receipt_private=
receipt_public=
allow_host_admin=false
restart=true
node_lock_fd=
while [[ $# -gt 0 ]]; do
	case "$1" in
		--policy) policy=${2:-}; shift 2 ;;
		--site-root-public-key) site_root=${2:-}; shift 2 ;;
		--site-root-key-id) site_root_key_id=${2:-}; shift 2 ;;
		--node-id) node_id=${2:-}; shift 2 ;;
		--receipt-private-key) receipt_private=${2:-}; shift 2 ;;
		--receipt-public-key) receipt_public=${2:-}; shift 2 ;;
		--allow-host-admin-intent) allow_host_admin=true; shift ;;
		--no-restart) restart=false; shift ;;
		--node-lock-fd) node_lock_fd=${2:-}; shift 2 ;;
		-h | --help) usage; exit 0 ;;
		*) echo "configure-admission: unknown option $1" >&2; usage >&2; exit 2 ;;
	esac
done

[[ ${EUID} -eq 0 ]] || { echo "configure-admission: run as root" >&2; exit 2; }
[[ $(uname -s) == Linux ]] || { echo "configure-admission: Linux is required" >&2; exit 2; }
for input in "$policy" "$site_root"; do
	[[ -n $input ]] || {
		echo "configure-admission: required trust input is missing" >&2
		exit 2
	}
done
[[ $site_root_key_id =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$ ]] || {
	echo "configure-admission: invalid --site-root-key-id" >&2; exit 2;
}
if { [[ -z $receipt_private ]] && [[ -n $receipt_public ]]; } ||
	{ [[ -n $receipt_private ]] && [[ -z $receipt_public ]]; }; then
	echo "configure-admission: --receipt-private-key and --receipt-public-key are required together" >&2
	exit 2
fi

# BEGIN NODE_LOCK_BOUNDARY
readonly node_lock_directory=/run/steward-node
readonly node_lock_file=$node_lock_directory/activation.lock
readonly node_lock_error_prefix=configure-admission

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
		echo "$node_lock_error_prefix: flock is required to serialize signed-admission configuration" >&2
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

if [[ -n $node_lock_fd ]]; then
	use_inherited_node_lock "$node_lock_fd"
else
	acquire_node_lock 60
fi

# BEGIN TRUSTED_INPUT_BOUNDARY
# This entrypoint can be invoked directly, so it independently snapshots its
# authority files even when configure-node has already supplied protected
# snapshots. The protected parent chain excludes non-root pathname replacement.
trusted_input_error() {
	echo "configure-admission: $1; copy the input to a protected root-owned directory and retry" >&2
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

stage_admission_input_sources() {
	trusted_input_snapshot "$policy" "$input_stage/site-policy.dsse.json" \
		"admission policy" 1048576 false || return
	policy=$input_stage/site-policy.dsse.json
	trusted_input_snapshot "$site_root" "$input_stage/site-root.public" \
		"site-root public key" 4096 false || return
	site_root=$input_stage/site-root.public
	if [[ -n ${receipt_private:-} ]]; then
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

input_stage_prefix=/run/steward-admission-inputs.
input_stage=
trap cleanup_trusted_input_stage EXIT
create_trusted_input_stage
stage_admission_input_sources

if [[ -z $node_id ]]; then
	[[ -r /etc/machine-id ]] || { echo "configure-admission: --node-id is required without /etc/machine-id" >&2; exit 2; }
	machine_id=$(tr -d '\n' </etc/machine-id)
	[[ $machine_id =~ ^[a-f0-9]{32}$ ]] || { echo "configure-admission: /etc/machine-id is invalid" >&2; exit 2; }
	node_id="steward-$machine_id"
fi
[[ $node_id =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] || { echo "configure-admission: invalid node ID" >&2; exit 2; }
for path in /usr/local/bin/stewardctl /usr/local/bin/steward-executor \
	/usr/local/libexec/steward/node-preflight /usr/local/libexec/steward/build-relay-image \
	/etc/steward/executor.env; do
	[[ -e $path ]] || { echo "configure-admission: Steward node is missing $path" >&2; exit 2; }
done
receipt_key_pair_state() {
	local private_path=$1 public_path=$2 private_present=false public_present=false
	[[ ! -e $private_path && ! -L $private_path ]] || private_present=true
	[[ ! -e $public_path && ! -L $public_path ]] || public_present=true
	[[ $private_present == "$public_present" ]] || return 1
	[[ $private_present == true ]] && printf 'present\n' || printf 'absent\n'
}
if ! receipt_identity_state=$(receipt_key_pair_state \
	/etc/steward/node-receipts.private.pem /etc/steward/node-receipts.public); then
	echo "configure-admission: receipt private/public key files must both exist or both be absent" >&2
	exit 2
fi

# Authenticate and semantically validate the policy before changing host state.
/usr/local/bin/stewardctl policy verify -in "$policy" -public-key "$site_root" \
	-key-id "$site_root_key_id" >/dev/null
if [[ -n $receipt_private ]]; then
	/usr/local/bin/stewardctl key match -private-key "$receipt_private" \
		-public-key "$receipt_public" >/dev/null
fi
if [[ $receipt_identity_state == present ]]; then
	/usr/local/bin/stewardctl key match \
		-private-key /etc/steward/node-receipts.private.pem \
		-public-key /etc/steward/node-receipts.public >/dev/null
	if [[ -n $receipt_private ]]; then
		/usr/local/bin/stewardctl key match \
			-private-key /etc/steward/node-receipts.private.pem \
			-public-key "$receipt_public" >/dev/null || {
			echo "configure-admission: imported receipt key does not match the installed evidence identity" >&2
			exit 2
		}
	fi
fi

targets=(
	/etc/steward/executor.env
	/etc/steward/site-policy.dsse.json
	/etc/steward/site-root.public
	/etc/steward/node-receipts.private.pem
	/etc/steward/node-receipts.public
	/etc/steward/executor-gateway.env
)
backup=$(mktemp -d /etc/steward/.admission-backup.XXXXXX)
for target in "${targets[@]}"; do
	name=${target##*/}
	if [[ -e $target || -L $target ]]; then cp -a -- "$target" "$backup/$name"; else : >"$backup/$name.absent"; fi
done
fence=/var/lib/steward-executor/admission-fences.bin
fence_created=false
journal=/var/lib/steward-executor/operation-journal.bin
journal_created=false
evidence=/var/lib/steward-executor/evidence.bin
evidence_created=false
was_active=false
systemctl is-active --quiet steward-executor.service && was_active=true
committed=false
tmp_private=
tmp_public=
tmp_env=
rollback() {
	status=$?
	trap - ERR INT TERM
	if [[ $committed != true ]]; then
		for target in "${targets[@]}"; do
			name=${target##*/}
			rm -f -- "$target"
			[[ -e $backup/$name || -L $backup/$name ]] && cp -a -- "$backup/$name" "$target"
		done
		[[ $fence_created == false ]] || rm -f -- "$fence"
		[[ $journal_created == false ]] || rm -f -- "$journal"
		[[ $evidence_created == false ]] || rm -f -- "$evidence"
		if [[ $was_active == true ]]; then systemctl restart steward-executor.service >/dev/null 2>&1 || true; fi
		echo "configure-admission: failed; restored previous trust configuration" >&2
	fi
	rm -f -- "${tmp_private:-}" "${tmp_public:-}" "${tmp_env:-}"
	rm -rf -- "$backup"
	exit "$status"
}
trap rollback ERR INT TERM

install -o root -g steward-executor -m 0640 "$policy" /etc/steward/site-policy.dsse.json
install -o root -g root -m 0644 "$site_root" /etc/steward/site-root.public
if [[ $receipt_identity_state == absent && -n $receipt_private ]]; then
	install -o steward-executor -g steward-executor -m 0600 \
		"$receipt_private" /etc/steward/node-receipts.private.pem
	install -o root -g root -m 0644 \
		"$receipt_public" /etc/steward/node-receipts.public
elif [[ $receipt_identity_state == absent ]]; then
	tmp_private=$(mktemp /etc/steward/.node-receipts.private.XXXXXX)
	tmp_public=$(mktemp /etc/steward/.node-receipts.public.XXXXXX)
	rm -f "$tmp_private" "$tmp_public"
	/usr/local/bin/stewardctl keygen -private-out "$tmp_private" -public-out "$tmp_public" >/dev/null
	chown steward-executor:steward-executor "$tmp_private"
	chmod 0600 "$tmp_private"
	chown root:root "$tmp_public"
	chmod 0644 "$tmp_public"
	mv -f "$tmp_private" /etc/steward/node-receipts.private.pem
	tmp_private=
	mv -f "$tmp_public" /etc/steward/node-receipts.public
	tmp_public=
fi

tmp_env=$(mktemp /etc/steward/.executor.env.XXXXXX)
awk '!/^EXECUTOR_ADMISSION_(POLICY_FILE|SITE_ROOT_PUBLIC_KEY_FILE|SITE_ROOT_KEY_ID|NODE_ID|EVIDENCE_KEY_FILE|HOST_ADMIN_ARG)=/' \
	/etc/steward/executor.env >"$tmp_env"
{
	printf 'EXECUTOR_ADMISSION_POLICY_FILE=/etc/steward/site-policy.dsse.json\n'
	printf 'EXECUTOR_ADMISSION_SITE_ROOT_PUBLIC_KEY_FILE=/etc/steward/site-root.public\n'
	printf 'EXECUTOR_ADMISSION_SITE_ROOT_KEY_ID=%s\n' "$site_root_key_id"
	printf 'EXECUTOR_ADMISSION_NODE_ID=%s\n' "$node_id"
	printf 'EXECUTOR_ADMISSION_EVIDENCE_KEY_FILE=/etc/steward/node-receipts.private.pem\n'
	if [[ $allow_host_admin == true ]]; then
		printf 'EXECUTOR_ADMISSION_HOST_ADMIN_ARG=-admission-allow-host-admin-intent\n'
	else
		printf 'EXECUTOR_ADMISSION_HOST_ADMIN_ARG=\n'
	fi
} >>"$tmp_env"
chown root:root "$tmp_env"
chmod 0600 "$tmp_env"
mv -f "$tmp_env" /etc/steward/executor.env
tmp_env=

gateway_line=$(grep -v '^[[:space:]]*#' /etc/steward/executor-gateway.env 2>/dev/null | grep -v '^[[:space:]]*$' || true)
if [[ ! -e $fence && ! -L $fence ]]; then
	fence_created=true
	runuser -u steward-executor -- /usr/local/bin/steward-executor -initialize-admission-fence -admission-fence-file "$fence"
fi
# Configuration validation is strictly read-only. Initialize the two empty
# append-only stores explicitly, with the service identity that will own later
# writes. The transaction removes them again if a later validation step fails.
if [[ ! -e $journal && ! -L $journal ]]; then
	journal_created=true
	install -o steward-executor -g steward-executor -m 0600 /dev/null "$journal"
fi
if [[ ! -e $evidence && ! -L $evidence ]]; then
	evidence_created=true
	install -o steward-executor -g steward-executor -m 0600 /dev/null "$evidence"
fi
# Validate trust, node identity, the uplink credential, and every non-topology
# prerequisite before doing an image build. This catches a mismatched v2 node
# credential without leaving even an unreferenced relay image behind.
if [[ -z $gateway_line || $gateway_line == EXECUTOR_GATEWAY_ARGS= ]]; then
	/usr/local/libexec/steward/node-preflight
	/usr/local/libexec/steward/build-relay-image --configure
fi
/usr/local/libexec/steward/node-preflight
if [[ $restart == true && $was_active == true ]]; then systemctl restart steward-executor.service; fi

committed=true
trap - ERR INT TERM
rm -rf -- "$backup"
echo "configure-admission: signed admission ready for node $node_id"
echo "configure-admission: retain /etc/steward/node-receipts.public outside the node for receipt verification"
