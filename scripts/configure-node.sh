#!/usr/bin/env bash
# Provision node trust material, validate it, and optionally start Steward.
set -Eeuo pipefail

usage() {
	cat <<'EOF'
Usage: configure-node.sh OPTIONS

Remote enrollment (omit with --local-only):
  --control-plane-url URL       HTTPS control-plane base URL
  --steward-credential FILE     Steward uplink credential JSON
  --executor-credential FILE    Executor uplink credential JSON
  --ca-file FILE                PEM CA bundle for the control plane

Signed admission (all trust inputs are optional as one group):
  --admission-policy FILE       Site-root-signed site policy DSSE envelope
  --site-root-public-key FILE   Base64 Ed25519 site-root public key
  --site-root-key-id ID         Signature key ID used by the policy
  --node-id ID                  Stable node ID (machine-derived if omitted)
  --allow-host-admin-intent     Let the host token select signed tenant intent

Optional:
  --local-only                 Configure loopback HTTP, CLI, and MCP without an uplink
  --executor-token FILE         Existing host-local bearer token; generated if omitted
  --no-start                    Validate and configure, but leave services stopped
  -h, --help                    Show this help

The operation is transactional through preflight: invalid input restores the
previous files under /etc/steward and removes state files created by this run.
Existing Executor fence, delivery, journal, and evidence state is never reset.
EOF
}

control_plane_url=
steward_credential=
executor_credential=
ca_file=
executor_token=
admission_policy=
site_root=
site_root_key_id=
node_id=
allow_host_admin=false
start_services=true
local_only=false
while [[ $# -gt 0 ]]; do
	case "$1" in
		--control-plane-url) control_plane_url=${2:-}; shift 2 ;;
		--steward-credential) steward_credential=${2:-}; shift 2 ;;
		--executor-credential) executor_credential=${2:-}; shift 2 ;;
		--ca-file) ca_file=${2:-}; shift 2 ;;
		--executor-token) executor_token=${2:-}; shift 2 ;;
		--admission-policy) admission_policy=${2:-}; shift 2 ;;
		--site-root-public-key) site_root=${2:-}; shift 2 ;;
		--site-root-key-id) site_root_key_id=${2:-}; shift 2 ;;
		--node-id) node_id=${2:-}; shift 2 ;;
		--allow-host-admin-intent) allow_host_admin=true; shift ;;
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
else
	for input in "$steward_credential" "$executor_credential" "$ca_file"; do
		if [[ -z $input || ! -f $input || ! -r $input ]]; then
			echo "configure-node: required input is not a readable regular file: ${input:-<unset>}" >&2
			exit 2
		fi
	done
fi
if [[ -n $executor_token && ( ! -f $executor_token || ! -r $executor_token ) ]]; then
	echo "configure-node: Executor token is not a readable regular file: $executor_token" >&2
	exit 2
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
if (( admission_required == 3 )); then
	for input in "$admission_policy" "$site_root"; do
		if [[ ! -f $input || ! -r $input || -L $input ]]; then
			echo "configure-node: admission trust input must be a readable regular file, not a symlink: $input" >&2
			exit 2
		fi
	done
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
	/usr/local/bin/steward-executor /usr/local/libexec/steward/node-preflight; do
	if [[ ! -e $path ]]; then
		echo "configure-node: missing installed path $path; install Steward first" >&2
		exit 2
	fi
done
if (( admission_required == 3 )) && [[ ! -x /usr/local/libexec/steward/configure-admission ]]; then
	echo "configure-node: missing signed-admission configurator; install Steward first" >&2
	exit 2
fi

acquire_node_lock() {
	local lock_file=${1:-/run/lock/steward-node-activation.lock}
	local wait_seconds=${2:-60}
	if ! command -v flock >/dev/null 2>&1; then
		echo "configure-node: flock is required to serialize node configuration" >&2
		return 2
	fi
	exec 9>"$lock_file"
	if ! flock -w "$wait_seconds" 9; then
		echo "configure-node: another node configuration or activation did not finish within $wait_seconds seconds" >&2
		return 1
	fi
}

install -d -o root -g root -m 0755 /run/lock
acquire_node_lock

install -d -o root -g root -m 0755 /etc/steward
backup_dir=$(mktemp -d /etc/steward/.configure-backup.XXXXXX)
targets=(
	/etc/steward/steward.json
	/etc/steward/executor.env
	/etc/steward/executor-gateway.env
	/etc/steward/uplink-credential.json
	/etc/steward/executor-uplink.json
	/etc/steward/executor-token
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
	rm -f -- "${steward_tmp:-}" "${executor_tmp:-}" "${token_tmp:-}" "${atomic_tmp:-}"
	rm -rf -- "$backup_dir"
	exit "$status"
}
trap rollback ERR INT TERM

transaction_error() {
	echo "configure-node: $1" >&2
	return 2
}

steward_tmp=$(mktemp /etc/steward/.steward.json.XXXXXX)
if [[ $local_only == true ]]; then
	printf '%s\n' '{' \
		'  "addr": "127.0.0.1:8080",' \
		'  "disable_inbound_listener": false,' \
		'  "enable_process_exec": false,' \
		'  "log_level": "info",' \
		'  "max_instances": 1024,' \
		'  "state_file": "/var/lib/steward/state.json"' \
		'}' >"$steward_tmp"
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
awk -v url="$control_plane_url" -v ca="/etc/steward/control-plane-ca.pem" -v local_only="$local_only" '
	/^EXECUTOR_UPLINK_URL=/ {
		print "EXECUTOR_UPLINK_URL=" (local_only == "true" ? "" : url)
		found_url = 1
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
	/^EXECUTOR_UPLINK_TLS_CA_FILE=/ {
		print "EXECUTOR_UPLINK_TLS_CA_FILE=" (local_only == "true" ? "" : ca)
		found_ca = 1
		next
	}
	{ print }
	END {
		if (!found_delivery) print "EXECUTOR_UPLINK_DELIVERY_STATE_FILE="
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
	install_atomic "$steward_credential" /etc/steward/uplink-credential.json \
		steward steward 0600
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
		--no-restart
	)
	[[ -z $node_id ]] || admission_args+=(--node-id "$node_id")
	[[ $allow_host_admin == false ]] || admission_args+=(--allow-host-admin-intent)
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

# Node-scoped credentials select protocol 3 and therefore require the durable
# delivery ledger. Tenant-scoped credentials retain protocol 1 with an empty
# delivery-state setting. Initialization is create-only: an existing ledger is
# never reset, and final preflight verifies its owner, format, and node binding.
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
	if [[ ! -e $uplink_delivery_state && ! -L $uplink_delivery_state ]]; then
		runuser -u steward-executor -- /usr/local/bin/steward-executor \
			-initialize-uplink-delivery-state \
			-uplink-delivery-state-file "$uplink_delivery_state" \
			-admission-node-id "$configured_node_id"
		uplink_delivery_state_created=true
	fi
	executor_tmp=$(mktemp /etc/steward/.executor.env.XXXXXX)
	awk -v path="$uplink_delivery_state" '
		/^EXECUTOR_UPLINK_DELIVERY_STATE_FILE=/ {
			if (found++) exit 3
			print "EXECUTOR_UPLINK_DELIVERY_STATE_FILE=" path
			next
		}
		{ print }
		END { if (!found) print "EXECUTOR_UPLINK_DELIVERY_STATE_FILE=" path }
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
if [[ $derived_relay == true ]]; then
	echo "configure-node: trusted relay topology was built offline and pinned automatically"
fi
