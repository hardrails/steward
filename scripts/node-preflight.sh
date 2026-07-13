#!/usr/bin/env bash
# Validate the installed node, trust material, six binaries, and three services.
set -euo pipefail

steward_config=${STEWARD_CONFIG_FILE:-/etc/steward/steward.json}
executor_env=${STEWARD_EXECUTOR_ENV_FILE:-/etc/steward/executor.env}
executor_gateway_env=${STEWARD_EXECUTOR_GATEWAY_ENV_FILE:-/etc/steward/executor-gateway.env}
steward_bin=${STEWARD_BIN:-/usr/local/bin/steward}
ctl_bin=${STEWARD_CTL_BIN:-/usr/local/bin/stewardctl}
mcp_bin=${STEWARD_MCP_BIN:-/usr/local/bin/steward-mcp}
executor_bin=${STEWARD_EXECUTOR_BIN:-/usr/local/bin/steward-executor}
gateway_bin=${STEWARD_GATEWAY_BIN:-/usr/local/bin/steward-gateway}
relay_bin=${STEWARD_RELAY_BIN:-/usr/local/bin/steward-relay}
gateway_config=${STEWARD_GATEWAY_CONFIG_FILE:-/etc/steward/gateway.json}
connector_receipt_private=${STEWARD_CONNECTOR_RECEIPT_PRIVATE_KEY_FILE:-/etc/steward/connector-receipts.private.pem}
connector_receipt_public=${STEWARD_CONNECTOR_RECEIPT_PUBLIC_KEY_FILE:-/etc/steward/connector-receipts.public}
unit_dir=${STEWARD_UNIT_DIR:-}

hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		echo "node-preflight: sha256sum or shasum is required" >&2
		exit 2
	fi
}

if [[ ${EUID} -ne 0 ]]; then
	echo "node-preflight: run as root so checks use the service identities" >&2
	exit 2
fi
if [[ $(uname -s) != Linux ]]; then
	echo "node-preflight: Linux is required" >&2
	exit 2
fi
for command in docker runuser systemctl systemd-analyze; do
	command -v "$command" >/dev/null || {
		echo "node-preflight: missing required command $command" >&2
		exit 2
	}
done
if ! docker info --format '{{json .Runtimes}}' | grep -q '"runsc"'; then
	echo "node-preflight: Docker runtime runsc is required" >&2
	exit 2
fi
binary_names=(steward stewardctl steward-mcp steward-executor steward-gateway steward-relay)
binary_paths=("$steward_bin" "$ctl_bin" "$mcp_bin" "$executor_bin" "$gateway_bin" "$relay_bin")
for binary in "${binary_paths[@]}"; do
	if [[ ! -x $binary ]]; then
		echo "node-preflight: missing executable $binary" >&2
		exit 2
	fi
done

declare -A seen_uid=()
for identity in steward steward-executor steward-gateway; do
	if ! id "$identity" >/dev/null 2>&1; then
		echo "node-preflight: missing service identity $identity" >&2
		exit 2
	fi
	uid=$(id -u "$identity")
	if (( uid == 0 )) || [[ ${seen_uid[$uid]+present} == present ]]; then
		echo "node-preflight: Steward service identities must be distinct non-root users" >&2
		exit 2
	fi
	seen_uid[$uid]=$identity
done
has_group() { id -nG "$1" | tr ' ' '\n' | grep -qx -- "$2"; }
if has_group steward docker || has_group steward-gateway docker || ! has_group steward-executor docker; then
	echo "node-preflight: only steward-executor may hold the required Docker group membership" >&2
	exit 2
fi
for group in steward-executor steward-relay; do
	if ! has_group steward-gateway "$group"; then
		echo "node-preflight: steward-gateway is missing required group $group" >&2
		exit 2
	fi
done
gateway_uid=$(id -u steward-gateway)
gateway_gid=$(id -g steward-gateway)
if [[ ! -f $connector_receipt_private || -L $connector_receipt_private ||
	$(stat -c '%u:%g:%a' "$connector_receipt_private" 2>/dev/null || true) != "$gateway_uid:$gateway_gid:600" ]]; then
	echo "node-preflight: connector receipt private key must be a steward-gateway-owned regular file with mode 0600" >&2
	exit 2
fi
if [[ ! -f $connector_receipt_public || -L $connector_receipt_public ||
	$(stat -c '%u:%g:%a' "$connector_receipt_public" 2>/dev/null || true) != "0:0:644" ]]; then
	echo "node-preflight: connector receipt public key must be a root-owned regular file with mode 0644" >&2
	exit 2
fi

expected_version=
for index in "${!binary_paths[@]}"; do
	name=${binary_names[$index]}
	output=$(runuser -u steward -- "${binary_paths[$index]}" -version)
	if [[ ! $output =~ ^${name}[[:space:]]+([A-Za-z0-9._+-]+)$ ]]; then
		echo "node-preflight: $name returned an invalid binary identity/version" >&2
		exit 2
	fi
	reported_version=${BASH_REMATCH[1]}
	if [[ -z $expected_version ]]; then
		expected_version=$reported_version
	elif [[ $reported_version != "$expected_version" ]]; then
		echo "node-preflight: Steward binary versions do not match ($name reports $reported_version, expected $expected_version)" >&2
		exit 2
	fi
done

for mapping in \
	steward.service:steward:steward \
	steward-executor.service:steward-executor:steward-executor \
	steward-gateway.service:steward-gateway:steward-gateway; do
	IFS=: read -r unit expected_user expected_group <<<"$mapping"
	actual_user=$(systemctl show "$unit" --property=User --value)
	actual_group=$(systemctl show "$unit" --property=Group --value)
	if [[ $actual_user != "$expected_user" || $actual_group != "$expected_group" ]]; then
		echo "node-preflight: $unit must run as $expected_user:$expected_group (effective identity is ${actual_user:-<unset>}:${actual_group:-<unset>})" >&2
		exit 2
	fi
done
if [[ ! -r $steward_config || ! -r $executor_env || ! -r $executor_gateway_env || ! -r $gateway_config ]]; then
	echo "node-preflight: missing readable Steward configuration" >&2
	exit 2
fi

declare -A executor=()
required=' EXECUTOR_TOKEN_FILE EXECUTOR_DOCKER_SOCKET EXECUTOR_MAX_MEMORY_BYTES EXECUTOR_MAX_CPU_MILLIS EXECUTOR_MAX_PIDS EXECUTOR_MAX_WORKLOADS EXECUTOR_MAX_WORKLOADS_PER_TENANT '
uplink=' EXECUTOR_UPLINK_URL EXECUTOR_UPLINK_CREDENTIAL_FILE EXECUTOR_UPLINK_STATE_FILE EXECUTOR_UPLINK_TLS_CA_FILE '
optional=' EXECUTOR_ADMISSION_POLICY_FILE EXECUTOR_ADMISSION_SITE_ROOT_PUBLIC_KEY_FILE EXECUTOR_ADMISSION_SITE_ROOT_KEY_ID EXECUTOR_ADMISSION_NODE_ID EXECUTOR_ADMISSION_EVIDENCE_KEY_FILE EXECUTOR_ADMISSION_HOST_ADMIN_ARG EXECUTOR_STATE_ARG EXECUTOR_MAX_TOTAL_MEMORY_BYTES EXECUTOR_MAX_TOTAL_CPU_MILLIS EXECUTOR_MAX_TOTAL_PIDS EXECUTOR_MAX_TENANT_MEMORY_BYTES EXECUTOR_MAX_TENANT_CPU_MILLIS EXECUTOR_MAX_TENANT_PIDS '
allowed="$required$uplink$optional"
while IFS= read -r line || [[ -n $line ]]; do
	[[ -z $line || $line == \#* ]] && continue
	if [[ ! $line =~ ^([A-Z_]+)=(.*)$ ]]; then
		echo "node-preflight: invalid executor.env line" >&2
		exit 2
	fi
	key=${BASH_REMATCH[1]}
	value=${BASH_REMATCH[2]}
	if [[ $value == *[[:space:]]* ]]; then
		echo "node-preflight: executor setting $key contains whitespace" >&2
		exit 2
	fi
	if [[ $allowed != *" $key "* || ${executor[$key]+present} == present ]]; then
		echo "node-preflight: unknown or duplicate executor setting $key" >&2
		exit 2
	fi
	executor[$key]=$value
done <"$executor_env"
for key in $required; do
	if [[ -z ${executor[$key]:-} ]]; then
		echo "node-preflight: missing executor setting $key" >&2
		exit 2
	fi
done
uplink_set=0
for key in $uplink; do
	if [[ -n ${executor[$key]:-} ]]; then ((uplink_set += 1)); fi
done
if (( uplink_set != 0 && uplink_set != 4 )); then
	echo "node-preflight: Executor uplink settings must be all set or all empty" >&2
	exit 2
fi

admission_args=()
gateway_args=()
admission_keys=(EXECUTOR_ADMISSION_POLICY_FILE EXECUTOR_ADMISSION_SITE_ROOT_PUBLIC_KEY_FILE \
	EXECUTOR_ADMISSION_SITE_ROOT_KEY_ID EXECUTOR_ADMISSION_NODE_ID EXECUTOR_ADMISSION_EVIDENCE_KEY_FILE)
admission_set=0
for key in "${admission_keys[@]}"; do
	if [[ -n ${executor[$key]:-} ]]; then ((admission_set += 1)); fi
done
if (( admission_set != 0 && admission_set != ${#admission_keys[@]} )); then
	echo "node-preflight: signed admission settings must be all set or all absent" >&2
	exit 2
fi
if (( admission_set == ${#admission_keys[@]} )); then
	admission_args=(
		-admission-policy-file "${executor[EXECUTOR_ADMISSION_POLICY_FILE]}"
		-admission-site-root-public-key-file "${executor[EXECUTOR_ADMISSION_SITE_ROOT_PUBLIC_KEY_FILE]}"
		-admission-site-root-key-id "${executor[EXECUTOR_ADMISSION_SITE_ROOT_KEY_ID]}"
		-admission-node-id "${executor[EXECUTOR_ADMISSION_NODE_ID]}"
		-admission-evidence-key-file "${executor[EXECUTOR_ADMISSION_EVIDENCE_KEY_FILE]}"
	)
	admin_arg=${executor[EXECUTOR_ADMISSION_HOST_ADMIN_ARG]:-}
	if [[ -n $admin_arg && $admin_arg != -admission-allow-host-admin-intent ]]; then
		echo "node-preflight: invalid host-admin admission argument" >&2
		exit 2
	fi
	[[ -z $admin_arg ]] || admission_args+=("$admin_arg")
	state_arg=${executor[EXECUTOR_STATE_ARG]:-}
	if [[ -n $state_arg && $state_arg != -allow-unquotaed-state-on-dedicated-host ]]; then
		echo "node-preflight: invalid persistent-state compatibility argument" >&2
		exit 2
	fi
	[[ -z $state_arg ]] || admission_args+=("$state_arg")
elif [[ -n ${executor[EXECUTOR_ADMISSION_HOST_ADMIN_ARG]:-} ]]; then
	echo "node-preflight: host-admin intent requires complete signed admission" >&2
	exit 2
elif [[ -n ${executor[EXECUTOR_STATE_ARG]:-} ]]; then
	echo "node-preflight: persistent-state compatibility requires complete signed admission" >&2
	exit 2
fi

if [[ ( -e $executor_gateway_env || -L $executor_gateway_env ) && ! -r $executor_gateway_env ]]; then
	echo "node-preflight: Executor gateway environment is missing or unreadable" >&2
	exit 2
fi
if [[ -r $executor_gateway_env ]]; then
	line=$(grep -v '^[[:space:]]*#' "$executor_gateway_env" | grep -v '^[[:space:]]*$' || true)
	if [[ $line != EXECUTOR_GATEWAY_ARGS=* || $line == *$'\n'* ]]; then
		echo "node-preflight: executor-gateway.env must contain exactly one EXECUTOR_GATEWAY_ARGS line" >&2
		exit 2
	fi
	value=${line#EXECUTOR_GATEWAY_ARGS=}
	if [[ -n $value ]]; then
		resolved_gateway_env=$(readlink -f "$executor_gateway_env")
		if [[ ! -f $resolved_gateway_env || -L $resolved_gateway_env || $(stat -c '%u:%g:%a' "$resolved_gateway_env") != 0:0:600 ]]; then
			echo "node-preflight: relay binding must resolve to a root-owned regular file with mode 0600" >&2
			exit 2
		fi
		read -r -a gateway_args <<<"$value"
		if (( ${#gateway_args[@]} != 4 )); then
			echo "node-preflight: gateway topology requires exactly four arguments" >&2
			exit 2
		fi
		for prefix in -gateway-control-socket= -gateway-grant-root= -relay-image= -relay-gid=; do
			found=0
			for argument in "${gateway_args[@]}"; do [[ $argument == "$prefix"* ]] && ((found += 1)); done
			(( found == 1 )) || { echo "node-preflight: gateway argument $prefix must appear exactly once" >&2; exit 2; }
		done
		binding_schema=$(grep -Fxc '# steward.relay-binding.v1' "$resolved_gateway_env" || true)
		binding_release=$(sed -n 's/^# release_version=//p' "$resolved_gateway_env")
		binding_binary_sha=$(sed -n 's/^# relay_binary_sha256=//p' "$resolved_gateway_env")
		binding_image_id=$(sed -n 's/^# relay_image_id=//p' "$resolved_gateway_env")
		if [[ $binding_schema != 1 || $binding_release != "$expected_version" ||
			! $binding_binary_sha =~ ^[a-f0-9]{64}$ || $binding_binary_sha != "$(hash_file "$relay_bin")" ||
			! $binding_image_id =~ ^sha256:[a-f0-9]{64}$ ]]; then
			echo "node-preflight: relay binding does not match the prospective Steward release" >&2
			exit 2
		fi
		relay_image=
		for argument in "${gateway_args[@]}"; do
			[[ $argument == -relay-image=* ]] && relay_image=${argument#-relay-image=}
		done
		if [[ $relay_image != "$binding_image_id" ]]; then
			echo "node-preflight: relay binding image ID does not match Executor arguments" >&2
			exit 2
		fi
		image_version=$(docker image inspect --format '{{index .Config.Labels "io.hardrails.steward.release.version"}}' "$relay_image")
		image_binary_sha=$(docker image inspect --format '{{index .Config.Labels "io.hardrails.steward.relay.binary.sha256"}}' "$relay_image")
		image_id=$(docker image inspect --format '{{.Id}}' "$relay_image")
		if [[ $image_id != "$relay_image" || $image_version != "$binding_release" || $image_binary_sha != "$binding_binary_sha" ]]; then
			echo "node-preflight: relay image identity or labels do not match its release binding" >&2
			exit 2
		fi
		if (( admission_set != ${#admission_keys[@]} )); then
			echo "node-preflight: gateway topology requires complete signed admission" >&2
			exit 2
		fi
		server_version=$(docker version --format '{{.Server.Version}}')
		server_major=${server_version%%.*}
		if [[ ! $server_major =~ ^[0-9]+$ ]] || (( server_major < 28 )); then
			echo "node-preflight: gateway topology requires Docker 28 or newer for isolated bridge gateway mode (server reports ${server_version:-unknown})" >&2
			exit 2
		fi
	fi
fi

runuser -u steward -- "$steward_bin" -check-config -config "$steward_config" \
	-audit-log-file /var/log/steward/audit.jsonl
runuser -u steward-gateway -- "$gateway_bin" -check-config -config "$gateway_config"
runuser -u steward-executor -- "$executor_bin" -check-config \
	-token-file "${executor[EXECUTOR_TOKEN_FILE]}" \
	-docker-socket "${executor[EXECUTOR_DOCKER_SOCKET]}" \
	-uplink-url "${executor[EXECUTOR_UPLINK_URL]}" \
	-uplink-credential-file "${executor[EXECUTOR_UPLINK_CREDENTIAL_FILE]}" \
	-uplink-state-file "${executor[EXECUTOR_UPLINK_STATE_FILE]}" \
	-uplink-tls-ca-file "${executor[EXECUTOR_UPLINK_TLS_CA_FILE]}" \
	-max-memory-bytes "${executor[EXECUTOR_MAX_MEMORY_BYTES]}" \
	-max-cpu-millis "${executor[EXECUTOR_MAX_CPU_MILLIS]}" \
	-max-pids "${executor[EXECUTOR_MAX_PIDS]}" \
	-max-workloads "${executor[EXECUTOR_MAX_WORKLOADS]}" \
	-max-workloads-per-tenant "${executor[EXECUTOR_MAX_WORKLOADS_PER_TENANT]}" \
	-max-total-memory-bytes "${executor[EXECUTOR_MAX_TOTAL_MEMORY_BYTES]:-8589934592}" \
	-max-total-cpu-millis "${executor[EXECUTOR_MAX_TOTAL_CPU_MILLIS]:-8000}" \
	-max-total-pids "${executor[EXECUTOR_MAX_TOTAL_PIDS]:-2048}" \
	-max-tenant-memory-bytes "${executor[EXECUTOR_MAX_TENANT_MEMORY_BYTES]:-2147483648}" \
	-max-tenant-cpu-millis "${executor[EXECUTOR_MAX_TENANT_CPU_MILLIS]:-2000}" \
	-max-tenant-pids "${executor[EXECUTOR_MAX_TENANT_PIDS]:-512}" \
	"${admission_args[@]}" "${gateway_args[@]}"
if [[ -n $unit_dir ]]; then
	if [[ ! -d $unit_dir || -L $unit_dir ]]; then
		echo "node-preflight: target unit directory is missing or invalid: $unit_dir" >&2
		exit 2
	fi
	systemd-analyze verify "$unit_dir/steward.service" \
		"$unit_dir/steward-executor.service" "$unit_dir/steward-gateway.service"
else
	systemd-analyze verify steward.service steward-executor.service steward-gateway.service
fi
echo "node-preflight: Steward node configuration valid"
