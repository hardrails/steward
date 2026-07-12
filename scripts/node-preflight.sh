#!/usr/bin/env bash
# Validate the installed node, trust material, and both process configurations.
set -euo pipefail

steward_config=${STEWARD_CONFIG_FILE:-/etc/steward/steward.json}
executor_env=${STEWARD_EXECUTOR_ENV_FILE:-/etc/steward/executor.env}
executor_gateway_env=${STEWARD_EXECUTOR_GATEWAY_ENV_FILE:-/etc/steward/executor-gateway.env}
steward_bin=${STEWARD_BIN:-/usr/local/bin/steward}
executor_bin=${STEWARD_EXECUTOR_BIN:-/usr/local/bin/steward-executor}
gateway_bin=${STEWARD_GATEWAY_BIN:-/usr/local/bin/steward-gateway}
gateway_config=${STEWARD_GATEWAY_CONFIG_FILE:-/etc/steward/gateway.json}

if [[ ${EUID} -ne 0 ]]; then
	echo "node-preflight: run as root so checks use the service identities" >&2
	exit 2
fi
if [[ $(uname -s) != Linux ]]; then
	echo "node-preflight: Linux is required" >&2
	exit 2
fi
for command in docker runuser systemd-analyze; do
	command -v "$command" >/dev/null || {
		echo "node-preflight: missing required command $command" >&2
		exit 2
	}
done
if ! docker info --format '{{json .Runtimes}}' | grep -q '"runsc"'; then
	echo "node-preflight: Docker runtime runsc is required" >&2
	exit 2
fi
for binary in "$steward_bin" "$executor_bin" "$gateway_bin"; do
	if [[ ! -x $binary ]]; then
		echo "node-preflight: missing executable $binary" >&2
		exit 2
	fi
done
if [[ ! -r $steward_config || ! -r $executor_env || ! -r $gateway_config ]]; then
	echo "node-preflight: missing readable Steward configuration" >&2
	exit 2
fi

declare -A executor=()
required=' EXECUTOR_TOKEN_FILE EXECUTOR_DOCKER_SOCKET EXECUTOR_MAX_MEMORY_BYTES EXECUTOR_MAX_CPU_MILLIS EXECUTOR_MAX_PIDS EXECUTOR_MAX_WORKLOADS EXECUTOR_MAX_WORKLOADS_PER_TENANT '
uplink=' EXECUTOR_UPLINK_URL EXECUTOR_UPLINK_CREDENTIAL_FILE EXECUTOR_UPLINK_STATE_FILE EXECUTOR_UPLINK_TLS_CA_FILE '
optional=' EXECUTOR_ADMISSION_POLICY_FILE EXECUTOR_ADMISSION_SITE_ROOT_PUBLIC_KEY_FILE EXECUTOR_ADMISSION_SITE_ROOT_KEY_ID EXECUTOR_ADMISSION_NODE_ID EXECUTOR_ADMISSION_EVIDENCE_KEY_FILE EXECUTOR_ADMISSION_HOST_ADMIN_ARG '
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
	if [[ $allowed != *" $key "* || -v "executor[$key]" ]]; then
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
elif [[ -n ${executor[EXECUTOR_ADMISSION_HOST_ADMIN_ARG]:-} ]]; then
	echo "node-preflight: host-admin intent requires complete signed admission" >&2
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
		read -r -a gateway_args <<<"$value"
		if (( ${#gateway_args[@]} != 4 )); then
			echo "node-preflight: gateway topology requires exactly four arguments" >&2
			exit 2
		fi
		for prefix in -gateway-control-socket= -gateway-grant-root= -relay-image= -relay-gid=; do
			found=false
			for argument in "${gateway_args[@]}"; do [[ $argument == "$prefix"* ]] && found=true; done
			[[ $found == true ]] || { echo "node-preflight: missing gateway argument $prefix" >&2; exit 2; }
		done
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
	"${admission_args[@]}" "${gateway_args[@]}"
systemd-analyze verify steward.service steward-executor.service steward-gateway.service
echo "node-preflight: Steward node configuration valid"
