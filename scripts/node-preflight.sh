#!/usr/bin/env bash
# Validate the installed node, trust material, and both process configurations.
set -euo pipefail

steward_config=${STEWARD_CONFIG_FILE:-/etc/steward/steward.json}
executor_env=${STEWARD_EXECUTOR_ENV_FILE:-/etc/steward/executor.env}
steward_bin=${STEWARD_BIN:-/usr/local/bin/steward}
executor_bin=${STEWARD_EXECUTOR_BIN:-/usr/local/bin/steward-executor}

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
for binary in "$steward_bin" "$executor_bin"; do
	if [[ ! -x $binary ]]; then
		echo "node-preflight: missing executable $binary" >&2
		exit 2
	fi
done
if [[ ! -r $steward_config || ! -r $executor_env ]]; then
	echo "node-preflight: missing readable Steward configuration" >&2
	exit 2
fi

declare -A executor=()
allowed=' EXECUTOR_TOKEN_FILE EXECUTOR_DOCKER_SOCKET EXECUTOR_UPLINK_URL EXECUTOR_UPLINK_CREDENTIAL_FILE EXECUTOR_UPLINK_STATE_FILE EXECUTOR_UPLINK_TLS_CA_FILE EXECUTOR_MAX_MEMORY_BYTES EXECUTOR_MAX_CPU_MILLIS EXECUTOR_MAX_PIDS EXECUTOR_MAX_WORKLOADS EXECUTOR_MAX_WORKLOADS_PER_TENANT '
while IFS= read -r line || [[ -n $line ]]; do
	[[ -z $line || $line == \#* ]] && continue
	if [[ ! $line =~ ^([A-Z_]+)=([^[:space:]]+)$ ]]; then
		echo "node-preflight: invalid executor.env line" >&2
		exit 2
	fi
	key=${BASH_REMATCH[1]}
	value=${BASH_REMATCH[2]}
	if [[ $allowed != *" $key "* || -v "executor[$key]" ]]; then
		echo "node-preflight: unknown or duplicate executor setting $key" >&2
		exit 2
	fi
	executor[$key]=$value
done <"$executor_env"
for key in $allowed; do
	if [[ -z ${executor[$key]:-} ]]; then
		echo "node-preflight: missing executor setting $key" >&2
		exit 2
	fi
done

runuser -u steward -- "$steward_bin" -check-config -config "$steward_config" \
	-audit-log-file /var/log/steward/audit.jsonl
runuser -u steward-executor -- "$executor_bin" -check-config \
	-token-file "${executor[EXECUTOR_TOKEN_FILE]}" \
	-docker-socket "${executor[EXECUTOR_DOCKER_SOCKET]}" \
	-disable-inbound-listener \
	-uplink-url "${executor[EXECUTOR_UPLINK_URL]}" \
	-uplink-credential-file "${executor[EXECUTOR_UPLINK_CREDENTIAL_FILE]}" \
	-uplink-state-file "${executor[EXECUTOR_UPLINK_STATE_FILE]}" \
	-uplink-tls-ca-file "${executor[EXECUTOR_UPLINK_TLS_CA_FILE]}" \
	-max-memory-bytes "${executor[EXECUTOR_MAX_MEMORY_BYTES]}" \
	-max-cpu-millis "${executor[EXECUTOR_MAX_CPU_MILLIS]}" \
	-max-pids "${executor[EXECUTOR_MAX_PIDS]}" \
	-max-workloads "${executor[EXECUTOR_MAX_WORKLOADS]}" \
	-max-workloads-per-tenant "${executor[EXECUTOR_MAX_WORKLOADS_PER_TENANT]}"
systemd-analyze verify steward.service steward-executor.service
echo "node-preflight: Steward node configuration valid"
