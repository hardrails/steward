#!/bin/bash -p
# Refuse removal or a release transition while managed Docker objects exist.
set -euo pipefail
if ! shopt -qo privileged; then
	echo "node-removal-guard: execute this root helper directly or invoke it with /bin/bash -p" >&2
	exit 2
fi
test_root=${STEWARD_RELAY_TEST_ROOT:-}
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
LC_ALL=C
LANG=C
HOME=/root
export PATH LC_ALL LANG HOME
unset BASH_ENV ENV CDPATH GLOBIGNORE TMPDIR XDG_CONFIG_HOME
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH
unset DOCKER_TLS_VERIFY DOCKER_API_VERSION DOCKER_BUILDKIT BUILDKIT_HOST
IFS=$' \t\n'
umask 077

purge=false
if [[ ${1:-} == --purge-data ]]; then
	purge=true
	shift
fi
if [[ $# -ne 0 ]]; then
	echo "usage: node-removal-guard.sh [--purge-data]" >&2
	exit 2
fi
if [[ ${EUID} -ne 0 ]]; then
	echo "node-removal-guard: run as root so the drain proof uses the installed control boundary" >&2
	exit 2
fi
# The lifecycle parent owns serialization. Do not let Docker descendants retain
# those descriptors if the parent is killed while this read-only proof runs.
exec 7>&- 9>&-

trusted_root_directory_chain() {
	local directory=$1 current metadata uid mode
	[[ -d $directory && ! -L $directory && $(readlink -e -- "$directory" 2>/dev/null) == "$directory" ]] || return 1
	current=$directory
	while :; do
		metadata=$(stat -c '%u:%a' -- "$current") || return 1
		uid=${metadata%%:*}
		mode=${metadata#*:}
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

if [[ -n $test_root ]]; then
	script_file=$(readlink -e -- "${BASH_SOURCE[0]}" 2>/dev/null || true)
	if [[ ! $test_root =~ ^/run/steward-relay-test\.[A-Za-z0-9]{6,32}$ ]] ||
		! trusted_root_directory_chain "$test_root" ||
		[[ $script_file != "$test_root"/releases/*/integration/scripts/node-removal-guard.sh ]]; then
		echo "node-removal-guard: refusing an invalid isolated relay test root" >&2
		exit 2
	fi
	docker_bin=$(trusted_root_executable "$test_root/bin/docker") || {
		echo "node-removal-guard: isolated relay test root has no trusted Docker fixture" >&2
		exit 2
	}
else
	docker_path=$(command -v docker 2>/dev/null || true)
	[[ -n $docker_path ]] || {
		echo "node-removal-guard: Docker is required to prove that no managed containers or networks remain" >&2
		exit 1
	}
	docker_bin=$(trusted_root_executable "$docker_path") || {
		echo "node-removal-guard: Docker must be a trusted root-owned executable" >&2
		exit 1
	}
fi
[[ -n $docker_bin ]] || {
	echo "node-removal-guard: Docker is required to prove that no managed containers or networks remain" >&2
	exit 1
}

if [[ ! -d /run || -L /run || $(stat -c %u -- /run 2>/dev/null) != 0 ]]; then
	echo "node-removal-guard: refusing an unsafe /run directory" >&2
	exit 2
fi
run_mode=$(stat -c %a -- /run)
if (( (8#$run_mode & 022) != 0 )); then
	echo "node-removal-guard: /run must not be group- or world-writable" >&2
	exit 2
fi
docker_work=$(mktemp -d /run/steward-removal-guard.XXXXXX)
chmod 0700 "$docker_work"
cleanup_docker_work() {
	rm -rf -- "$docker_work"
}
trap cleanup_docker_work EXIT HUP INT TERM

run_bounded_docker() {
	local output=$1
	shift
	local error="$output.err" status=0 output_size error_size
	rm -f -- "$output" "$error"
	(ulimit -c 0; ulimit -f 2048
		exec timeout --signal=TERM --kill-after=5 15 "$docker_bin" "$@") \
		>"$output" 2>"$error" || status=$?
	output_size=$(stat -c %s -- "$output" 2>/dev/null || printf '%s' 1048577)
	error_size=$(stat -c %s -- "$error" 2>/dev/null || printf '%s' 1048577)
	if (( status != 0 || output_size > 1048576 || error_size > 1048576 )); then
		return 1
	fi
}

if ! run_bounded_docker "$docker_work/info" info; then
	echo "node-removal-guard: Docker is unavailable; refusing to remove the control boundary" >&2
	exit 1
fi

run_bounded_docker "$docker_work/agents" ps -aq --filter label=io.hardrails.executor.managed=true || {
	echo "node-removal-guard: Docker container inventory failed or exceeded its resource bound" >&2
	exit 1
}
run_bounded_docker "$docker_work/relays" ps -aq --filter label=io.hardrails.relay.managed=true || {
	echo "node-removal-guard: Docker relay inventory failed or exceeded its resource bound" >&2
	exit 1
}
run_bounded_docker "$docker_work/networks" network ls -q --filter label=io.hardrails.network.managed=true || {
	echo "node-removal-guard: Docker network inventory failed or exceeded its resource bound" >&2
	exit 1
}
if [[ -s $docker_work/agents || -s $docker_work/relays || -s $docker_work/networks ]]; then
	echo "node-removal-guard: managed agent containers, relay containers, or capability networks still exist" >&2
	echo "  Destroy workloads through Steward before removing or changing the control boundary; stopped containers also count." >&2
	exit 1
fi

if [[ $purge == true ]]; then
	run_bounded_docker "$docker_work/volumes" volume ls -q --filter label=io.hardrails.state.managed=true || {
		echo "node-removal-guard: Docker volume inventory failed or exceeded its resource bound" >&2
		exit 1
	}
	if [[ -s $docker_work/volumes ]]; then
		echo "node-removal-guard: managed state volumes still exist" >&2
		echo "  Destroy workloads and explicitly purge retained state before --purge-data." >&2
		exit 1
	fi
fi
