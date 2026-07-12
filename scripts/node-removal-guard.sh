#!/usr/bin/env bash
# Refuse removal or a release transition while managed Docker objects exist.
set -euo pipefail

purge=false
if [[ ${1:-} == --purge-data ]]; then
	purge=true
	shift
fi
if [[ $# -ne 0 ]]; then
	echo "usage: node-removal-guard.sh [--purge-data]" >&2
	exit 2
fi
command -v docker >/dev/null || {
	echo "node-removal-guard: Docker is required to prove that no managed containers or networks remain" >&2
	exit 1
}
docker info >/dev/null 2>&1 || {
	echo "node-removal-guard: Docker is unavailable; refusing to remove the control boundary" >&2
	exit 1
}

all_agents=$(docker ps -aq --filter label=io.hardrails.executor.managed=true)
all_relays=$(docker ps -aq --filter label=io.hardrails.relay.managed=true)
networks=$(docker network ls -q --filter label=io.hardrails.network.managed=true)
if [[ -n $all_agents || -n $all_relays || -n $networks ]]; then
	echo "node-removal-guard: managed agent containers, relay containers, or capability networks still exist" >&2
	echo "  Destroy workloads through Steward before removing or changing the control boundary; stopped containers also count." >&2
	exit 1
fi

if [[ $purge == true ]]; then
	volumes=$(docker volume ls -q --filter label=io.hardrails.state.managed=true)
	if [[ -n $volumes ]]; then
		echo "node-removal-guard: managed state volumes still exist" >&2
		echo "  Destroy workloads and explicitly purge retained state before --purge-data." >&2
		exit 1
	fi
fi
