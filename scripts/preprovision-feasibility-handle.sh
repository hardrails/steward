#!/usr/bin/env bash
# Trusted disposable-host harness for Phase 1 adapter feasibility. This is not the
# production quota or secret service and must never be exposed to an untrusted API.
set -euo pipefail

usage() {
	cat <<'USAGE'
Usage: sudo scripts/preprovision-feasibility-handle.sh KIND TENANT LINEAGE HANDLE_ID GENERATION

KIND is state or secret. The harness derives every directory below the fixed
STEWARD_FEASIBILITY_ROOT (default /var/lib/steward/feasibility-handles). It accepts
no path, mount option, UID, GID, device, command, or secret value.
USAGE
}

[[ $# -eq 5 ]] || { usage >&2; exit 2; }

kind=$1
tenant=$2
lineage=$3
handle_id=$4
generation=$5
root=${STEWARD_FEASIBILITY_ROOT:-/var/lib/steward/feasibility-handles}
max_handles=${STEWARD_FEASIBILITY_MAX_HANDLES:-64}

[[ $kind == state || $kind == secret ]] || { echo "invalid kind" >&2; exit 2; }
for value in "$tenant" "$lineage" "$handle_id"; do
	[[ $value =~ ^[a-z0-9][a-z0-9_-]{0,63}$ ]] || { echo "invalid identifier" >&2; exit 2; }
done
[[ $generation =~ ^[1-9][0-9]*$ ]] || { echo "invalid generation" >&2; exit 2; }
generation_too_large=false
if (( ${#generation} > 20 )); then
	generation_too_large=true
elif (( ${#generation} == 20 )) && [[ $generation != 18446744073709551615 ]] && \
	printf '%s\n' 18446744073709551615 "$generation" | LC_ALL=C sort -C; then
	generation_too_large=true
fi
if [[ $generation_too_large == true ]]; then
	echo "generation exceeds uint64" >&2
	exit 2
fi
if [[ ! $max_handles =~ ^[1-9][0-9]*$ ]] || (( max_handles > 1024 )); then
	echo "invalid STEWARD_FEASIBILITY_MAX_HANDLES" >&2
	exit 2
fi
[[ $root == /* && $root != / ]] || {
	echo "STEWARD_FEASIBILITY_ROOT must be a clean absolute non-root path" >&2
	exit 2
}
[[ $root != *//* && $root != */./* && $root != */. && $root != */../* && $root != */.. && $root != */ ]] || {
	echo "STEWARD_FEASIBILITY_ROOT must be clean" >&2
	exit 2
}
if (( EUID != 0 )) && [[ ${STEWARD_FEASIBILITY_ALLOW_UNPRIVILEGED:-0} != 1 ]]; then
	echo "root is required; the unprivileged override is for disposable tests only" >&2
	exit 1
fi
for command in flock sha256sum sort sync; do
	command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 2; }
done

umask 077
registry_root=$root/registry
payload_root=$root/payload
state_root=$payload_root/state
secret_root=$payload_root/secret
[[ ! -L $root && ! -L $registry_root && ! -L $payload_root && ! -L $state_root && ! -L $secret_root ]] || {
	echo "refusing symlinked root" >&2
	exit 1
}
install -d -m 0700 -- "$root" "$registry_root"
install -d -m 0711 -- "$payload_root" "$state_root" "$secret_root"
[[ ! -L $root && ! -L $registry_root && ! -L $payload_root && ! -L $state_root && ! -L $secret_root ]] || {
	echo "refusing symlinked root" >&2
	exit 1
}
if (( EUID == 0 )); then
	for directory in "$root" "$registry_root" "$payload_root" "$state_root" "$secret_root"; do
		[[ $(stat -c %u -- "$directory") == 0 ]] || { echo "root must own $directory" >&2; exit 1; }
	done
fi

exec 9>"$root/registry.lock"
flock -w 10 9 || { echo "handle registry is busy" >&2; exit 4; }

backend_id=$(printf '%s\0%s\0%s' "$kind" "$handle_id" "$generation" | sha256sum | cut -c1-32)
backend="$payload_root/$kind/$backend_id"
metadata="$registry_root/$backend_id.json"
expected=$(mktemp "$registry_root/.handle.XXXXXX")
trap 'rm -f -- "$expected"' EXIT
printf '{"version":1,"handle_id":"%s","generation":%s,"kind":"%s","tenant_id":"%s","lineage_id":"%s","backend_id":"%s","status":"ready"}\n' \
	"$handle_id" "$generation" "$kind" "$tenant" "$lineage" "$backend_id" >"$expected"
chmod 0600 "$expected"

if [[ -e $backend || -L $backend || -e $metadata || -L $metadata ]]; then
	[[ -d $backend && ! -L $backend && -f $metadata && ! -L $metadata ]] || {
		echo "existing handle backend has an unsafe type" >&2
		exit 1
	}
	if (( EUID == 0 )); then
		[[ $(stat -c %u -- "$backend") == 65532 && $(stat -c %u -- "$metadata") == 0 ]] || {
			echo "existing handle ownership drifted" >&2
			exit 1
		}
	fi
	cmp -s -- "$expected" "$metadata" || { echo "handle binding conflict" >&2; exit 4; }
else
	current=$(find "$state_root" "$secret_root" -mindepth 1 -maxdepth 1 -type d | wc -l)
	(( current < max_handles )) || { echo "handle capacity exceeded" >&2; exit 4; }
	mkdir -m 0700 -- "$backend"
	if (( EUID == 0 )); then
		chown 65532:65532 "$backend"
	fi
	sync -f "$backend"
	sync -f "$expected"
	mv -T -- "$expected" "$metadata"
	sync -f "$registry_root"
fi

printf '{"version":1,"handle_id":"%s","generation":%s,"kind":"%s"}\n' \
	"$handle_id" "$generation" "$kind"
