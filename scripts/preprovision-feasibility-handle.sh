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
[[ $max_handles =~ ^[1-9][0-9]*$ ]] && (( max_handles <= 1024 )) || {
	echo "invalid STEWARD_FEASIBILITY_MAX_HANDLES" >&2
	exit 2
}
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

umask 077
[[ ! -L $root && ! -L $root/state && ! -L $root/secret ]] || {
	echo "refusing symlinked root" >&2
	exit 1
}
install -d -m 0700 -- "$root" "$root/state" "$root/secret"
[[ ! -L $root && ! -L $root/state && ! -L $root/secret ]] || {
	echo "refusing symlinked root" >&2
	exit 1
}
if (( EUID == 0 )); then
	for directory in "$root" "$root/state" "$root/secret"; do
		[[ $(stat -c %u -- "$directory") == 0 ]] || { echo "root must own $directory" >&2; exit 1; }
	done
fi

backend_id="${handle_id}-${generation}"
backend="$root/$kind/$backend_id"
metadata="$backend/handle.json"
expected=$(mktemp "$root/.handle.XXXXXX")
trap 'rm -f -- "$expected"' EXIT
printf '{"version":1,"handle_id":"%s","generation":%s,"kind":"%s","tenant_id":"%s","lineage_id":"%s","backend_id":"%s","status":"ready"}\n' \
	"$handle_id" "$generation" "$kind" "$tenant" "$lineage" "$backend_id" >"$expected"
chmod 0600 "$expected"

if [[ -e $backend || -L $backend ]]; then
	[[ -d $backend && ! -L $backend && -f $metadata && ! -L $metadata ]] || {
		echo "existing handle backend has an unsafe type" >&2
		exit 1
	}
	cmp -s -- "$expected" "$metadata" || { echo "handle binding conflict" >&2; exit 4; }
else
	current=$(find "$root/state" "$root/secret" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
	(( current < max_handles )) || { echo "handle capacity exceeded" >&2; exit 4; }
	mkdir -m 0700 -- "$backend"
	install -m 0600 -- "$expected" "$metadata"
fi

printf '{"version":1,"handle_id":"%s","generation":%s,"kind":"%s"}\n' \
	"$handle_id" "$generation" "$kind"
