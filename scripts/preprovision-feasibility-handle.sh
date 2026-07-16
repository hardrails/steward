#!/bin/bash -p
# Trusted disposable-host harness for Phase 1 adapter feasibility. This is not the
# production quota or secret service and must never be exposed to an untrusted API.
set -euo pipefail
if ! shopt -qo privileged; then
	echo "preprovision-feasibility-handle: execute this root helper directly or invoke it with /bin/bash -p" >&2
	exit 2
fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
LANG=C
HOME=/root
export PATH LC_ALL LANG HOME
unset BASH_ENV ENV CDPATH GLOBIGNORE TMPDIR XDG_CONFIG_HOME
IFS=$' \t\n'
umask 077

usage() {
	cat <<'USAGE'
Usage: sudo scripts/preprovision-feasibility-handle.sh KIND TENANT LINEAGE HANDLE_ID GENERATION

KIND is state or secret. The harness derives every directory below the fixed
/var/lib/steward/feasibility-handles root. It accepts no path, mount option, UID,
GID, device, command, or secret value.
USAGE
}

[[ $# -eq 5 ]] || { usage >&2; exit 2; }

kind=$1
tenant=$2
lineage=$3
handle_id=$4
generation=$5
root=/var/lib/steward/feasibility-handles
max_handles=64

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
if (( EUID != 0 )); then
	echo "root is required" >&2
	exit 1
fi
for command in flock sha256sum sort sync; do
	command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 2; }
done

trusted_root_directory_chain() {
	local directory=$1 current metadata uid mode
	[[ -d $directory && ! -L $directory && $(readlink -e -- "$directory" 2>/dev/null) == "$directory" ]] || return 1
	current=$directory
	while :; do
		metadata=$(stat -c '%u:%a' -- "$current") || return 1
		uid=${metadata%%:*}; mode=${metadata#*:}
		[[ $uid == 0 ]] && (( (8#$mode & 022) == 0 )) || return 1
		[[ $current == / ]] && break
		current=$(dirname -- "$current")
	done
}

if ! trusted_root_directory_chain /var/lib; then
	echo "refusing an unsafe /var/lib directory chain" >&2
	exit 1
fi
if [[ ! -e /var/lib/steward && ! -L /var/lib/steward ]]; then
	install -d -o root -g root -m 0750 /var/lib/steward
fi
if ! trusted_root_directory_chain /var/lib/steward; then
	echo "refusing an unsafe /var/lib/steward directory chain" >&2
	exit 1
fi
if [[ ! -e $root && ! -L $root ]]; then
	install -d -o root -g root -m 0700 -- "$root"
fi
if [[ -L $root || ! -d $root || $(stat -c '%u:%g:%a' -- "$root") != 0:0:700 ]] ||
	! trusted_root_directory_chain "$root"; then
	echo "refusing an unsafe feasibility root" >&2
	exit 1
fi

registry_root=$root/registry
payload_root=$root/payload
state_root=$payload_root/state
secret_root=$payload_root/secret
[[ ! -L $root && ! -L $registry_root && ! -L $payload_root && ! -L $state_root && ! -L $secret_root ]] || {
	echo "refusing symlinked root" >&2
	exit 1
}
for directory in "$registry_root" "$payload_root" "$state_root" "$secret_root"; do
	if [[ -e $directory || -L $directory ]]; then
		[[ -d $directory && ! -L $directory && $(stat -c %u -- "$directory") == 0 ]] || {
			echo "refusing an unsafe existing feasibility directory $directory" >&2
			exit 1
		}
	fi
done
[[ -d $registry_root ]] || install -d -o root -g root -m 0700 -- "$registry_root"
[[ -d $payload_root ]] || install -d -o root -g root -m 0711 -- "$payload_root"
[[ -d $state_root ]] || install -d -o root -g root -m 0711 -- "$state_root"
[[ -d $secret_root ]] || install -d -o root -g root -m 0711 -- "$secret_root"
[[ ! -L $root && ! -L $registry_root && ! -L $payload_root && ! -L $state_root && ! -L $secret_root ]] || {
	echo "refusing symlinked root" >&2
	exit 1
}
[[ $(stat -c '%u:%g:%a' -- "$registry_root") == 0:0:700 ]] || { echo "registry directory mode drifted" >&2; exit 1; }
for directory in "$payload_root" "$state_root" "$secret_root"; do
	[[ $(stat -c '%u:%g:%a' -- "$directory") == 0:0:711 ]] || { echo "payload directory mode drifted" >&2; exit 1; }
done

# Lock the already-validated root directory itself. This avoids opening a
# caller-precreated lock pathname and therefore cannot follow a lock symlink.
exec 9<"$root"
flock -x -w 10 9 || { echo "handle registry is busy" >&2; exit 4; }

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
