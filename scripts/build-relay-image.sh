#!/usr/bin/env bash
# Build and bind one release's trusted relay image without network access.
set -euo pipefail

usage() {
	cat <<'EOF' >&2
usage: build-relay-image.sh [--release-dir DIR] [--configure] [--replace-missing]

Build the relay image for one installed release and write its immutable,
host-local binding. --configure also selects that binding for Executor; normal
release preparation never changes the live Executor environment. --replace-missing
is for the activation transaction: it permits replacement only when the previously
bound image is absent and the node-removal guard proves that no managed topology
remains; the old binding is archived.
EOF
}

release_dir=
configure=false
replace_missing=false
while [[ $# -gt 0 ]]; do
	case "$1" in
		--release-dir) release_dir=${2:-}; shift 2 ;;
		--configure) configure=true; shift ;;
		--replace-missing) replace_missing=true; shift ;;
		-h | --help) usage; exit 0 ;;
		*) echo "build-relay-image: unknown option $1" >&2; usage; exit 2 ;;
	esac
done

if [[ ${EUID} -ne 0 ]]; then
	echo "build-relay-image: run as root so the release binding is root-owned" >&2
	exit 2
fi
command -v docker >/dev/null || { echo "build-relay-image: Docker is required" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "build-relay-image: Docker is unavailable" >&2; exit 2; }
server_version=$(docker version --format '{{.Server.Version}}')
server_major=${server_version%%.*}
if [[ ! $server_major =~ ^[0-9]+$ ]] || (( server_major < 28 )); then
	echo "build-relay-image: positive-capability topology requires Docker 28 or newer for isolated bridge gateway mode (server reports ${server_version:-unknown})" >&2
	exit 2
fi

if [[ -n $release_dir ]]; then
	[[ $release_dir == /* && -d $release_dir && ! -L $release_dir ]] || {
		echo "build-relay-image: --release-dir must name an absolute, non-symlink directory" >&2
		exit 2
	}
	binary="$release_dir/steward-relay"
else
	binary=${STEWARD_RELAY_BIN:-/usr/local/bin/steward-relay}
fi
[[ -x $binary && -f $binary ]] || { echo "build-relay-image: missing $binary" >&2; exit 2; }

valid_release_version() {
	local candidate=$1 core prerelease identifier
	[[ $candidate =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$ ]] || return 1
	core=${candidate#v}
	if [[ $core == *-* ]]; then
		prerelease=${core#*-}
		IFS=. read -r -a identifiers <<<"$prerelease"
		for identifier in "${identifiers[@]}"; do
			[[ $identifier =~ ^[0-9]+$ && $identifier == 0[0-9]* ]] && return 1
		done
	fi
	return 0
}

version=$($binary -version | awk 'NR == 1 {print $2}')
if ! valid_release_version "$version"; then
	echo "build-relay-image: steward-relay reported an invalid release version '${version:-<empty>}'" >&2
	exit 2
fi
if [[ -n $release_dir && ${release_dir##*/} != "$version" ]]; then
	echo "build-relay-image: release directory '${release_dir##*/}' does not match relay version '$version'" >&2
	exit 2
fi

hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		echo "build-relay-image: sha256sum or shasum is required" >&2
		exit 2
	fi
}

binary_sha=$(hash_file "$binary")
[[ $binary_sha =~ ^[a-f0-9]{64}$ ]] || { echo "build-relay-image: invalid relay binary SHA-256" >&2; exit 2; }
relay_gid=${STEWARD_RELAY_GID:-$(getent group steward-relay | cut -d: -f3)}
[[ $relay_gid =~ ^[1-9][0-9]*$ ]] || { echo "build-relay-image: steward-relay group is missing" >&2; exit 2; }

binding_root=${STEWARD_RELAY_BINDING_ROOT:-/var/lib/steward-node/relay-images}
live_env=${STEWARD_RELAY_CURRENT_ENV:-/etc/steward/executor-gateway.env}
[[ $binding_root == /* && $live_env == /* ]] || {
	echo "build-relay-image: binding paths must be absolute" >&2
	exit 2
}
install -d -o root -g root -m 0700 "$binding_root"
binding="$binding_root/$version.env"

select_binding() {
	local selected owner mode line unsafe_mode selection_change
	[[ $configure == true ]] || return 0
	selection_change=true
	install -d -o root -g root -m 0755 "$(dirname "$live_env")"
	if [[ -e $live_env || -L $live_env ]]; then
		if [[ -L $live_env ]]; then
			selected=$(readlink "$live_env")
			case "$selected" in "$binding_root"/*.env) ;; *)
				echo "build-relay-image: refusing unmanaged selector $live_env" >&2
				return 2
			esac
			[[ $selected != "$binding" ]] || selection_change=false
		else
			owner=$(stat -c '%u' "$live_env")
			mode=$(stat -c '%a' "$live_env")
			line=$(grep -v '^[[:space:]]*#' "$live_env" | grep -v '^[[:space:]]*$' || true)
			unsafe_mode=false
			(( (8#$mode & 0022) == 0 )) || unsafe_mode=true
			if [[ $owner != 0 || $unsafe_mode == true || ( -n $line && $line != EXECUTOR_GATEWAY_ARGS=* ) || $line == *$'\n'* ]]; then
				echo "build-relay-image: refusing unmanaged Executor gateway environment $live_env" >&2
				return 2
			fi
		fi
	fi
	# Selecting a different relay image can strand a retained workload. Require
	# the same zero-container/zero-network proof used for release activation.
	[[ $selection_change == false ]] || "$(dirname "$0")/node-removal-guard.sh"
	selector_tmp="$(dirname "$live_env")/.${live_env##*/}.new.$$"
	rm -f "$selector_tmp"
	ln -s "$binding" "$selector_tmp"
	mv -Tf "$selector_tmp" "$live_env"
	selector_tmp=
	if sync -f "$(dirname "$live_env")" 2>/dev/null; then :; fi
	echo "build-relay-image: selected relay binding for $version"
}

existing_image_missing=false
if [[ -e $binding || -L $binding ]]; then
	binding_meta=$(stat -c '%u:%g:%a' "$binding" 2>/dev/null || true)
	existing_version=$(sed -n 's/^# release_version=//p' "$binding" 2>/dev/null || true)
	existing_binary_sha=$(sed -n 's/^# relay_binary_sha256=//p' "$binding" 2>/dev/null || true)
	existing_image=$(sed -n 's/^# relay_image_id=//p' "$binding" 2>/dev/null || true)
	existing_line=$(grep -v '^[[:space:]]*#' "$binding" 2>/dev/null | grep -v '^[[:space:]]*$' || true)
	existing_arguments="-gateway-control-socket=/run/steward-gateway/control.sock -gateway-grant-root=/run/steward-gateway/grants -relay-image=$existing_image -relay-gid=$relay_gid"
	if [[ ! -f $binding || -L $binding || $binding_meta != 0:0:600 || $existing_version != "$version" ||
		$existing_binary_sha != "$binary_sha" || ! $existing_image =~ ^sha256:[a-f0-9]{64}$ ||
		$existing_line != "EXECUTOR_GATEWAY_ARGS=$existing_arguments" ]]; then
		echo "build-relay-image: existing release binding is malformed or does not match the target binary" >&2
		exit 1
	fi
	if existing_id=$(docker image inspect --format '{{.Id}}' "$existing_image" 2>/dev/null) &&
		existing_label_version=$(docker image inspect --format '{{index .Config.Labels "io.hardrails.steward.release.version"}}' "$existing_image" 2>/dev/null) &&
		existing_label_sha=$(docker image inspect --format '{{index .Config.Labels "io.hardrails.steward.relay.binary.sha256"}}' "$existing_image" 2>/dev/null); then
		if [[ $existing_id != "$existing_image" || $existing_label_version != "$version" || $existing_label_sha != "$binary_sha" ]]; then
			echo "build-relay-image: existing relay image does not match its immutable release binding" >&2
			exit 1
		fi
		select_binding
		echo "build-relay-image: immutable relay image $existing_image (already present)"
		echo "build-relay-image: release binding $binding"
		echo "$existing_line"
		exit 0
	fi
	existing_image_missing=true
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/steward-relay.XXXXXX")
binding_tmp=
selector_tmp=
cleanup() {
	rm -rf -- "$work"
	rm -f -- "${binding_tmp:-}" "${selector_tmp:-}"
}
trap cleanup EXIT HUP INT TERM
install -m 0755 "$binary" "$work/steward-relay"
cat >"$work/Dockerfile" <<EOF
FROM scratch
COPY steward-relay /steward-relay
LABEL io.hardrails.steward.release.version="$version"
LABEL io.hardrails.steward.relay.binary.sha256="$binary_sha"
USER 65532:65532
ENTRYPOINT ["/steward-relay"]
EOF
# Context mtimes are fixed so rebuilding the same release does not manufacture a
# different content identity merely because the operator ran this helper later.
TZ=UTC touch -t 197001010000.00 "$work/steward-relay" "$work/Dockerfile" "$work"

tag="steward-relay-local:${version#v}"
docker build --network=none --pull=false --provenance=false \
	--build-arg SOURCE_DATE_EPOCH=0 -t "$tag" "$work" >/dev/null
image_id=$(docker image inspect --format '{{.Id}}' "$tag")
[[ $image_id =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "build-relay-image: Docker returned an invalid image ID" >&2; exit 1; }
image_version=$(docker image inspect --format '{{index .Config.Labels "io.hardrails.steward.release.version"}}' "$image_id")
image_binary_sha=$(docker image inspect --format '{{index .Config.Labels "io.hardrails.steward.relay.binary.sha256"}}' "$image_id")
if [[ $image_version != "$version" || $image_binary_sha != "$binary_sha" ]]; then
	echo "build-relay-image: built image labels do not bind the requested release and relay binary" >&2
	exit 1
fi

arguments="-gateway-control-socket=/run/steward-gateway/control.sock -gateway-grant-root=/run/steward-gateway/grants -relay-image=$image_id -relay-gid=$relay_gid"
binding_tmp=$(mktemp "$binding_root/.${version}.env.XXXXXX")
cat >"$binding_tmp" <<EOF
# steward.relay-binding.v1
# release_version=$version
# relay_binary_sha256=$binary_sha
# relay_image_id=$image_id
EXECUTOR_GATEWAY_ARGS=$arguments
EOF
chown root:root "$binding_tmp"
chmod 0600 "$binding_tmp"
if [[ -e $binding || -L $binding ]]; then
	binding_meta=$(stat -c '%u:%g:%a' "$binding" 2>/dev/null || true)
	if [[ ! -f $binding || -L $binding || $binding_meta != 0:0:600 ]] || ! cmp -s "$binding_tmp" "$binding"; then
		if [[ $existing_image_missing != true || $replace_missing != true ]]; then
			echo "build-relay-image: rebuilt image ID differs from the retained binding" >&2
			echo "  The live selector was not changed. Re-run through drained release activation, which permits an audited missing-image replacement." >&2
			exit 1
		fi
		"$(dirname "$0")/node-removal-guard.sh"
		retired="$binding_root/retired"
		install -d -o root -g root -m 0700 "$retired"
		retired_binding="$retired/$version.${existing_image#sha256:}.env"
		if [[ -e $retired_binding || -L $retired_binding ]]; then
			if [[ ! -f $retired_binding || -L $retired_binding ]] || ! cmp -s "$binding" "$retired_binding"; then
				echo "build-relay-image: conflicting retired binding $retired_binding" >&2
				exit 1
			fi
		else
			install -o root -g root -m 0600 "$binding" "$retired_binding"
		fi
		mv -f "$binding_tmp" "$binding"
		binding_tmp=
	fi
	if [[ -n $binding_tmp ]]; then rm -f "$binding_tmp"; binding_tmp=; fi
else
	mv -f "$binding_tmp" "$binding"
	binding_tmp=
	if sync -f "$binding_root" 2>/dev/null; then :; fi
fi

select_binding

echo "build-relay-image: immutable relay image $image_id"
echo "build-relay-image: release binding $binding"
echo "EXECUTOR_GATEWAY_ARGS=$arguments"
