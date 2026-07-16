#!/bin/bash -p
# Build and bind one release's trusted relay image without network access.
set -euo pipefail
if ! shopt -qo privileged; then
	echo "build-relay-image: execute this root helper directly or invoke it with /bin/bash -p" >&2
	exit 2
fi
test_root=${STEWARD_RELAY_TEST_ROOT:-}
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
LC_ALL=C
LANG=C
HOME=/root
export PATH LC_ALL LANG HOME
unset BASH_ENV ENV CDPATH GLOBIGNORE TAR_OPTIONS GZIP POSIXLY_CORRECT TMPDIR
unset CURL_HOME XDG_CONFIG_HOME DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG
unset DOCKER_CERT_PATH DOCKER_TLS_VERIFY DOCKER_API_VERSION DOCKER_BUILDKIT BUILDKIT_HOST
unset STEWARD_RELAY_BIN STEWARD_RELAY_GID STEWARD_RELAY_BINDING_ROOT STEWARD_RELAY_CURRENT_ENV
IFS=$' \t\n'
umask 077

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

script_file=$(trusted_root_executable "${BASH_SOURCE[0]}") || {
	echo "build-relay-image: this helper and its directory chain must be root-owned and not group- or world-writable" >&2
	exit 2
}
script_dir=$(dirname -- "$script_file")
derived_release_dir=$(dirname -- "$(dirname -- "$script_dir")")

if [[ -n $test_root ]]; then
	if [[ ! $test_root =~ ^/run/steward-relay-test\.[A-Za-z0-9]{6,32}$ ]] ||
		! trusted_root_directory_chain "$test_root" ||
		[[ $script_file != "$test_root"/releases/*/integration/scripts/build-relay-image.sh ]]; then
		echo "build-relay-image: refusing an invalid isolated relay test root" >&2
		exit 2
	fi
	docker_bin=$(trusted_root_executable "$test_root/bin/docker") || {
		echo "build-relay-image: isolated relay test root has no trusted Docker fixture" >&2
		exit 2
	}
	binding_root="$test_root/relay-images"
	live_env="$test_root/etc/executor-gateway.env"
	relay_gid=4242
else
	case "$script_file" in
		/opt/steward/releases/*/integration/scripts/build-relay-image.sh) ;;
		*)
			echo "build-relay-image: execute the helper from an installed immutable Steward release" >&2
			exit 2
			;;
	esac
	docker_path=$(command -v docker 2>/dev/null || true)
	[[ -n $docker_path ]] || { echo "build-relay-image: Docker is required" >&2; exit 2; }
	docker_bin=$(trusted_root_executable "$docker_path") || {
		echo "build-relay-image: Docker must be a trusted root-owned executable" >&2
		exit 2
	}
	binding_root=/var/lib/steward-node/relay-images
	live_env=/etc/steward/executor-gateway.env
	relay_gid=$(getent group steward-relay | cut -d: -f3)
fi

if [[ -n $release_dir ]]; then
	[[ $release_dir == /* && -d $release_dir && ! -L $release_dir &&
		$(readlink -e -- "$release_dir" 2>/dev/null) == "$release_dir" ]] || {
		echo "build-relay-image: --release-dir must name an absolute, non-symlink directory" >&2
		exit 2
	}
	if [[ $release_dir != "$derived_release_dir" ]]; then
		echo "build-relay-image: --release-dir must be the immutable release that contains this helper" >&2
		exit 2
	fi
else
	release_dir=$derived_release_dir
fi
trusted_root_directory_chain "$release_dir" || {
	echo "build-relay-image: release directory chain must be root-owned and not group- or world-writable" >&2
	exit 2
}
binary=$(trusted_root_executable "$release_dir/steward-relay") || {
	echo "build-relay-image: release has no trusted steward-relay executable" >&2
	exit 2
}
guard_bin=$(trusted_root_executable "$script_dir/node-removal-guard.sh") || {
	echo "build-relay-image: release has no trusted node-removal guard" >&2
	exit 2
}

"$docker_bin" info >/dev/null 2>&1 || { echo "build-relay-image: Docker is unavailable" >&2; exit 2; }
server_version=$("$docker_bin" version --format '{{.Server.Version}}')
server_major=${server_version%%.*}
if [[ ! $server_major =~ ^[0-9]+$ ]] || (( server_major < 28 )); then
	echo "build-relay-image: positive-capability topology requires Docker 28 or newer for isolated bridge gateway mode (server reports ${server_version:-unknown})" >&2
	exit 2
fi

valid_release_version() {
	local candidate=$1 core prerelease identifier
	(( ${#candidate} <= 128 )) || return 1
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
[[ $relay_gid =~ ^[1-9][0-9]*$ ]] || { echo "build-relay-image: steward-relay group is missing" >&2; exit 2; }

binding_parent=$(dirname -- "$binding_root")
if [[ ! -e $binding_root && ! -L $binding_root ]]; then
	trusted_root_directory_chain "$binding_parent" || {
		echo "build-relay-image: relay binding parent is not trusted" >&2
		exit 2
	}
	install -d -o root -g root -m 0700 "$binding_root"
fi
if [[ -L $binding_root || $(readlink -e -- "$binding_root" 2>/dev/null) != "$binding_root" ||
	$(stat -c '%u:%g:%a' -- "$binding_root") != 0:0:700 ]] ||
	! trusted_root_directory_chain "$binding_root"; then
	echo "build-relay-image: relay binding directory is not a trusted root-only directory" >&2
	exit 2
fi
live_env_parent=$(dirname -- "$live_env")
if [[ ! -e $live_env_parent && ! -L $live_env_parent ]]; then
	trusted_root_directory_chain "$(dirname -- "$live_env_parent")" || {
		echo "build-relay-image: Executor selector parent is not trusted" >&2
		exit 2
	}
	install -d -o root -g root -m 0755 "$live_env_parent"
fi
if ! trusted_root_directory_chain "$live_env_parent"; then
	echo "build-relay-image: Executor selector directory is not trusted" >&2
	exit 2
fi
binding="$binding_root/$version.env"

select_binding() {
	local selected owner mode line unsafe_mode selection_change
	[[ $configure == true ]] || return 0
	selection_change=true
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
	[[ $selection_change == false ]] || STEWARD_RELAY_TEST_ROOT="$test_root" "$guard_bin"
	selector_tmp="$live_env_parent/.${live_env##*/}.new.$$"
	rm -f "$selector_tmp"
	ln -s "$binding" "$selector_tmp"
	mv -Tf "$selector_tmp" "$live_env"
	selector_tmp=
	if sync -f "$live_env_parent" 2>/dev/null; then :; fi
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
	if existing_id=$("$docker_bin" image inspect --format '{{.Id}}' "$existing_image" 2>/dev/null) &&
		existing_label_version=$("$docker_bin" image inspect --format '{{index .Config.Labels "io.hardrails.steward.release.version"}}' "$existing_image" 2>/dev/null) &&
		existing_label_sha=$("$docker_bin" image inspect --format '{{index .Config.Labels "io.hardrails.steward.relay.binary.sha256"}}' "$existing_image" 2>/dev/null); then
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

work=$(mktemp -d /run/steward-relay.XXXXXX)
if [[ ! -d $work || -L $work || $(readlink -e -- "$work" 2>/dev/null) != "$work" ||
	$(stat -c '%u:%g:%a' -- "$work") != 0:0:700 ]]; then
	echo "build-relay-image: could not create a trusted root-only build directory" >&2
	exit 1
fi
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
"$docker_bin" build --network=none --pull=false --provenance=false \
	--build-arg SOURCE_DATE_EPOCH=0 -t "$tag" "$work" >/dev/null
image_id=$("$docker_bin" image inspect --format '{{.Id}}' "$tag")
[[ $image_id =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "build-relay-image: Docker returned an invalid image ID" >&2; exit 1; }
image_version=$("$docker_bin" image inspect --format '{{index .Config.Labels "io.hardrails.steward.release.version"}}' "$image_id")
image_binary_sha=$("$docker_bin" image inspect --format '{{index .Config.Labels "io.hardrails.steward.relay.binary.sha256"}}' "$image_id")
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
		STEWARD_RELAY_TEST_ROOT="$test_root" "$guard_bin"
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
