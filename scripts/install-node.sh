#!/usr/bin/env bash
# Install one versioned Steward node release without enabling or starting it.
set -euo pipefail

if [[ $# -ne 2 || $1 != --expected-version || -z ${2:-} ]]; then
	echo "usage: install-node.sh --expected-version vX.Y.Z" >&2
	exit 2
fi
expected_version=$2
if [[ -n ${STEWARD_EXPECTED_VERSION:-} && $STEWARD_EXPECTED_VERSION != "$expected_version" ]]; then
	echo "install-node: package expects '$expected_version' but the caller requested '$STEWARD_EXPECTED_VERSION'" >&2
	exit 2
fi

valid_release_version() {
	local candidate=$1 core prerelease identifier
	[[ $candidate =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$ ]] || return 1
	core=${candidate#v}
	if [[ $core == *-* ]]; then
		prerelease=${core#*-}
		IFS=. read -r -a identifiers <<<"$prerelease"
		for identifier in "${identifiers[@]}"; do
			if [[ $identifier =~ ^[0-9]+$ && $identifier == 0[0-9]* ]]; then
				return 1
			fi
		done
	fi
	return 0
}

if ! valid_release_version "$expected_version"; then
	echo "install-node: --expected-version must be an installable vX.Y.Z release tag" >&2
	exit 2
fi
if [[ ${EUID} -ne 0 ]]; then
	echo "install-node: run as root" >&2
	exit 2
fi
if [[ $(uname -s) != Linux ]]; then
	echo "install-node: the Steward node appliance supports Linux only" >&2
	exit 2
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
case "$(uname -m)" in
	x86_64 | amd64) goarch=amd64 ;;
	aarch64 | arm64) goarch=arm64 ;;
	*) echo "install-node: unsupported architecture $(uname -m)" >&2; exit 2 ;;
esac

release_files=(
	steward
	steward-executor
	steward-gateway
	steward-mcp
	steward-relay
	stewardctl
	integration/deploy/config/executor-gateway.env
	integration/deploy/config/executor.env
	integration/deploy/config/gateway.json.in
	integration/deploy/config/steward-local.json
	integration/deploy/config/steward.json
	integration/deploy/systemd/steward-executor.service
	integration/deploy/systemd/steward-gateway.service
	integration/deploy/systemd/steward.service
	integration/scripts/activate-node-release.sh
	integration/scripts/build-relay-image.sh
	integration/scripts/configure-admission.sh
	integration/scripts/configure-node.sh
	integration/scripts/install-node.sh
	integration/scripts/node-preflight.sh
	integration/scripts/node-removal-guard.sh
	integration/scripts/uninstall-node.sh
)

release_file_path() {
	local base=$1 layout=$2 logical=$3
	if [[ $layout == source && $logical == integration/* ]]; then
		printf '%s/%s\n' "$base" "${logical#integration/}"
	else
		printf '%s/%s\n' "$base" "$logical"
	fi
}

hash_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		echo "install-node: sha256sum or shasum is required" >&2
		exit 2
	fi
}

write_canonical_manifest() {
	local base=$1 layout=$2 output=$3 logical path suffix index last_index
	{
		printf '{\n'
		printf '  "schema": "steward.release.v2",\n'
		printf '  "version": "%s",\n' "$expected_version"
		printf '  "os": "linux",\n'
		printf '  "arch": "%s",\n' "$goarch"
		printf '  "state_formats": {\n'
		printf '    "admission_fence": {"read_min": 1, "read_max": 2, "write": 2},\n'
		printf '    "evidence_log": {"read_min": 1, "read_max": 1, "write": 1},\n'
		printf '    "gateway_state": {"read_min": 1, "read_max": 2, "write": 2},\n'
		printf '    "operation_journal": {"read_min": 1, "read_max": 1, "write": 1},\n'
		printf '    "supervisor_state": {"read_min": 1, "read_max": 1, "write": 1},\n'
		printf '    "uplink_state": {"read_min": 2, "read_max": 2, "write": 2}\n'
		printf '  },\n'
		printf '  "files": {\n'
		last_index=$((${#release_files[@]} - 1))
		for index in "${!release_files[@]}"; do
			logical=${release_files[$index]}
			path=$(release_file_path "$base" "$layout" "$logical")
			if [[ ! -f $path || -L $path ]]; then
				echo "install-node: release is missing regular file $logical" >&2
				return 2
			fi
			suffix=,
			(( index == last_index )) && suffix=
			printf '    "%s": "%s"%s\n' "$logical" "$(hash_file "$path")" "$suffix"
		done
		printf '  }\n'
		printf '}\n'
	} >"$output"
}

verify_release() {
	local base=$1 layout=$2 expected_tmp manifest_version file_count
	local manifest="$base/release.json"
	if [[ ! -f $manifest || -L $manifest ]]; then
		echo "install-node: release is missing regular file release.json" >&2
		return 2
	fi
	manifest_version=$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' "$manifest")
	if [[ $manifest_version != "$expected_version" ]]; then
		echo "install-node: release.json reports '${manifest_version:-<invalid>}', expected '$expected_version'" >&2
		return 2
	fi
	expected_tmp=$(mktemp)
	if ! write_canonical_manifest "$base" "$layout" "$expected_tmp"; then
		rm -f "$expected_tmp"
		return 2
	fi
	if ! cmp -s "$manifest" "$expected_tmp"; then
		rm -f "$expected_tmp"
		echo "install-node: release.json does not match the target or release files" >&2
		return 2
	fi
	rm -f "$expected_tmp"
	if [[ $layout == installed ]]; then
		if find "$base" -mindepth 1 -type l -print -quit | grep -q . || \
			find "$base" -mindepth 1 ! -type f ! -type d -print -quit | grep -q .; then
			echo "install-node: immutable release contains a symlink or special file" >&2
			return 2
		fi
		file_count=$(find "$base" -mindepth 1 -type f | wc -l)
		if [[ $file_count -ne $((${#release_files[@]} + 1)) ]]; then
			echo "install-node: immutable release contains unexpected files" >&2
			return 2
		fi
	fi
}

# Validate the release identity, target, complete file set, and every digest
# before creating users or writing anything to the host.
verify_release "$root" source

getent group docker >/dev/null || {
	echo "install-node: Docker group is missing; install Docker before Steward" >&2
	exit 2
}
for group in steward steward-executor steward-gateway steward-relay; do
	getent group "$group" >/dev/null || groupadd --system "$group"
done
if ! id steward >/dev/null 2>&1; then
	useradd --system --gid steward --home-dir /var/lib/steward --shell /usr/sbin/nologin steward
elif [[ $(id -gn steward) != steward ]]; then
	echo "install-node: existing steward user must have primary group steward" >&2
	exit 2
fi
if ! id steward-executor >/dev/null 2>&1; then
	useradd --system --gid steward-executor --home-dir /var/lib/steward-executor --shell /usr/sbin/nologin \
		--groups docker steward-executor
else
	[[ $(id -gn steward-executor) == steward-executor ]] || {
		echo "install-node: existing steward-executor user must have primary group steward-executor" >&2
		exit 2
	}
	usermod --append --groups docker steward-executor
fi
if ! id steward-gateway >/dev/null 2>&1; then
	useradd --system --gid steward-gateway --home-dir /var/lib/steward-gateway --shell /usr/sbin/nologin \
		--groups steward-executor,steward-relay steward-gateway
else
	[[ $(id -gn steward-gateway) == steward-gateway ]] || {
		echo "install-node: existing steward-gateway user must have primary group steward-gateway" >&2
		exit 2
	}
	usermod --append --groups steward-executor,steward-relay steward-gateway
fi
steward_uid=$(id -u steward)
executor_uid=$(id -u steward-executor)
gateway_uid=$(id -u steward-gateway)
if (( steward_uid == 0 || executor_uid == 0 || gateway_uid == 0 )) || \
	(( steward_uid == executor_uid || steward_uid == gateway_uid || executor_uid == gateway_uid )); then
	echo "install-node: Steward service identities must be distinct non-root users" >&2
	exit 2
fi
if id -nG steward | tr ' ' '\n' | grep -qx docker || \
	id -nG steward-gateway | tr ' ' '\n' | grep -qx docker; then
	echo "install-node: only steward-executor may hold Docker authority" >&2
	exit 2
fi

# Run the archive's binaries only as the unprivileged lifecycle identity, which is
# forbidden from the Docker group. The installer itself is trusted only after the
# operator's out-of-band bundle check; this still avoids granting a malformed binary
# root merely to read its version.
install -d -o root -g root -m 0755 /opt/steward
incoming=$(mktemp -d /opt/steward/.incoming.XXXXXX)
trap 'rm -rf "$incoming"' EXIT
chmod 0755 "$incoming"
for binary in steward stewardctl steward-mcp steward-executor steward-gateway steward-relay; do
	install -o root -g root -m 0755 "$root/$binary" "$incoming/$binary"
done
install -d -o root -g root -m 0755 "$incoming/integration" \
	"$incoming/integration/deploy" "$incoming/integration/deploy/config" \
	"$incoming/integration/deploy/systemd" "$incoming/integration/scripts"
for file in deploy/config/executor-gateway.env deploy/config/executor.env \
	deploy/config/gateway.json.in deploy/config/steward-local.json deploy/config/steward.json \
	deploy/systemd/steward-executor.service deploy/systemd/steward-gateway.service \
	deploy/systemd/steward.service; do
	install -o root -g root -m 0644 "$root/$file" "$incoming/integration/$file"
done
for script in activate-node-release.sh build-relay-image.sh configure-admission.sh \
	configure-node.sh install-node.sh node-preflight.sh node-removal-guard.sh uninstall-node.sh; do
	install -o root -g root -m 0755 "$root/scripts/$script" "$incoming/integration/scripts/$script"
done
install -o root -g root -m 0644 "$root/release.json" "$incoming/release.json"
verify_release "$incoming" installed

steward_version=$(runuser -u steward -- "$incoming/steward" -version | awk '{print $2}')
ctl_version=$(runuser -u steward -- "$incoming/stewardctl" -version | awk '{print $2}')
executor_version=$(runuser -u steward -- "$incoming/steward-executor" -version | awk '{print $2}')
gateway_version=$(runuser -u steward -- "$incoming/steward-gateway" -version | awk '{print $2}')
relay_version=$(runuser -u steward -- "$incoming/steward-relay" -version | awk '{print $2}')
mcp_version=$(runuser -u steward -- "$incoming/steward-mcp" -version | awk '{print $2}')
if [[ -z $steward_version || $steward_version != "$executor_version" || $steward_version != "$ctl_version" || \
	$steward_version != "$gateway_version" || $steward_version != "$relay_version" || $steward_version != "$mcp_version" ]]; then
	echo "install-node: Steward process versions do not match" >&2
	exit 2
fi
if [[ $steward_version != "$expected_version" ]]; then
	echo "install-node: binaries report '$steward_version', expected '$expected_version'" >&2
	exit 2
fi

release_dir="/opt/steward/releases/$expected_version"
install -d -o root -g root -m 0755 /opt/steward/releases
if [[ -e $release_dir || -L $release_dir ]]; then
	[[ -d $release_dir && ! -L $release_dir ]] || {
		echo "install-node: existing release path is not a directory: $release_dir" >&2
		exit 2
	}
	verify_release "$release_dir" installed
	if ! cmp -s "$incoming/release.json" "$release_dir/release.json"; then
		echo "install-node: refusing to rewrite immutable release $expected_version" >&2
		exit 2
	fi
	rm -rf "$incoming"
else
	mv "$incoming" "$release_dir"
fi
trap - EXIT
install -d -o root -g root -m 0755 /etc/steward /usr/local/bin /usr/local/libexec/steward \
	/usr/local/lib/systemd/system
install -d -o steward -g steward -m 0700 /var/lib/steward /var/log/steward
install -d -o steward-executor -g steward-executor -m 0700 /var/lib/steward-executor
install -d -o steward-gateway -g steward-gateway -m 0700 /var/lib/steward-gateway
install -d -o root -g root -m 0700 /var/lib/steward-node /var/lib/steward-node/relay-images

release_config="$release_dir/integration/deploy/config"
release_units="$release_dir/integration/deploy/systemd"

if [[ ! -e /etc/steward/steward.json ]]; then
	install -o root -g steward -m 0640 "$release_config/steward.json" \
		/etc/steward/steward.json
fi
if [[ ! -e /etc/steward/executor.env ]]; then
	install -o root -g root -m 0600 "$release_config/executor.env" \
		/etc/steward/executor.env
fi
if [[ ! -e /etc/steward/executor-gateway.env ]]; then
	install -o root -g root -m 0600 "$release_config/executor-gateway.env" \
		/etc/steward/executor-gateway.env
fi
if [[ ! -e /etc/steward/gateway-service-token ]]; then
	od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >/etc/steward/gateway-service-token
	printf '\n' >>/etc/steward/gateway-service-token
	chown steward-gateway:steward-gateway /etc/steward/gateway-service-token
	chmod 0600 /etc/steward/gateway-service-token
fi
if [[ ! -e /etc/steward/gateway.json ]]; then
	sed -e "s/@EXECUTOR_GID@/$(id -g steward-executor)/g" \
		-e "s/@RELAY_GID@/$(getent group steward-relay | cut -d: -f3)/g" \
		"$release_config/gateway.json.in" >/etc/steward/gateway.json
	chown root:steward-gateway /etc/steward/gateway.json
	chmod 0640 /etc/steward/gateway.json
fi

if [[ -e /opt/steward/current || -L /opt/steward/current ]]; then
	current_target=$(readlink /opt/steward/current 2>/dev/null || true)
	case "$current_target" in
	/opt/steward/releases/*)
		[[ -d $current_target && ! -L $current_target ]] || {
			echo "install-node: active release target is missing or invalid: $current_target" >&2
			exit 2
		}
		;;
	*)
		echo "install-node: refusing unmanaged /opt/steward/current" >&2
		exit 2
		;;
	esac
	selection="staged; the active release was not changed"
else
	# A first install may repair only an already-correct managed symlink. Any
	# unrelated file at a stable entry point belongs to the operator and is not
	# replaced implicitly.
	for binary in steward stewardctl steward-mcp steward-executor steward-gateway steward-relay; do
		path="/usr/local/bin/$binary"
		if [[ -e $path || -L $path ]]; then
			[[ -L $path && $(readlink "$path") == "/opt/steward/current/$binary" ]] || {
				echo "install-node: refusing to replace unmanaged $path" >&2
				exit 2
			}
		fi
	done
	for mapping in \
		activate-node-release:/opt/steward/current/integration/scripts/activate-node-release.sh \
		node-preflight:/opt/steward/current/integration/scripts/node-preflight.sh \
		configure-node:/opt/steward/current/integration/scripts/configure-node.sh \
		configure-admission:/opt/steward/current/integration/scripts/configure-admission.sh \
		uninstall-node:/opt/steward/current/integration/scripts/uninstall-node.sh \
		node-removal-guard:/opt/steward/current/integration/scripts/node-removal-guard.sh \
		build-relay-image:/opt/steward/current/integration/scripts/build-relay-image.sh; do
		name=${mapping%%:*}
		target=${mapping#*:}
		path="/usr/local/libexec/steward/$name"
		if [[ -e $path || -L $path ]]; then
			[[ -L $path && $(readlink "$path") == "$target" ]] || {
				echo "install-node: refusing to replace unmanaged $path" >&2
				exit 2
			}
		fi
	done
	for unit in steward.service steward-executor.service steward-gateway.service; do
		path="/usr/local/lib/systemd/system/$unit"
		target="/opt/steward/current/integration/deploy/systemd/$unit"
		if [[ -e $path || -L $path ]]; then
			[[ -L $path && $(readlink "$path") == "$target" ]] || {
				echo "install-node: refusing to replace unmanaged $path" >&2
				exit 2
			}
		fi
		legacy="/etc/systemd/system/$unit"
		if [[ -e $legacy || -L $legacy ]]; then
			if [[ -f $legacy && ! -L $legacy ]] && cmp -s "$legacy" "$release_units/$unit"; then
				:
			else
				echo "install-node: refusing modified $legacy because it shadows the packaged vendor unit" >&2
				echo "  Preserve local settings in /etc/systemd/system/$unit.d/*.conf, then remove the full-unit override and re-run." >&2
				exit 2
			fi
		fi
	done

	current_tmp="/opt/steward/.current.new.$$"
	rm -f "$current_tmp"
	ln -s "$release_dir" "$current_tmp"
	mv -Tf "$current_tmp" /opt/steward/current
	selection="selected for first-time configuration"

	for binary in steward stewardctl steward-mcp steward-executor steward-gateway steward-relay; do
		tmp="/usr/local/bin/.${binary}.new.$$"
		rm -f "$tmp"
		ln -s "/opt/steward/current/$binary" "$tmp"
		mv -Tf "$tmp" "/usr/local/bin/$binary"
	done
	for mapping in \
		activate-node-release:/opt/steward/current/integration/scripts/activate-node-release.sh \
		node-preflight:/opt/steward/current/integration/scripts/node-preflight.sh \
		configure-node:/opt/steward/current/integration/scripts/configure-node.sh \
		configure-admission:/opt/steward/current/integration/scripts/configure-admission.sh \
		uninstall-node:/opt/steward/current/integration/scripts/uninstall-node.sh \
		node-removal-guard:/opt/steward/current/integration/scripts/node-removal-guard.sh \
		build-relay-image:/opt/steward/current/integration/scripts/build-relay-image.sh; do
		name=${mapping%%:*}
		target=${mapping#*:}
		tmp="/usr/local/libexec/steward/.${name}.new.$$"
		rm -f "$tmp"
		ln -s "$target" "$tmp"
		mv -Tf "$tmp" "/usr/local/libexec/steward/$name"
	done
	for unit in steward.service steward-executor.service steward-gateway.service; do
		legacy="/etc/systemd/system/$unit"
		if [[ -e $legacy || -L $legacy ]]; then
			rm -f "$legacy"
			echo "install-node: migrated legacy installer-owned $legacy"
		fi
		tmp="/usr/local/lib/systemd/system/.${unit}.new.$$"
		rm -f "$tmp"
		ln -s "/opt/steward/current/integration/deploy/systemd/$unit" "$tmp"
		mv -Tf "$tmp" "/usr/local/lib/systemd/system/$unit"
	done
	systemctl daemon-reload
fi

echo "install-node: installed Steward $expected_version ($selection)"
echo "install-node: services remain disabled and stopped"
if [[ $selection == selected* ]]; then
	echo "install-node: install customer credentials and CA material, initialize the Executor fence, then run:"
	echo "  /usr/local/libexec/steward/node-preflight"
	echo "  systemctl enable --now steward-gateway steward steward-executor"
else
	echo "install-node: activate after provisioning trust material (activation runs full preflight):"
	echo "  $release_dir/integration/scripts/activate-node-release.sh $expected_version --restart"
fi
