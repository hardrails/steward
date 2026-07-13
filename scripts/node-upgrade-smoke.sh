#!/usr/bin/env bash
# Exercise relay binding and removal/drain behavior with a deterministic fake Docker.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
as_root=()
relay_test=true
if [[ ${EUID} -ne 0 ]]; then
	if ! sudo -n true 2>/dev/null; then
		if [[ ${STEWARD_REQUIRE_ROOT_SMOKE:-0} == 1 ]]; then
			echo "node-upgrade-smoke: passwordless root is required for privilege-boundary and relay binding checks" >&2
			exit 1
		fi
		relay_test=false
	else
		as_root=(sudo -n)
	fi
fi
cleanup() {
	if (( ${#as_root[@]} > 0 )); then "${as_root[@]}" rm -rf -- "$work"; else rm -rf -- "$work"; fi
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$work/bin" "$work/releases/v0.0.0-test" "$work/etc"

exercise_connector_keygen_boundary() {
	local target_user target_group target_uid helper
	if [[ ${EUID} -eq 0 ]]; then
		target_user=nobody
	else
		target_user=$(id -un)
	fi
	target_group=$(id -gn "$target_user")
	target_uid=$(id -u "$target_user")
	if (( target_uid == 0 )); then
		echo "node-upgrade-smoke: connector key generation test identity is root" >&2
		return 1
	fi

	mkdir -p "$work/key-release"
	cat >"$work/key-release/stewardctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
	keygen)
		shift
		private= public=
		while (( $# > 0 )); do
			case "$1" in
				-private-out) private=${2:-}; shift 2 ;;
				-public-out) public=${2:-}; shift 2 ;;
				*) exit 2 ;;
			esac
		done
		uid=$(id -u)
		if (( uid == 0 )); then
			echo "fake stewardctl: keygen executed as root" >&2
			exit 90
		fi
		[[ -n $private && -n $public ]]
		printf 'private:%s\n' "$uid" >"$private"
		printf 'public:%s\n' "$uid" >"$public"
		chmod 0600 "$private"
		chmod 0644 "$public"
		;;
	key)
		[[ ${2:-} == match ]] || exit 2
		shift 2
		private= public=
		while (( $# > 0 )); do
			case "$1" in
				-private-key) private=${2:-}; shift 2 ;;
				-public-key) public=${2:-}; shift 2 ;;
				*) exit 2 ;;
			esac
		done
		[[ -n $private && -n $public ]]
		private_uid=$(sed -n 's/^private://p' "$private")
		public_uid=$(sed -n 's/^public://p' "$public")
		[[ -n $private_uid && $private_uid == "$public_uid" && $(id -u) == "$private_uid" ]]
		;;
	*) exit 2 ;;
esac
EOF
	chmod 0755 "$work/key-release/stewardctl"

	helper="$work/exercise-connector-keygen.sh"
	{
		printf '#!/usr/bin/env bash\nset -euo pipefail\n'
		awk '
			/^generate_connector_receipt_keypair\(\) \($/ { copying=1 }
			copying { print }
			copying && /^\)$/ { exit }
		' "$root/scripts/install-node.sh"
		cat <<'EOF'
generate_connector_receipt_keypair "$SMOKE_RELEASE_DIR" "$SMOKE_GATEWAY_USER" \
	"$SMOKE_GATEWAY_GROUP" "$SMOKE_CONFIG_ROOT"
EOF
	} >"$helper"
	chmod 0755 "$helper"
	if ! grep -q '^generate_connector_receipt_keypair() ($' "$helper"; then
		echo "node-upgrade-smoke: could not extract connector key generation boundary" >&2
		return 1
	fi

	"${as_root[@]}" chmod 0755 "$work"
	"${as_root[@]}" chown -R root:root "$work/key-release" "$helper"
	"${as_root[@]}" install -d -o root -g root -m 0755 "$work/key-config"
	"${as_root[@]}" env \
		"SMOKE_RELEASE_DIR=$work/key-release" \
		"SMOKE_GATEWAY_USER=$target_user" \
		"SMOKE_GATEWAY_GROUP=$target_group" \
		"SMOKE_CONFIG_ROOT=$work/key-config" \
		bash "$helper"

	[[ $(cat "$work/key-config/connector-receipts.public") == "public:$target_uid" ]]
	[[ $("${as_root[@]}" stat -c '%u:%g:%a' "$work/key-config/connector-receipts.private.pem") == "$target_uid:$(id -g "$target_user"):600" ]]
	[[ $("${as_root[@]}" stat -c '%u:%g:%a' "$work/key-config/connector-receipts.public") == "0:0:644" ]]
	if (( $("${as_root[@]}" find "$work/key-config" -maxdepth 1 -name '.connector-keygen.*' -print -quit | wc -l) != 0 )); then
		echo "node-upgrade-smoke: connector key generation left its work directory behind" >&2
		return 1
	fi
}

if [[ $relay_test == true ]]; then
	exercise_connector_keygen_boundary
else
	echo "node-upgrade-smoke: connector key generation boundary check skipped (passwordless root unavailable)"
fi

cat >"$work/releases/v0.0.0-test/steward-relay" <<'EOF'
#!/usr/bin/env bash
if [[ ${1:-} == -version ]]; then
	echo 'steward-relay v0.0.0-test'
	exit 0
fi
exit 2
EOF
chmod 0755 "$work/releases/v0.0.0-test/steward-relay"
binary_sha=$(sha256sum "$work/releases/v0.0.0-test/steward-relay" | awk '{print $1}')
image_id="sha256:$(printf 'a%.0s' {1..64})"

cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"
case "${1:-}" in
	info) exit 0 ;;
	version) echo '29.0.0' ;;
	build) [[ -z ${FAKE_BUILD_MARKER:-} ]] || : >"$FAKE_BUILD_MARKER"; exit 0 ;;
	image)
		[[ ${2:-} == inspect && ${3:-} == --format ]] || exit 2
		if [[ ${FAKE_MISSING_UNTIL_BUILD:-0} == 1 && ! -e ${FAKE_BUILD_MARKER:-/nonexistent} ]]; then exit 1; fi
		case "${4:-}" in
			'{{.Id}}') echo "$FAKE_IMAGE_ID" ;;
			'{{index .Config.Labels "io.hardrails.steward.release.version"}}') echo 'v0.0.0-test' ;;
			'{{index .Config.Labels "io.hardrails.steward.relay.binary.sha256"}}') echo "$FAKE_BINARY_SHA" ;;
			*) exit 2 ;;
		esac
		;;
	ps)
		case "$*" in
			*io.hardrails.executor.managed=true*) [[ -z ${FAKE_AGENT_IDS:-} ]] || echo "$FAKE_AGENT_IDS" ;;
			*io.hardrails.relay.managed=true*) [[ -z ${FAKE_RELAY_IDS:-} ]] || echo "$FAKE_RELAY_IDS" ;;
		esac
		;;
	network) [[ -z ${FAKE_NETWORK_IDS:-} ]] || echo "$FAKE_NETWORK_IDS" ;;
	volume) [[ -z ${FAKE_VOLUME_IDS:-} ]] || echo "$FAKE_VOLUME_IDS" ;;
	*) exit 2 ;;
esac
EOF
chmod 0755 "$work/bin/docker"
: >"$work/docker.log"

common_env=(
	"PATH=$work/bin:$PATH"
	"FAKE_DOCKER_LOG=$work/docker.log"
	"FAKE_IMAGE_ID=$image_id"
	"FAKE_BINARY_SHA=$binary_sha"
	"STEWARD_RELAY_GID=4242"
	"STEWARD_RELAY_BINDING_ROOT=$work/relay-images"
	"STEWARD_RELAY_CURRENT_ENV=$work/etc/executor-gateway.env"
)
if [[ $relay_test == true ]]; then
	"${as_root[@]}" env "${common_env[@]}" "$root/scripts/build-relay-image.sh" \
		--release-dir "$work/releases/v0.0.0-test" >/dev/null
	binding="$work/relay-images/v0.0.0-test.env"
	# The production binding directory is root-only and the binding itself is
	# mode 0600. Inspect it through the same privilege boundary used to create it
	# so this smoke also works for passwordless-sudo CI runners.
	"${as_root[@]}" test -f "$binding"
	"${as_root[@]}" test ! -L "$binding"
	[[ $("${as_root[@]}" stat -c '%u:%g:%a' "$binding") == 0:0:600 ]]
	"${as_root[@]}" grep -Fxq '# steward.relay-binding.v1' "$binding"
	"${as_root[@]}" grep -Fxq '# release_version=v0.0.0-test' "$binding"
	"${as_root[@]}" grep -Fxq "# relay_binary_sha256=$binary_sha" "$binding"
	"${as_root[@]}" grep -Fxq "# relay_image_id=$image_id" "$binding"
	"${as_root[@]}" grep -Fq -- "-relay-image=$image_id" "$binding"
	[[ ! -e $work/etc/executor-gateway.env && ! -L $work/etc/executor-gateway.env ]]
	grep -Fq 'build --network=none --pull=false --provenance=false' "$work/docker.log"

	"${as_root[@]}" env "${common_env[@]}" "$root/scripts/build-relay-image.sh" \
		--release-dir "$work/releases/v0.0.0-test" --configure >/dev/null
	[[ -L $work/etc/executor-gateway.env ]]
	[[ $(readlink "$work/etc/executor-gateway.env") == "$binding" ]]
	[[ $(grep -c '^build ' "$work/docker.log") -eq 1 ]]

	# Model an operator-deleted image. A deterministic rebuild that returns the
	# retained image ID restores availability without replacing the binding.
	rm -f "$work/build.marker"
	"${as_root[@]}" env "${common_env[@]}" FAKE_MISSING_UNTIL_BUILD=1 \
		"FAKE_BUILD_MARKER=$work/build.marker" "$root/scripts/build-relay-image.sh" \
		--release-dir "$work/releases/v0.0.0-test" --replace-missing >/dev/null
	[[ $(grep -c '^build ' "$work/docker.log") -eq 2 ]]
	"${as_root[@]}" grep -Fxq "# relay_image_id=$image_id" "$binding"
else
	echo "node-upgrade-smoke: relay binding checks skipped (passwordless root unavailable)"
fi

guard_env=("PATH=$work/bin:$PATH" "FAKE_DOCKER_LOG=$work/docker.log")
env "${guard_env[@]}" "$root/scripts/node-removal-guard.sh"
if env "${guard_env[@]}" FAKE_AGENT_IDS=stopped-agent "$root/scripts/node-removal-guard.sh" 2>/dev/null; then
	echo "node-upgrade-smoke: stopped managed agent did not block removal" >&2
	exit 1
fi
if env "${guard_env[@]}" FAKE_NETWORK_IDS=capability-network "$root/scripts/node-removal-guard.sh" 2>/dev/null; then
	echo "node-upgrade-smoke: capability network did not block removal" >&2
	exit 1
fi
# Retained state is permitted for ordinary removal, but not an explicit purge.
env "${guard_env[@]}" FAKE_VOLUME_IDS=retained-state "$root/scripts/node-removal-guard.sh"
if env "${guard_env[@]}" FAKE_VOLUME_IDS=retained-state "$root/scripts/node-removal-guard.sh" --purge-data 2>/dev/null; then
	echo "node-upgrade-smoke: retained state volume did not block purge" >&2
	exit 1
fi
if "$root/scripts/uninstall-node.sh" --purge-config 2>/dev/null; then
	echo "node-upgrade-smoke: uninstall accepted a configuration-only identity purge" >&2
	exit 1
fi
if "$root/scripts/uninstall-node.sh" --purge-data 2>/dev/null; then
	echo "node-upgrade-smoke: uninstall accepted a data-only identity purge" >&2
	exit 1
fi

echo "node-upgrade-smoke: key-generation boundary, relay binding, and drain guards passed"
