#!/usr/bin/env bash
# Exercise node-installer input boundaries in a disposable Linux root namespace.
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ ${1:-} != --inside ]]; then
	command -v docker >/dev/null 2>&1 || {
		echo "node-installer-security-test: Docker is required" >&2
		exit 2
	}
	exec docker run --rm -v "$root:/repo:ro" ubuntu:24.04 \
		/bin/bash -p /repo/scripts/node-installer-security-test.sh --inside
fi

[[ $(uname -s) == Linux && ${EUID} -eq 0 ]]
export DEBIAN_FRONTEND=noninteractive
if ! command -v curl >/dev/null 2>&1 || ! command -v useradd >/dev/null 2>&1; then
	apt-get update -qq
	apt-get install --no-install-recommends -y -qq ca-certificates curl passwd >/dev/null
fi
for command in awk curl dd env flock getent groupadd gzip id readlink sha256sum stat tar timeout useradd usermod; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "node-installer-security-test: container is missing $command" >&2
		exit 2
	}
done

# The disposable feasibility harness is root-only and has a fixed managed root.
# Hostile legacy overrides must not chmod or populate an arbitrary directory,
# and locking the validated directory must not create/follow a lock pathname.
tmp_mode_before=$(stat -c %a /tmp)
STEWARD_FEASIBILITY_ROOT=/tmp STEWARD_FEASIBILITY_MAX_HANDLES=999 \
	STEWARD_FEASIBILITY_ALLOW_UNPRIVILEGED=1 \
	/bin/bash -p /repo/scripts/preprovision-feasibility-handle.sh \
	state tenant-a lineage-a handle-a 1
[[ $(stat -c %a /tmp) == "$tmp_mode_before" ]]
[[ ! -e /tmp/registry && ! -e /tmp/payload && ! -e /tmp/registry.lock ]]
feasibility_root=/var/lib/steward/feasibility-handles
[[ $(stat -c '%u:%g:%a' "$feasibility_root") == 0:0:700 ]]
[[ $(stat -c '%u:%g:%a' "$feasibility_root/registry") == 0:0:700 ]]
[[ ! -e $feasibility_root/registry.lock && ! -L $feasibility_root/registry.lock ]]
/bin/bash -p /repo/scripts/preprovision-feasibility-handle.sh \
	state tenant-a lineage-a handle-a 1

fixture=$(mktemp -d /run/steward-node-installer-security.XXXXXX)
cleanup() {
	[[ -z ${growth_pid:-} ]] || kill "$growth_pid" 2>/dev/null || true
	[[ -z ${flip_pid:-} ]] || kill "$flip_pid" 2>/dev/null || true
	rm -rf -- /run/steward-host-role
	rm -rf -- "$fixture"
}
trap cleanup EXIT HUP INT TERM
chmod 0700 "$fixture"

# Load the exact primitive definitions without entering the installer's option
# parser. The archive validator lives later in the file, so append that one
# complete top-level function explicitly.
awk '/^while \[\[ \$# -gt 0 \]\]; do$/ { exit } { print }' \
	/repo/scripts/install-steward.sh >"$fixture/primitives.sh"
# shellcheck disable=SC2129 # These extracts intentionally build one sourced helper.
sed -n '/^extract_verified_node_archive() {$/,/^}$/p' \
	/repo/scripts/install-steward.sh >>"$fixture/primitives.sh"
for function_name in bounded_docker_info docker_daemon_reachable has_runsc; do
	sed -n "/^${function_name}() {$/,/^}$/p" /repo/scripts/install-steward.sh \
		>>"$fixture/primitives.sh"
done
sed -n '/^validate_release_source_tree() {$/,/^}$/p' \
	/repo/scripts/install-node.sh >>"$fixture/primitives.sh"
sed -n '/^# BEGIN HOST_ROLE_LOCK_BOUNDARY$/,/^# END HOST_ROLE_LOCK_BOUNDARY$/p' \
	/repo/scripts/install-node.sh >>"$fixture/primitives.sh"
for function_name in trusted_root_directory_chain ensure_managed_directory getent_one \
	validate_unique_nss_id validate_managed_group validate_group_members \
	validate_primary_group_users validate_service_identity validate_install_marker \
	create_install_marker remove_pending_regular_file validate_gateway_service_token \
	ensure_gateway_service_token managed_symlink_pending_path \
	validate_managed_symlink_slot ensure_managed_symlink validate_managed_config_file \
	install_default_config_atomic read_machine_id install_gateway_config_atomic; do
	sed -n "/^${function_name}() {$/,/^}$/p" /repo/scripts/install-node.sh \
		>>"$fixture/primitives.sh"
done
TMPDIR=/tmp/steward-hostile-parent
CURL_CA_BUNDLE=/tmp/attacker-ca.pem
SSL_CERT_FILE=/tmp/attacker-cert.pem
SSL_CERT_DIR=/tmp/attacker-cert-dir
# shellcheck source=/dev/null
source "$fixture/primitives.sh"
[[ -z ${TMPDIR+x} ]]
[[ -z ${CURL_CA_BUNDLE+x} && -z ${SSL_CERT_FILE+x} && -z ${SSL_CERT_DIR+x} ]]
work="$fixture/work"
install -d -o root -g root -m 0700 "$work" "$fixture/trusted"
node_lock_directory="$fixture/nss"
install -d -o root -g root -m 0700 "$node_lock_directory"

# Docker is a privileged but independent local service and can wedge or emit a
# hostile response. Both installer probes have a deadline and file-size limit
# before any response is parsed. They deliberately do not apply ulimit -v: the
# Go runtime reserves a large virtual address range even when resident memory is
# small, so that limit crashes current Docker clients before they contact Docker.
install -d -m 0700 "$fixture/fake-docker"
cat >"$fixture/fake-docker/docker" <<'EOF'
#!/bin/bash -p
set -euo pipefail
case "${FAKE_DOCKER_MODE:?}" in
	ready)
		if [[ $(ulimit -v) != unlimited ]]; then
			echo 'docker probe inherited a virtual-memory limit' >&2
			exit 3
		fi
		if [[ $* == *Runtimes* ]]; then
			printf '%s\n' '{"io.containerd.runc.v2":{},"runsc":{}}'
		else
			printf '%s\n' '27.5.1'
		fi
		;;
	sleep) exec sleep 60 ;;
	flood) exec yes X ;;
	*) exit 2 ;;
esac
EOF
chmod 0755 "$fixture/fake-docker/docker"
real_path=$PATH
PATH="$fixture/fake-docker:$PATH"
FAKE_DOCKER_MODE=ready docker_daemon_reachable
FAKE_DOCKER_MODE=ready has_runsc
# shellcheck disable=SC2016 # Literal bash -c fixture; positional parameters expand in the child shell.
if timeout 25 env FAKE_DOCKER_MODE=sleep /bin/bash -p -c \
	'source "$1"; work=$2; PATH=$3; docker_daemon_reachable' _ \
	"$fixture/primitives.sh" "$work" "$PATH"; then
	echo "node-installer-security-test: sleeping Docker probe succeeded" >&2
	exit 1
fi
# shellcheck disable=SC2016 # Literal bash -c fixture; positional parameters expand in the child shell.
if timeout 25 env FAKE_DOCKER_MODE=flood /bin/bash -p -c \
	'source "$1"; work=$2; PATH=$3; has_runsc' _ \
	"$fixture/primitives.sh" "$work" "$PATH"; then
	echo "node-installer-security-test: flooding Docker probe succeeded" >&2
	exit 1
fi
PATH=$real_path
[[ ! -e $work/docker-info.stderr && ! -e $work/docker-runtimes.stdout &&
	! -e $work/docker-version.stdout ]]

[[ ! -e /run/steward-host-role && ! -L /run/steward-host-role ]]
ln -s "$fixture/trusted" /run/steward-host-role
if prepare_host_role_lock; then
	echo "node-installer-security-test: shared host-role lock accepted a symlinked directory" >&2
	exit 1
fi
rm -f /run/steward-host-role
acquire_host_role_lock
[[ $(stat -c '%u:%g:%a' /run/steward-host-role) == 0:0:700 ]]
[[ $(stat -c '%u:%g:%a:%h' /run/steward-host-role/role.lock) == 0:0:600:1 ]]

# Managed destinations must never follow a preseeded symlink or accept the
# wrong ownership/mode. Exercise root-owned and service-owned directory classes.
install -d -o root -g root -m 0700 "$fixture/trusted/managed-parent"
ensure_managed_directory "$fixture/trusted/managed-parent/root-owned" root root 0700 true
target_user=nobody
target_group=$(id -gn "$target_user")
ensure_managed_directory "$fixture/trusted/managed-parent/service-owned" \
	"$target_user" "$target_group" 0700 true
printf '%s\n' sentinel >"$fixture/trusted/sentinel"
sentinel_digest=$(sha256sum "$fixture/trusted/sentinel" | awk '{print $1}')
ln -s "$fixture/trusted/sentinel" "$fixture/trusted/managed-parent/preseeded-link"
if ensure_managed_directory "$fixture/trusted/managed-parent/preseeded-link" root root 0700 true; then
	echo "node-installer-security-test: managed directory followed a preseeded symlink" >&2
	exit 1
fi
[[ $(sha256sum "$fixture/trusted/sentinel" | awk '{print $1}') == "$sentinel_digest" ]]
install -d -o root -g root -m 0755 "$fixture/trusted/managed-parent/wrong-mode"
if ensure_managed_directory "$fixture/trusted/managed-parent/wrong-mode" root root 0700 true; then
	echo "node-installer-security-test: managed directory accepted the wrong mode" >&2
	exit 1
fi
ln -s "$fixture/trusted/managed-parent" "$fixture/trusted/linked-parent"
if ensure_managed_directory "$fixture/trusted/linked-parent/new-child" root root 0700 true; then
	echo "node-installer-security-test: managed directory accepted a symlinked ancestor" >&2
	exit 1
fi

# Existing service accounts are an input boundary. The validator requires a
# locked password, fixed home/shell, unique IDs, and the exact group set.
groupadd --system stwb-primary
groupadd --system stwb-extra
useradd --system --no-create-home --gid stwb-primary --home-dir /var/lib/stwb-good \
	--shell /usr/sbin/nologin stwb-good
validate_service_identity stwb-good stwb-primary /var/lib/stwb-good stwb-primary
usermod --append --groups stwb-extra stwb-good
if validate_service_identity stwb-good stwb-primary /var/lib/stwb-good stwb-primary; then
	echo "node-installer-security-test: service identity accepted an extra group" >&2
	exit 1
fi
useradd --system --no-create-home --gid stwb-primary --home-dir /tmp/stwb-bad-home \
	--shell /usr/sbin/nologin stwb-home
if validate_service_identity stwb-home stwb-primary /var/lib/stwb-home stwb-primary; then
	echo "node-installer-security-test: service identity accepted a hostile home" >&2
	exit 1
fi
printf '%s\n' 'stwb-good:unsafe-test-password' | chpasswd
if validate_service_identity stwb-good stwb-primary /var/lib/stwb-good stwb-primary stwb-extra; then
	echo "node-installer-security-test: service identity accepted an unlocked password" >&2
	exit 1
fi
passwd -l stwb-good >/dev/null

# Secret publication is atomic and journaled. Simulate interruption before and
# after rename, then prove ambiguous unjournaled state is rejected.
install -d -o root -g root -m 0755 "$fixture/token-config"
install -d -o root -g root -m 0700 "$fixture/token-state"
ensure_gateway_service_token "$fixture/token-config" "$fixture/token-state" \
	"$target_user" "$target_group"
target_uid=$(id -u "$target_user")
target_gid=$(id -g "$target_user")
validate_gateway_service_token "$fixture/token-config/gateway-service-token" \
	"$target_uid" "$target_gid"
rm -f "$fixture/token-config/gateway-service-token"
install -o root -g root -m 0600 /dev/null \
	"$fixture/token-state/install.gateway-token.pending"
printf partial >"$fixture/token-config/.gateway-service-token.pending"
chmod 0600 "$fixture/token-config/.gateway-service-token.pending"
ensure_gateway_service_token "$fixture/token-config" "$fixture/token-state" \
	"$target_user" "$target_group"
validate_gateway_service_token "$fixture/token-config/gateway-service-token" \
	"$target_uid" "$target_gid"
install -o root -g root -m 0600 /dev/null \
	"$fixture/token-state/install.gateway-token.pending"
ensure_gateway_service_token "$fixture/token-config" "$fixture/token-state" \
	"$target_user" "$target_group"
[[ ! -e $fixture/token-state/install.gateway-token.pending ]]
rm -f "$fixture/token-config/gateway-service-token"
ln -s "$fixture/trusted/sentinel" "$fixture/token-config/.gateway-service-token.pending"
if ensure_gateway_service_token "$fixture/token-config" "$fixture/token-state" \
	"$target_user" "$target_group"; then
	echo "node-installer-security-test: unjournaled pending token symlink was accepted" >&2
	exit 1
fi
[[ $(sha256sum "$fixture/trusted/sentinel" | awk '{print $1}') == "$sentinel_digest" ]]

# Stable entry points recover from an interrupted publication and refuse an
# unrelated destination. Use binary, helper, and unit-shaped slots.
for slot in bin/steward libexec/node-doctor systemd/steward.service; do
	install -d -o root -g root -m 0700 "$fixture/links/$(dirname "$slot")"
	path="$fixture/links/$slot"
	target="/opt/steward/current/$slot"
	pending=$(managed_symlink_pending_path "$path")
	ln -s "$target" "$pending"
	ensure_managed_symlink "$path" "$target"
	[[ -L $path && $(readlink "$path") == "$target" && ! -e $pending && ! -L $pending ]]
	rm -f "$path"
	ensure_managed_symlink "$path" "$target"
done
rm -f "$fixture/links/bin/steward"
printf unmanaged >"$fixture/links/bin/steward"
if ensure_managed_symlink "$fixture/links/bin/steward" /opt/steward/current/bin/steward; then
	echo "node-installer-security-test: stable entry point replaced an unmanaged file" >&2
	exit 1
fi

# Default and generated configuration use the same atomic retry shape as
# secrets. Existing symlinks and empty partial finals are never adopted.
install -d -o root -g root -m 0755 "$fixture/config-root"
printf 'DEFAULT=value\n' >"$fixture/trusted/default.env"
install_default_config_atomic "$fixture/trusted/default.env" \
	"$fixture/config-root/default.env" root root 0600
cmp "$fixture/trusted/default.env" "$fixture/config-root/default.env"
rm -f "$fixture/config-root/default.env"
printf partial >"$fixture/config-root/.default.env.steward-install"
chmod 0600 "$fixture/config-root/.default.env.steward-install"
install_default_config_atomic "$fixture/trusted/default.env" \
	"$fixture/config-root/default.env" root root 0600
cmp "$fixture/trusted/default.env" "$fixture/config-root/default.env"
rm -f "$fixture/config-root/default.env"
ln -s "$fixture/trusted/sentinel" "$fixture/config-root/default.env"
if install_default_config_atomic "$fixture/trusted/default.env" \
	"$fixture/config-root/default.env" root root 0600; then
	echo "node-installer-security-test: default config followed a destination symlink" >&2
	exit 1
fi

# A wrapper-supplied Steward node identity must become the Gateway receipt
# identity. Otherwise the installed Gateway can never export task trust for the
# enrolled node without abandoning its receipt chain.
getent group steward-gateway >/dev/null || groupadd --system steward-gateway
printf '%s\n' '{"connector_receipt_node_id":"@CONNECTOR_RECEIPT_NODE_ID@"}' \
	>"$fixture/trusted/gateway.json.in"
install_gateway_config_atomic "$fixture/trusted/gateway.json.in" \
	"$fixture/config-root/gateway.json" 1001 1002 node-a
grep -Fq '"connector_receipt_node_id":"node-a/gateway"' \
	"$fixture/config-root/gateway.json"
[[ $(sha256sum "$fixture/trusted/sentinel" | awk '{print $1}') == "$sentinel_digest" ]]
rm -f "$fixture/config-root/default.env"
install -o root -g root -m 0600 /dev/null "$fixture/config-root/default.env"
if install_default_config_atomic "$fixture/trusted/default.env" \
	"$fixture/config-root/default.env" root root 0600; then
	echo "node-installer-security-test: default config adopted an empty partial final" >&2
	exit 1
fi

rm -f /etc/machine-id
printf '0123456789abcdef0123456789abcdef\n' >/etc/machine-id
chown root:root /etc/machine-id
chmod 0444 /etc/machine-id
[[ $(read_machine_id) == 0123456789abcdef0123456789abcdef ]]
rm -f /etc/machine-id
mkfifo /etc/machine-id
if read_machine_id; then
	echo "node-installer-security-test: machine ID reader accepted a FIFO" >&2
	exit 1
fi
rm -f /etc/machine-id

install -d -m 0700 "$fixture/trusted/release-tree"
printf '%s\n' release >"$fixture/trusted/release-tree/file"
chmod 0600 "$fixture/trusted/release-tree/file"
validate_release_source_tree "$fixture/trusted/release-tree"
ln "$fixture/trusted/release-tree/file" "$fixture/trusted/release-tree/hardlink"
if validate_release_source_tree "$fixture/trusted/release-tree"; then
	echo "node-installer-security-test: hard-linked release source passed validation" >&2
	exit 1
fi
rm "$fixture/trusted/release-tree/hardlink"
rm -rf /tmp/steward-unsafe-release
install -d -m 0777 /tmp/steward-unsafe-release
printf '%s\n' release >/tmp/steward-unsafe-release/file
chmod 0600 /tmp/steward-unsafe-release/file
if validate_release_source_tree /tmp/steward-unsafe-release; then
	echo "node-installer-security-test: release source under an unsafe parent passed validation" >&2
	exit 1
fi

printf '%s\n' stable >"$fixture/trusted/stable"
chmod 0600 "$fixture/trusted/stable"
bounded_snapshot "$fixture/trusted/stable" "$work/stable" 1024 5
cmp "$fixture/trusted/stable" "$work/stable"

mkfifo "$fixture/trusted/fifo"
# shellcheck disable=SC2016 # Positional parameters are expanded by the child Bash.
if timeout 2 /bin/bash -p -c \
	'source "$1"; bounded_snapshot "$2" "$3" 1024 1' _ \
	"$fixture/primitives.sh" "$fixture/trusted/fifo" "$work/fifo"; then
	echo "node-installer-security-test: FIFO snapshot succeeded" >&2
	exit 1
fi
ln -s stable "$fixture/trusted/link"
if bounded_snapshot "$fixture/trusted/link" "$work/link" 1024 1; then
	echo "node-installer-security-test: symlink snapshot succeeded" >&2
	exit 1
fi
install -d -m 0777 /tmp/steward-hostile-parent
printf '%s\n' unsafe >/tmp/steward-hostile-parent/input
chmod 0600 /tmp/steward-hostile-parent/input
if bounded_snapshot /tmp/steward-hostile-parent/input "$work/unsafe-parent" 1024 1; then
	echo "node-installer-security-test: untrusted parent snapshot succeeded" >&2
	exit 1
fi
truncate -s 2048 "$fixture/trusted/oversized"
chmod 0600 "$fixture/trusted/oversized"
if bounded_snapshot "$fixture/trusted/oversized" "$work/oversized" 1024 1; then
	echo "node-installer-security-test: oversized snapshot succeeded" >&2
	exit 1
fi

# A root-controlled race models removable media changing beneath an install.
# The snapshot must either reject the race or contain one complete version; a
# later digest check must never accept the alternate bytes.
dd if=/dev/zero bs=1M count=64 status=none | tr '\0' A >"$fixture/trusted/good"
dd if=/dev/zero bs=1M count=64 status=none | tr '\0' B >"$fixture/trusted/bad"
chmod 0600 "$fixture/trusted/good" "$fixture/trusted/bad"
good_digest=$(sha256sum "$fixture/trusted/good" | awk '{print $1}')
bad_digest=$(sha256sum "$fixture/trusted/bad" | awk '{print $1}')

install -d -m 0700 "$fixture/fake-dd"
cat >"$fixture/fake-dd/dd" <<'EOF'
#!/bin/bash -p
set -euo pipefail
: >"${STEWARD_DD_READY:?}"
while [[ ! -e ${STEWARD_DD_RELEASE:?} ]]; do sleep 0.01; done
exec /usr/bin/dd "$@"
EOF
chmod 0755 "$fixture/fake-dd/dd"
printf '%s' seed >"$fixture/trusted/growing"
chmod 0600 "$fixture/trusted/growing"
(
	while [[ ! -e $fixture/dd-ready ]]; do sleep 0.01; done
	printf '%s' changed >>"$fixture/trusted/growing"
	: >"$fixture/dd-release"
) &
growth_pid=$!
real_path=$PATH
PATH="$fixture/fake-dd:$PATH"
if STEWARD_DD_READY="$fixture/dd-ready" STEWARD_DD_RELEASE="$fixture/dd-release" \
	bounded_snapshot "$fixture/trusted/growing" "$work/growing" 1024 5; then
	echo "node-installer-security-test: changing source snapshot succeeded" >&2
	exit 1
fi
PATH=$real_path
wait "$growth_pid"
growth_pid=

cp "$fixture/trusted/good" "$fixture/trusted/racing"
(
	while :; do
		cp "$fixture/trusted/bad" "$fixture/trusted/racing.next"
		chmod 0600 "$fixture/trusted/racing.next"
		mv -f "$fixture/trusted/racing.next" "$fixture/trusted/racing"
		cp "$fixture/trusted/good" "$fixture/trusted/racing.next"
		chmod 0600 "$fixture/trusted/racing.next"
		mv -f "$fixture/trusted/racing.next" "$fixture/trusted/racing"
	done
) &
flip_pid=$!
snapshot_status=0
bounded_snapshot "$fixture/trusted/racing" "$work/racing" 67108864 15 || snapshot_status=$?
kill "$flip_pid" 2>/dev/null || true
wait "$flip_pid" 2>/dev/null || true
flip_pid=
if (( snapshot_status == 0 )); then
	racing_digest=$(sha256sum "$work/racing" | awk '{print $1}')
	if [[ $racing_digest != "$good_digest" && $racing_digest != "$bad_digest" ]]; then
		echo "node-installer-security-test: rename race produced a mixed snapshot" >&2
		exit 1
	fi
fi

install -d -m 0700 "$fixture/archive-stage/scripts" "$fixture/extract"
printf '%s\n' '{}' >"$fixture/archive-stage/release.json"
printf '%s\n' '#!/bin/bash -p' 'exit 2' >"$fixture/archive-stage/scripts/install-node.sh"
chmod 0755 "$fixture/archive-stage/scripts/install-node.sh"
tar -C "$fixture/archive-stage" -czf "$fixture/trusted/node.tar.gz" release.json scripts
chmod 0600 "$fixture/trusted/node.tar.gz"
cat >"$fixture/tar-payload" <<EOF
#!/bin/sh
touch "$fixture/tar-options-executed"
EOF
chmod 0755 "$fixture/tar-payload"
TAR_OPTIONS="--checkpoint=1 --checkpoint-action=exec=$fixture/tar-payload" GZIP=-v \
	extract_verified_node_archive "$fixture/trusted/node.tar.gz" "$fixture/extract"
[[ ! -e $fixture/tar-options-executed ]]

shopt -s nullglob
release_archives=(/repo/dist/steward_v*_linux_*.tar.gz)
shopt -u nullglob
if (( ${#release_archives[@]} == 1 )); then
	install -d -m 0700 "$fixture/release-extract"
	extract_verified_node_archive "${release_archives[0]}" "$fixture/release-extract"
	[[ -f $fixture/release-extract/release.json && -x $fixture/release-extract/scripts/install-node.sh ]]
fi

cp "$fixture/trusted/node.tar.gz" "$fixture/trusted/truncated.tar.gz"
truncate -s 16 "$fixture/trusted/truncated.tar.gz"
# shellcheck disable=SC2016 # Positional parameters are expanded by the child Bash.
if timeout 5 /bin/bash -p -c \
	'source "$1"; work=$2; extract_verified_node_archive "$3" "$4"' _ \
	"$fixture/primitives.sh" "$work" "$fixture/trusted/truncated.tar.gz" "$fixture/extract"; then
	echo "node-installer-security-test: truncated archive passed validation" >&2
	exit 1
fi

printf '%s\n' release.json scripts/install-node.sh >"$fixture/members"
for _ in {1..5000}; do printf '%s\n' release.json; done >>"$fixture/members"
tar -C "$fixture/archive-stage" -czf "$fixture/trusted/list-bomb.tar.gz" -T "$fixture/members"
# shellcheck disable=SC2016 # Positional parameters are expanded by the child Bash.
if timeout 10 /bin/bash -p -c \
	'source "$1"; work=$2; extract_verified_node_archive "$3" "$4"' _ \
	"$fixture/primitives.sh" "$work" "$fixture/trusted/list-bomb.tar.gz" "$fixture/extract"; then
	echo "node-installer-security-test: archive list bomb passed validation" >&2
	exit 1
fi

printf payload >"$fixture/archive-stage/payload"
long_name=$(printf 'a%.0s' {1..1100})
tar --format=pax --transform="s|^payload$|$long_name|" -C "$fixture/archive-stage" \
	-czf "$fixture/trusted/pax-bomb.tar.gz" payload
# shellcheck disable=SC2016 # Positional parameters are expanded by the child Bash.
if timeout 10 /bin/bash -p -c \
	'source "$1"; work=$2; extract_verified_node_archive "$3" "$4"' _ \
	"$fixture/primitives.sh" "$work" "$fixture/trusted/pax-bomb.tar.gz" "$fixture/extract"; then
	echo "node-installer-security-test: oversized PAX path passed validation" >&2
	exit 1
fi

install -d -m 0700 "$fixture/curl-home"
printf 'trace-ascii = "%s"\n' "$fixture/curl-trace" >"$fixture/curl-home/.curlrc"
CURL_HOME="$fixture/curl-home" curl --connect-timeout 1 https://127.0.0.1:1 \
	>/dev/null 2>&1 || true
[[ -f $fixture/curl-trace ]]
rm -f "$fixture/curl-trace"
CURL_HOME="$fixture/curl-home" download https://127.0.0.1:1 "$work/curl-output" 1048576 || true
[[ ! -e $fixture/curl-trace && ! -e $work/curl-output ]]

install -d -m 0700 "$fixture/fake-bin"
cat >"$fixture/fake-bin/curl" <<'EOF'
#!/bin/bash -p
set -euo pipefail
[[ -z ${CURL_CA_BUNDLE:-} && -z ${SSL_CERT_FILE:-} && -z ${SSL_CERT_DIR:-} ]]
output=
while (( $# > 0 )); do
	case "$1" in --output) output=${2:-}; shift 2 ;; *) shift ;; esac
done
[[ -n $output ]]
exec dd if=/dev/zero of="$output" bs=1048576 count=32 status=none
EOF
chmod 0755 "$fixture/fake-bin/curl"
real_path=$PATH
PATH="$fixture/fake-bin:$PATH"
if download https://unknown-length.invalid "$work/unbounded" 1048576; then
	echo "node-installer-security-test: oversized unknown-length response succeeded" >&2
	exit 1
fi
PATH=$real_path
[[ ! -e $work/unbounded ]]

echo "node-installer-security-test: bounded local, archive, curl, and temp-input checks passed"
