#!/usr/bin/env bash
# Remove generic-archive Steward integration without deleting state by default.
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: uninstall-node.sh [--purge-config --purge-data]

Stops and removes Steward's generic-archive service integration. Versioned
binaries, configuration, credentials, audit data, and fence state are retained
by default. Node identity can be retired only by supplying both purge options;
Steward refuses a partial purge that would separate receipt keys from evidence
or configuration from anti-replay state.

For a DEB or RPM installation, use the operating system package manager instead.
EOF
}

purge_config=false
purge_data=false
while [[ $# -gt 0 ]]; do
	case "$1" in
		--purge-config) purge_config=true; shift ;;
		--purge-data) purge_data=true; shift ;;
		-h | --help) usage; exit 0 ;;
		*) echo "uninstall-node: unknown option $1" >&2; usage >&2; exit 2 ;;
	esac
done
if [[ $purge_config != "$purge_data" ]]; then
	echo "uninstall-node: --purge-config and --purge-data must be supplied together" >&2
	echo "  A partial purge would leave an incomplete node identity that cannot be reopened safely." >&2
	exit 2
fi
if [[ ${EUID} -ne 0 ]]; then
	echo "uninstall-node: run as root" >&2
	exit 2
fi

guard_args=()
if [[ $purge_data == true ]]; then guard_args+=(--purge-data); fi
"$(dirname "$0")/node-removal-guard.sh" "${guard_args[@]}"

systemctl stop steward-gateway.service >/dev/null 2>&1 || true
systemctl stop steward.service >/dev/null 2>&1 || true
systemctl stop steward-executor.service >/dev/null 2>&1 || true
systemctl disable steward-gateway.service steward.service steward-executor.service >/dev/null 2>&1 || true
for binary in steward steward-control stewardctl steward-mcp steward-executor steward-gateway steward-relay; do
	path="/usr/local/bin/$binary"
	target=$(readlink "$path" 2>/dev/null || true)
	case "$target" in
		/opt/steward/current/* | /opt/steward/releases/*) rm -f "$path" ;;
	esac
done
rm -f /usr/local/lib/systemd/system/steward.service \
	/usr/local/lib/systemd/system/steward-executor.service \
	/usr/local/lib/systemd/system/steward-gateway.service
rm -rf /usr/local/libexec/steward
systemctl daemon-reload >/dev/null 2>&1 || true

if [[ $purge_config == true ]]; then rm -rf /etc/steward; fi
if [[ $purge_data == true ]]; then
	rm -rf /opt/steward /var/lib/steward /var/lib/steward-executor /var/lib/steward-gateway \
		/var/lib/steward-node /var/log/steward
fi
echo "uninstall-node: Steward integration removed"
if [[ $purge_config == false ]]; then
	echo "uninstall-node: retained configuration and/or durable state (see --help for purge options)"
fi
