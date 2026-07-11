#!/usr/bin/env bash
# Remove generic-archive Steward integration without deleting state by default.
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: uninstall-node.sh [--purge-config] [--purge-data]

Stops and removes Steward's generic-archive service integration. Versioned
binaries, configuration, credentials, audit data, and fence state are retained
unless their corresponding explicit purge option is supplied.

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
if [[ ${EUID} -ne 0 ]]; then
	echo "uninstall-node: run as root" >&2
	exit 2
fi

systemctl disable --now steward.service steward-executor.service >/dev/null 2>&1 || true
for binary in steward steward-executor; do
	path="/usr/local/bin/$binary"
	target=$(readlink "$path" 2>/dev/null || true)
	case "$target" in
		/opt/steward/current/* | /opt/steward/releases/*) rm -f "$path" ;;
	esac
done
rm -f /usr/local/lib/systemd/system/steward.service \
	/usr/local/lib/systemd/system/steward-executor.service
rm -rf /usr/local/libexec/steward
systemctl daemon-reload >/dev/null 2>&1 || true

if [[ $purge_config == true ]]; then rm -rf /etc/steward; fi
if [[ $purge_data == true ]]; then
	rm -rf /opt/steward /var/lib/steward /var/lib/steward-executor /var/log/steward
fi
echo "uninstall-node: Steward integration removed"
if [[ $purge_config == false || $purge_data == false ]]; then
	echo "uninstall-node: retained configuration and/or durable state (see --help for purge options)"
fi
