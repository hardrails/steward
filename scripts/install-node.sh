#!/usr/bin/env bash
# Install one versioned Steward node release without enabling or starting it.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
	echo "install-node: run as root" >&2
	exit 2
fi
if [[ $(uname -s) != Linux ]]; then
	echo "install-node: the Steward node appliance supports Linux only" >&2
	exit 2
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
for path in steward stewardctl steward-executor deploy/systemd/steward.service \
	deploy/systemd/steward-executor.service deploy/config/steward.json \
	deploy/config/executor.env scripts/activate-node-release.sh \
	scripts/node-preflight.sh scripts/configure-node.sh scripts/uninstall-node.sh; do
	if [[ ! -f "$root/$path" ]]; then
		echo "install-node: release is missing $path" >&2
		exit 2
	fi
done

getent group docker >/dev/null || {
	echo "install-node: Docker group is missing; install Docker before Steward" >&2
	exit 2
}
if ! id steward >/dev/null 2>&1; then
	useradd --system --home-dir /var/lib/steward --shell /usr/sbin/nologin steward
fi
if ! id steward-executor >/dev/null 2>&1; then
	useradd --system --home-dir /var/lib/steward-executor --shell /usr/sbin/nologin \
		--groups docker steward-executor
else
	usermod --append --groups docker steward-executor
fi
if [[ $(id -u steward) -eq 0 || $(id -u steward-executor) -eq 0 || \
	$(id -u steward) -eq $(id -u steward-executor) ]]; then
	echo "install-node: Steward service identities must be distinct non-root users" >&2
	exit 2
fi
if id -nG steward | tr ' ' '\n' | grep -qx docker; then
	echo "install-node: refusing to give the lifecycle supervisor Docker authority" >&2
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
install -o root -g root -m 0755 "$root/steward" "$incoming/steward"
install -o root -g root -m 0755 "$root/stewardctl" "$incoming/stewardctl"
install -o root -g root -m 0755 "$root/steward-executor" "$incoming/steward-executor"
steward_version=$(runuser -u steward -- "$incoming/steward" -version | awk '{print $2}')
ctl_version=$(runuser -u steward -- "$incoming/stewardctl" -version | awk '{print $2}')
executor_version=$(runuser -u steward -- "$incoming/steward-executor" -version | awk '{print $2}')
if [[ -z $steward_version || $steward_version != "$executor_version" || $steward_version != "$ctl_version" ]]; then
	echo "install-node: Steward process versions do not match" >&2
	exit 2
fi
if [[ ! $steward_version =~ ^[A-Za-z0-9._+-]+$ ]]; then
	echo "install-node: unsafe version string '$steward_version'" >&2
	exit 2
fi

for binary in steward stewardctl steward-executor; do
	active="/usr/local/bin/$binary"
	if [[ -e $active || -L $active ]]; then
		target=$(readlink "$active" 2>/dev/null || true)
		case "$target" in
		/opt/steward/current/* | /opt/steward/releases/*) ;;
		*)
			echo "install-node: refusing to replace unmanaged $active" >&2
			exit 2
			;;
		esac
	fi
done

release_dir="/opt/steward/releases/$steward_version"
install -d -o root -g root -m 0755 "$release_dir"
install -o root -g root -m 0755 "$incoming/steward" "$release_dir/steward"
install -o root -g root -m 0755 "$incoming/stewardctl" "$release_dir/stewardctl"
install -o root -g root -m 0755 "$incoming/steward-executor" "$release_dir/steward-executor"
rm -rf "$incoming"
trap - EXIT
install -d -o root -g root -m 0755 /etc/steward /usr/local/bin /usr/local/libexec/steward \
	/usr/local/lib/systemd/system
install -d -o steward -g steward -m 0700 /var/lib/steward /var/log/steward
install -d -o steward-executor -g steward-executor -m 0700 /var/lib/steward-executor
install -o root -g root -m 0755 "$root/scripts/activate-node-release.sh" \
	/usr/local/libexec/steward/activate-node-release
install -o root -g root -m 0755 "$root/scripts/node-preflight.sh" \
	/usr/local/libexec/steward/node-preflight
install -o root -g root -m 0755 "$root/scripts/configure-node.sh" \
	/usr/local/libexec/steward/configure-node
install -o root -g root -m 0755 "$root/scripts/uninstall-node.sh" \
	/usr/local/libexec/steward/uninstall-node

if [[ ! -e /etc/steward/steward.json ]]; then
	install -o root -g steward -m 0640 "$root/deploy/config/steward.json" \
		/etc/steward/steward.json
fi
if [[ ! -e /etc/steward/executor.env ]]; then
	install -o root -g root -m 0600 "$root/deploy/config/executor.env" \
		/etc/steward/executor.env
fi
for unit in steward.service steward-executor.service; do
	legacy="/etc/systemd/system/$unit"
	if [[ -e $legacy || -L $legacy ]]; then
		if cmp -s "$legacy" "$root/deploy/systemd/$unit"; then
			rm -f "$legacy"
			echo "install-node: migrated legacy installer-owned $legacy"
		else
			echo "install-node: refusing modified $legacy because it shadows the packaged vendor unit" >&2
			echo "  Preserve local settings in /etc/systemd/system/$unit.d/*.conf, then remove the full-unit override and re-run." >&2
			exit 2
		fi
	fi
done
install -o root -g root -m 0644 "$root/deploy/systemd/steward.service" \
	/usr/local/lib/systemd/system/steward.service
install -o root -g root -m 0644 "$root/deploy/systemd/steward-executor.service" \
	/usr/local/lib/systemd/system/steward-executor.service

if [[ -e /opt/steward/current || -L /opt/steward/current ]]; then
	current_target=$(readlink /opt/steward/current 2>/dev/null || true)
	case "$current_target" in
	/opt/steward/releases/*) ;;
	*)
		echo "install-node: refusing unmanaged /opt/steward/current" >&2
		exit 2
		;;
	esac
	selection="staged; the active release was not changed"
else
	current_tmp="/opt/steward/.current.new.$$"
	rm -f "$current_tmp"
	ln -s "$release_dir" "$current_tmp"
	mv -Tf "$current_tmp" /opt/steward/current
	selection="selected for first-time configuration"
fi
for binary in steward stewardctl steward-executor; do
	tmp="/usr/local/bin/.${binary}.new.$$"
	rm -f "$tmp"
	ln -s "/opt/steward/current/$binary" "$tmp"
	mv -Tf "$tmp" "/usr/local/bin/$binary"
done
systemctl daemon-reload

echo "install-node: installed Steward $steward_version ($selection)"
echo "install-node: services remain disabled and stopped"
if [[ $selection == selected* ]]; then
	echo "install-node: install customer credentials and CA material, initialize the Executor fence, then run:"
	echo "  /usr/local/libexec/steward/node-preflight"
	echo "  systemctl enable --now steward steward-executor"
else
	echo "install-node: activate after provisioning trust material (activation runs full preflight):"
	echo "  /usr/local/libexec/steward/activate-node-release $steward_version --restart"
fi
