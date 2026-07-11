#!/usr/bin/env bash
# Atomically select an already-installed Steward node version; optionally restart.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
	echo "activate-node-release: run as root" >&2
	exit 2
fi
if [[ $# -lt 1 || $# -gt 2 || ( $# -eq 2 && $2 != --restart ) ]]; then
	echo "usage: activate-node-release VERSION [--restart]" >&2
	exit 2
fi

version=$1
if [[ ! $version =~ ^[A-Za-z0-9._+-]+$ ]]; then
	echo "activate-node-release: unsafe version string '$version'" >&2
	exit 2
fi
release_dir="/opt/steward/releases/$version"
for binary in steward steward-executor; do
	path="$release_dir/$binary"
	if [[ ! -x $path ]]; then
		echo "activate-node-release: missing executable $path" >&2
		exit 2
	fi
	reported=$(runuser -u steward -- "$path" -version | awk '{print $2}')
	if [[ $reported != "$version" ]]; then
		echo "activate-node-release: $binary reports '$reported', expected '$version'" >&2
		exit 2
	fi
done

if [[ ${2:-} == --restart ]]; then
	STEWARD_BIN="$release_dir/steward" \
		STEWARD_EXECUTOR_BIN="$release_dir/steward-executor" \
		/usr/local/libexec/steward/node-preflight
fi

install -d -o root -g root -m 0755 /opt/steward /usr/local/bin
current_tmp="/opt/steward/.current.new.$$"
rm -f "$current_tmp"
ln -s "$release_dir" "$current_tmp"
mv -Tf "$current_tmp" /opt/steward/current

# These stable entry points are installed once (or repair an old direct-release
# symlink). Every later activation changes only /opt/steward/current, so both
# process names cross the version boundary in one atomic rename.
for binary in steward steward-executor; do
	tmp="/usr/local/bin/.${binary}.new.$$"
	rm -f "$tmp"
	ln -s "/opt/steward/current/$binary" "$tmp"
	mv -Tf "$tmp" "/usr/local/bin/$binary"
done

if [[ ${2:-} == --restart ]]; then
	systemctl try-restart steward-executor.service steward.service
fi
echo "activate-node-release: active version is $version"
