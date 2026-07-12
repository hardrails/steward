#!/usr/bin/env bash
# Build one Debian package from an already-built Linux release stage.
set -euo pipefail

if [[ $# -ne 4 ]]; then
	echo "usage: $0 STAGE VERSION GOARCH OUTPUT.deb" >&2
	exit 2
fi

stage=$1
version=$2
goarch=$3
output=$4
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v dpkg-deb >/dev/null || {
	echo "build-deb: dpkg-deb is required" >&2
	exit 2
}
for path in steward stewardctl steward-executor deploy/config/steward.json \
	deploy/config/executor.env deploy/systemd/steward.service \
	deploy/systemd/steward-executor.service scripts/install-node.sh \
	scripts/activate-node-release.sh scripts/node-preflight.sh \
	scripts/configure-node.sh scripts/uninstall-node.sh LICENSE README.md; do
	if [[ ! -f "$stage/$path" ]]; then
		echo "build-deb: stage is missing $path" >&2
		exit 2
	fi
done

case "$goarch" in
	amd64) deb_arch=amd64 ;;
	arm64) deb_arch=arm64 ;;
	*)
		echo "build-deb: unsupported architecture $goarch" >&2
		exit 2
		;;
esac

raw_version=${version#v}
if [[ $raw_version =~ ^([0-9]+\.[0-9]+\.[0-9]+)(-([0-9A-Za-z.-]+))?$ ]]; then
	deb_version=${BASH_REMATCH[1]}
	if [[ -n ${BASH_REMATCH[3]:-} ]]; then
		deb_version+="~${BASH_REMATCH[3]}"
	fi
else
	safe=${raw_version//[^0-9A-Za-z.+~]/.}
	deb_version="0~${safe:-dev}"
fi

package_root=$(mktemp -d "${TMPDIR:-/tmp}/steward-deb.XXXXXX")
cleanup() {
	rm -rf "$package_root"
}
trap cleanup EXIT HUP INT TERM

install -d -m 0755 "$package_root/DEBIAN" \
	"$package_root/usr/lib/steward-node/release" \
	"$package_root/usr/share/doc/steward-node"
cp -R "$stage/steward" "$stage/stewardctl" "$stage/steward-executor" "$stage/deploy" "$stage/scripts" \
	"$package_root/usr/lib/steward-node/release/"
install -m 0644 "$stage/LICENSE" "$package_root/usr/share/doc/steward-node/copyright"
install -m 0644 "$stage/README.md" "$package_root/usr/share/doc/steward-node/README.md"

sed -e "s/@VERSION@/$deb_version/g" -e "s/@ARCH@/$deb_arch/g" \
	"$repo/packaging/debian/control.in" >"$package_root/DEBIAN/control"
for script in postinst prerm postrm; do
	install -m 0755 "$repo/packaging/debian/$script" "$package_root/DEBIAN/$script"
done

mkdir -p "$(dirname "$output")"
dpkg-deb --root-owner-group --build "$package_root" "$output" >/dev/null
echo "build-deb: wrote $output"
