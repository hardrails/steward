#!/usr/bin/env bash
# Build one RPM package from an already-built Linux release stage.
set -euo pipefail

if [[ $# -ne 4 ]]; then
	echo "usage: $0 STAGE VERSION GOARCH OUTPUT.rpm" >&2
	exit 2
fi

stage=$1
version=$2
goarch=$3
output=$4
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v rpmbuild >/dev/null || {
	echo "build-rpm: rpmbuild is required" >&2
	exit 2
}
for path in steward steward-executor deploy/config/steward.json \
	deploy/config/executor.env deploy/systemd/steward.service \
	deploy/systemd/steward-executor.service scripts/install-node.sh \
	scripts/activate-node-release.sh scripts/node-preflight.sh \
	scripts/configure-node.sh scripts/uninstall-node.sh LICENSE README.md; do
	if [[ ! -f "$stage/$path" ]]; then
		echo "build-rpm: stage is missing $path" >&2
		exit 2
	fi
done

case "$goarch" in
	amd64) rpm_arch=x86_64 ;;
	arm64) rpm_arch=aarch64 ;;
	*)
		echo "build-rpm: unsupported architecture $goarch" >&2
		exit 2
		;;
esac

raw_version=${version#v}
if [[ $raw_version =~ ^([0-9]+\.[0-9]+\.[0-9]+)(-([0-9A-Za-z.-]+))?$ ]]; then
	rpm_version=${BASH_REMATCH[1]}
	if [[ -n ${BASH_REMATCH[3]:-} ]]; then
		rpm_release="0.${BASH_REMATCH[3]//-/.}"
	else
		rpm_release=1
	fi
else
	safe=${raw_version//[^0-9A-Za-z.]/.}
	rpm_version=0.0.0
	rpm_release="0.${safe:-dev}"
fi

topdir=$(mktemp -d "${TMPDIR:-/tmp}/steward-rpm.XXXXXX")
cleanup() {
	rm -rf "$topdir"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$topdir"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
cp -R "$stage" "$topdir/SOURCES/release"
cp "$stage/LICENSE" "$stage/README.md" "$topdir/SOURCES/"
sed -e "s/@VERSION@/$rpm_version/g" \
	-e "s/@RELEASE@/$rpm_release/g" \
	-e "s/@ARCH@/$rpm_arch/g" \
	"$repo/packaging/rpm/steward-node.spec.in" >"$topdir/SPECS/steward-node.spec"

rpmbuild --define "_topdir $topdir" --target "$rpm_arch" \
	-bb "$topdir/SPECS/steward-node.spec" >/dev/null
built=$(find "$topdir/RPMS" -type f -name '*.rpm' -print -quit)
if [[ -z $built ]]; then
	echo "build-rpm: rpmbuild produced no package" >&2
	exit 1
fi
mkdir -p "$(dirname "$output")"
cp "$built" "$output"
echo "build-rpm: wrote $output"
