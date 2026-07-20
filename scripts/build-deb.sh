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
for forbidden in deploy/config/control.env deploy/systemd/steward-control.service \
	scripts/install-control.sh scripts/control-doctor.sh; do
	if [[ -e $stage/$forbidden || -L $stage/$forbidden ]]; then
		echo "build-deb: node package stage must not contain controller deployment asset $forbidden" >&2
		exit 2
	fi
done
for path in steward steward-control stewardctl steward-mcp steward-executor steward-gateway steward-relay steward-storage-zfs deploy/config/steward.json deploy/config/steward-local.json \
	deploy/config/executor.env deploy/config/executor-gateway.env deploy/systemd/steward.service \
	deploy/systemd/steward-executor.service deploy/systemd/steward-gateway.service deploy/systemd/steward-storage-zfs.service \
	deploy/config/gateway.json.in deploy/config/storage-zfs.json.in scripts/install-node.sh \
	scripts/activate-node-release.sh scripts/node-doctor.sh scripts/node-preflight.sh \
	scripts/configure-node.sh scripts/configure-admission.sh scripts/uninstall-node.sh \
	scripts/node-removal-guard.sh scripts/build-hermes-adapter.sh scripts/build-relay-image.sh \
	scripts/hermes-feasibility.sh scripts/hermes-steward-acceptance.sh \
	scripts/build-openclaw-adapter.sh scripts/openclaw-feasibility.sh \
	adapters/hermes-agent/Dockerfile adapters/hermes-agent/README.md \
	adapters/hermes-agent/adapter.json adapters/hermes-agent/entrypoint.py \
	adapters/hermes-agent/fixture_connector.py adapters/hermes-agent/fixture_mcp.py \
	adapters/hermes-agent/fixture_model.py adapters/hermes-agent/fixture_secret_scan.py \
	adapters/hermes-agent/fixtures/connector-skill/SKILL.md \
	adapters/hermes-agent/fixtures/connector-skill/connector-fixture-contract.json \
	adapters/hermes-agent/fixtures/connector-skill/connector_work.py \
	adapters/hermes-agent/fixtures/connector-skill/manifest.json \
	adapters/hermes-agent/fixtures/connector-skill/manifest.sig \
	adapters/hermes-agent/fixtures/connector-skill/public.pem \
	adapters/hermes-agent/fixtures/skill/SKILL.md \
	adapters/hermes-agent/fixtures/skill/manifest.json \
	adapters/hermes-agent/fixtures/skill/manifest.sig \
	adapters/hermes-agent/fixtures/skill/public.pem \
	adapters/hermes-agent/fixtures/skill/workspace-fixture-contract.json \
	adapters/hermes-agent/fixtures/skill/workspace_audit.py \
	adapters/hermes-agent/license-inventory.json adapters/hermes-agent/source-inputs.sha256 \
	adapters/openclaw/Dockerfile adapters/openclaw/adapter.json \
	adapters/openclaw/entrypoint.mjs adapters/openclaw/fixture_model.mjs \
	adapters/openclaw/result.mjs adapters/openclaw/source-inputs.sha256 \
	adapters/openclaw/fixtures/skill/SKILL.md \
	adapters/openclaw/fixtures/skill/workspace_audit.mjs \
	adapters/openclaw/fixtures/workspace/qualification/input/alpha.txt \
	adapters/openclaw/fixtures/workspace/qualification/input/nested.json \
	examples/agents/hermes/agent.json examples/agents/openclaw/agent.json \
	examples/agents/nodes.json examples/policy/steward.rego schemas/agent.cue \
	release.json LICENSE README.md; do
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
cp -R "$stage/steward" "$stage/steward-control" "$stage/stewardctl" "$stage/steward-mcp" "$stage/steward-executor" \
	"$stage/steward-gateway" "$stage/steward-relay" "$stage/steward-storage-zfs" "$stage/adapters" "$stage/deploy" "$stage/scripts" \
	"$stage/examples" "$stage/schemas" \
	"$stage/release.json" \
	"$package_root/usr/lib/steward-node/release/"
install -m 0644 "$stage/LICENSE" "$package_root/usr/share/doc/steward-node/copyright"
install -m 0644 "$stage/README.md" "$package_root/usr/share/doc/steward-node/README.md"

sed -e "s/@VERSION@/$deb_version/g" -e "s/@ARCH@/$deb_arch/g" \
	"$repo/packaging/debian/control.in" >"$package_root/DEBIAN/control"
sed -e "s/@RELEASE_VERSION@/$version/g" "$repo/packaging/debian/postinst" \
	>"$package_root/DEBIAN/postinst"
chmod 0755 "$package_root/DEBIAN/postinst"
for script in preinst prerm postrm; do
	install -m 0755 "$repo/packaging/debian/$script" "$package_root/DEBIAN/$script"
done

mkdir -p "$(dirname "$output")"
dpkg-deb --root-owner-group --build "$package_root" "$output" >/dev/null
echo "build-deb: wrote $output"
