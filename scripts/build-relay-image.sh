#!/usr/bin/env bash
# Build the trusted relay image locally, without a registry or network fetch.
set -euo pipefail

configure=false
if [[ ${1:-} == --configure ]]; then configure=true; shift; fi
if [[ $# -ne 0 ]]; then
	echo "usage: build-relay-image.sh [--configure]" >&2
	exit 2
fi
command -v docker >/dev/null || { echo "build-relay-image: Docker is required" >&2; exit 2; }
binary=${STEWARD_RELAY_BIN:-/usr/local/bin/steward-relay}
[[ -x $binary ]] || { echo "build-relay-image: missing $binary" >&2; exit 2; }
version=$($binary -version | awk '{print $2}')
[[ $version =~ ^[A-Za-z0-9._+-]+$ ]] || { echo "build-relay-image: unsafe relay version" >&2; exit 2; }

work=$(mktemp -d "${TMPDIR:-/tmp}/steward-relay.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
install -m 0755 "$binary" "$work/steward-relay"
printf '%s\n' 'FROM scratch' 'COPY steward-relay /steward-relay' \
	'USER 65532:65532' 'ENTRYPOINT ["/steward-relay"]' >"$work/Dockerfile"
tag="steward-relay-local:${version#v}"
docker build --network=none --pull=false --provenance=false -t "$tag" "$work" >/dev/null
image_id=$(docker image inspect --format '{{.Id}}' "$tag")
[[ $image_id =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "build-relay-image: Docker returned an invalid image ID" >&2; exit 1; }
relay_gid=$(getent group steward-relay | cut -d: -f3)
[[ $relay_gid =~ ^[1-9][0-9]*$ ]] || { echo "build-relay-image: steward-relay group is missing" >&2; exit 2; }
arguments="-gateway-control-socket=/run/steward-gateway/control.sock -gateway-grant-root=/run/steward-gateway/grants -relay-image=$image_id -relay-gid=$relay_gid"
if [[ $configure == true ]]; then
	[[ ${EUID} -eq 0 ]] || { echo "build-relay-image: --configure requires root" >&2; exit 2; }
	tmp=$(mktemp /etc/steward/.executor-gateway.env.XXXXXX)
	printf 'EXECUTOR_GATEWAY_ARGS=%s\n' "$arguments" >"$tmp"
	chown root:root "$tmp"
	chmod 0600 "$tmp"
	mv -f "$tmp" /etc/steward/executor-gateway.env
	echo "build-relay-image: configured Executor positive-capability topology"
fi
echo "build-relay-image: immutable relay image $image_id"
echo "EXECUTOR_GATEWAY_ARGS=$arguments"
