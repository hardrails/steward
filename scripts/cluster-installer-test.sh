#!/usr/bin/env bash
# Hermetic contract and attack checks for the privileged cluster installer.
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/steward-cluster-installer.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

installer=$root/scripts/install-cluster.sh
read -r shebang <"$installer"
[[ $shebang == '#!/bin/bash -p' ]]
grep -Fq 'unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy' "$installer"
grep -Fq -- "--proto '=https'" "$installer"
# shellcheck disable=SC2016 # Match the literal reviewed shell expression.
grep -Fq -- '--max-filesize "$limit"' "$installer"
grep -Fq 'RKE2 bundle size or SHA-256 differs from Steward' "$installer"
grep -Fq 'RKE2 bundle contains a link or special file' "$installer"
grep -Fq 'existing Kubernetes configuration is not owned by this installer' "$installer"
grep -Fq 'active firewalld conflicts' "$installer"
grep -Fq 'runtime_type = "io.containerd.runsc.v1"' "$installer"
# shellcheck disable=SC2016 # Match the literal reviewed shell expression.
grep -Fq 'get node "$node" -o '\''jsonpath={.status.conditions[?(@.type=="Ready")].status}' "$installer"
if grep -Fq '/usr/local/bin/rke2 kubectl' "$installer"; then
	echo "cluster-installer-test: doctor delegates kubectl to an unsupported RKE2 subcommand" >&2
	exit 1
fi
grep -Fq 'profile: cis' "$root/internal/clustersubstrate/plan.go"
grep -Fq 'secrets-encryption: true' "$root/internal/clustersubstrate/plan.go"
grep -Fq 'name: default-deny' "$root/internal/clustersubstrate/plan.go"

go build -o "$work/stewardctl" "$root/cmd/stewardctl"
/bin/bash -p "$installer" init \
	--cluster research --node server-1 --dry-run --stewardctl "$work/stewardctl" >"$work/plan"
grep -Fq 'Operation:     init' "$work/plan"
grep -Fq 'No host changes were made.' "$work/plan"

lock_version=$("$work/stewardctl" cluster plan init \
	-cluster research -node server-1 -arch amd64 -output json |
	sed -n 's/^[[:space:]]*"version": "\([^"]*\)",*$/\1/p')
[[ $lock_version == v1.35.6+rke2r1 ]]

for unsafe in \
	'init --cluster Bad_Name --node server-1 --dry-run' \
	'join-worker --cluster research --node worker-1 --server http://server:9345 --token-file /tmp/token --dry-run' \
	'join-worker --cluster research --node worker-1 --server https://server:6443 --token-file /tmp/token --dry-run'; do
	read -r -a arguments <<<"$unsafe"
	if /bin/bash -p "$installer" "${arguments[@]}" --stewardctl "$work/stewardctl" >/dev/null 2>&1; then
		echo "cluster-installer-test: unsafe plan succeeded: $unsafe" >&2
		exit 1
	fi
done

echo "cluster-installer-test: cluster installer contracts pass"
