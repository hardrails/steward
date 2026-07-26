#!/usr/bin/env bash
# Keep the public repository independent from separately developed products.
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
forbidden=$(printf '\162\141\151\154\171\141\162\144')
if rg -ni "$forbidden" "$root" \
	--glob '!.git/**' \
	--glob '!internal/controlplane/console/node_modules/**' >/dev/null; then
	echo "repository-independence-test: public source contains a forbidden project reference" >&2
	exit 1
fi
echo "repository-independence-test: public source remains independent"
