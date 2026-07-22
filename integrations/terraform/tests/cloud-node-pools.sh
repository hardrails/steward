#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
modules=$root/integrations/terraform/modules
work=$(mktemp -d "${TMPDIR:-/tmp}/steward-cloud-node-pools.XXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM

require_text() {
	local file=$1 text=$2
	grep -F -- "$text" "$file" >/dev/null || {
		echo "cloud node-pool test: missing required text '$text' in $file" >&2
		exit 1
	}
}

reject_text() {
	local file=$1 text=$2
	if grep -F -- "$text" "$file" >/dev/null; then
		echo "cloud node-pool test: forbidden text '$text' in $file" >&2
		exit 1
	fi
}

terraform fmt -check -recursive "$modules/aws-steward-node-pool" \
	"$modules/gcp-steward-node-pool" "$modules/azure-steward-node-pool"

require_text "$modules/aws-steward-node-pool/main.tf" 'http_tokens                 = "required"'
require_text "$modules/aws-steward-node-pool/main.tf" 'http_put_response_hop_limit = 1'
require_text "$modules/aws-steward-node-pool/main.tf" 'version = aws_launch_template.this.latest_version'
require_text "$modules/aws-steward-node-pool/main.tf" 'ignore_changes = [min_size, desired_capacity, max_size]'
reject_text "$modules/aws-steward-node-pool/main.tf" 'instance_refresh {'
require_text "$modules/gcp-steward-node-pool/main.tf" 'enable_secure_boot          = true'
require_text "$modules/gcp-steward-node-pool/main.tf" 'type                           = "OPPORTUNISTIC"'
require_text "$modules/gcp-steward-node-pool/main.tf" 'ignore_changes = [target_size]'
reject_text "$modules/gcp-steward-node-pool/main.tf" 'access_config {'
require_text "$modules/azure-steward-node-pool/main.tf" 'disable_password_authentication = true'
require_text "$modules/azure-steward-node-pool/main.tf" 'upgrade_mode                    = "Manual"'
require_text "$modules/azure-steward-node-pool/main.tf" 'ignore_changes = [instances]'
reject_text "$modules/azure-steward-node-pool/main.tf" 'admin_password'

for module in aws-steward-node-pool gcp-steward-node-pool azure-steward-node-pool; do
	if grep -E '^variable ".*(token|password|secret|private_key)' "$modules/$module/variables.tf" >/dev/null; then
		echo "cloud node-pool test: $module accepts authority or secret material" >&2
		exit 1
	fi
	require_text "$modules/$module/main.tf" 'bootstrap_mode   = "stage"'
	require_text "$modules/$module/README.md" 'does not enroll'
done

if ! command -v terraform >/dev/null 2>&1; then
	echo 'cloud node-pool test: static boundaries passed; terraform is unavailable, so provider schema validation was skipped'
	exit 0
fi

mkdir -p "$work/modules"
cp -R "$modules/steward-node" "$work/modules/steward-node"
for module in aws-steward-node-pool gcp-steward-node-pool azure-steward-node-pool; do
	cp -R "$modules/$module" "$work/modules/$module"
	terraform -chdir="$work/modules/$module" init -backend=false -input=false >/dev/null
	terraform -chdir="$work/modules/$module" validate >/dev/null
done

echo 'cloud node-pool test: AWS, Google Cloud, and Azure modules passed security and provider-schema gates'
