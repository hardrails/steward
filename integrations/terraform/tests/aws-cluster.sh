#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
module=$root/integrations/terraform/modules/aws-steward-cluster
example=$root/integrations/terraform/examples/aws-cluster-quickstart
work=$(mktemp -d "${TMPDIR:-/tmp}/steward-aws-cluster.XXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM

require_text() {
	local file=$1 text=$2
	grep -F -- "$text" "$file" >/dev/null || {
		echo "aws cluster test: missing required text '$text' in $file" >&2
		exit 1
	}
}

reject_text() {
	local file=$1 text=$2
	if grep -F -- "$text" "$file" >/dev/null; then
		echo "aws cluster test: forbidden text '$text' in $file" >&2
		exit 1
	fi
}

terraform fmt -check -recursive "$module" "$example"
shellcheck "$module/bootstrap.sh.tftpl" "$example/up.sh" "$example/wait.sh" "$example/down.sh"
bash -n "$module/bootstrap.sh.tftpl" "$example/up.sh" "$example/wait.sh" "$example/down.sh"

python3 - "$root" "$module/source-lock.json" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
lock = json.loads(pathlib.Path(sys.argv[2]).read_text())
assert lock["schema_version"] == "steward.aws-cluster-source-lock.v1"
version_source = (root / "internal/buildinfo/version.go").read_text()
match = re.search(r'const Version = "([^"]+)"', version_source)
assert match and f"v{match.group(1)}" == lock["steward"]["version"]
installer = (root / "scripts/install-steward.sh").read_bytes()
assert hashlib.sha256(installer).hexdigest() == lock["steward"]["installer_sha256"]
assert re.fullmatch(r"20[0-9]{6}(?:\.[0-9]+)?", lock["gvisor"]["version"])
for architecture in ("amd64", "arm64"):
    archive = lock["gvisor"]["archives"][architecture]
    assert archive["upstream_arch"] in ("x86_64", "aarch64")
    assert 1 < archive["size"] <= 209_715_200
    assert re.fullmatch(r"[0-9a-f]{128}", archive["sha512"])
PY

require_text "$module/main.tf" 'Action   = ["ssm:PutParameter"]'
require_text "$module/main.tf" 'Action   = ["ssm:GetParameter"]'
require_text "$module/main.tf" 'http_tokens                 = "required"'
require_text "$module/main.tf" 'ignore_changes = [user_data]'
require_text "$module/bootstrap.sh.tftpl" 'ssm put-parameter --cli-input-json'
require_text "$module/bootstrap.sh.tftpl" '"Tier":"Advanced"'
require_text "$module/bootstrap.sh.tftpl" '"Type\\":\\"Expiration\\"'
require_text "$module/bootstrap.sh.tftpl" 'install-cluster doctor'
require_text "$module/bootstrap.sh.tftpl" 'cluster doctor did not pass within'
require_text "$module/bootstrap.sh.tftpl" 'expected_inventory='
reject_text "$module/main.tf" 'resource "aws_ssm_parameter"'
reject_text "$module/main.tf" 'resource "random_'
reject_text "$module/main.tf" 'provisioner "'
reject_text "$module/bootstrap.sh.tftpl" 'ssm put-parameter --value'
reject_text "$module/bootstrap.sh.tftpl" 'set -x'
reject_text "$module/bootstrap.sh.tftpl" '! -L $cluster_installer'
reject_text "$example/main.tf" 'ingress {'
reject_text "$example/main.tf" 'key_name'

if ! command -v terraform >/dev/null 2>&1; then
	echo "aws cluster test: static trust and source-lock boundaries passed; terraform is unavailable"
	exit 0
fi

cat >"$work/main.tf" <<EOF
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region                      = "us-west-2"
  access_key                  = "fixture"
  secret_key                  = "fixture"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_requesting_account_id  = true
}

module "cluster" {
  source = "$module"

  name         = "fixture"
  vpc_id       = "vpc-0123456789abcdef0"
  subnet_ids   = ["subnet-0123456789abcdef0"]
  server_count = 1
  ami_id       = "ami-0123456789abcdef0"
  kms_key_arn  = "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
}
EOF

terraform -chdir="$work" init -backend=false -input=false >/dev/null
terraform -chdir="$work" validate >/dev/null
terraform -chdir="$work" plan -refresh=false -input=false -out="$work/plan" >/dev/null
terraform -chdir="$work" show -json "$work/plan" >"$work/plan.json"

python3 - "$work/plan.json" <<'PY'
import base64
import json
import re
import sys

plan = json.load(open(sys.argv[1], encoding="utf-8"))
resources = []

def walk(module):
    resources.extend(module.get("resources", []))
    for child in module.get("child_modules", []):
        walk(child)

walk(plan["planned_values"]["root_module"])
instance = next(r for r in resources if r["address"] == "module.cluster.aws_instance.bootstrap")
cloud_init = instance["values"]["user_data"]
assert len(cloud_init.encode()) <= 16_384
match = re.search(r"^\s*content: ([A-Za-z0-9+/=]+)$", cloud_init, re.MULTILINE)
assert match, f"rendered cloud-init does not contain its encoded bootstrap: {cloud_init!r}"
script = base64.b64decode(match.group(1)).decode()
assert len(script.encode()) < 16_384
assert "${" not in script
assert "ssm put-parameter --cli-input-json" in script
assert "ssm put-parameter --value" not in script
assert "set -x" not in script
assert 'gvisor_version="20260721.0"' in script
assert "v3.7.0" in script
PY

echo "aws cluster test: secret-free Terraform plan and rendered bootstrap passed"
