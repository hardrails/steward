#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ha=false
approve=false
terraform_args=()

usage() {
  cat <<'EOF'
Create a Steward management cluster with Terraform.

Usage:
  ./up.sh [--ha] [--yes] [terraform apply options]

Options:
  --ha      Create three RKE2 servers instead of one.
  --yes     Pass -auto-approve after Terraform has printed the plan.
  -h        Show this help.

AWS credentials and AWS_REGION (or your normal AWS CLI profile) must already be
configured. This command creates billable AWS resources.
EOF
}

while (($#)); do
  case "$1" in
  --ha)
    ha=true
    shift
    ;;
  --yes)
    approve=true
    shift
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    terraform_args+=("$1")
    shift
    ;;
  esac
done

for command in aws terraform; do
  command -v "$command" >/dev/null || {
    echo "steward-cluster-up: $command is required" >&2
    exit 2
  }
done

aws sts get-caller-identity >/dev/null
terraform -chdir="$root" init
apply_args=(apply)
[[ $ha == false ]] || apply_args+=(-var=server_count=3)
[[ $approve == false ]] || apply_args+=(-auto-approve)
apply_args+=("${terraform_args[@]}")
terraform -chdir="$root" "${apply_args[@]}"
"$root/wait.sh"
