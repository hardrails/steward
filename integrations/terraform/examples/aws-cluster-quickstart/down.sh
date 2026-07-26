#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
approve=false
terraform_args=()

usage() {
  cat <<'EOF'
Remove the AWS Steward management-cluster quick start.

Usage:
  ./down.sh [--yes] [terraform destroy options]

Options:
  --yes     Pass -auto-approve after Terraform has printed the plan.
  -h        Show this help.

The command deletes the encrypted bootstrap rendezvous without reading it, then
destroys every resource in this example's Terraform state.
EOF
}

while (($#)); do
  case "$1" in
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
    echo "steward-cluster-down: $command is required" >&2
    exit 2
  }
done

region=$(terraform -chdir="$root" output -raw aws_region)
cluster=$(terraform -chdir="$root" output -raw cluster_name)
parameter="/steward/$cluster/bootstrap/rke2-server-token"
existing=$(aws --region "$region" ssm describe-parameters \
  --parameter-filters "Key=Name,Option=Equals,Values=$parameter" \
  --query 'Parameters[0].Name' --output text)
if [[ $existing == "$parameter" ]]; then
  aws --region "$region" ssm delete-parameter --name "$parameter"
  echo "steward-cluster-down: deleted the encrypted bootstrap rendezvous"
fi

destroy_args=(destroy -var="name=$cluster")
[[ $approve == false ]] || destroy_args+=(-auto-approve)
destroy_args+=("${terraform_args[@]}")
terraform -chdir="$root" "${destroy_args[@]}"
