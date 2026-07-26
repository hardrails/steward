#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
for command in aws terraform; do
  command -v "$command" >/dev/null || {
    echo "steward-cluster-wait: $command is required" >&2
    exit 2
  }
done

region=$(terraform -chdir="$root" output -raw aws_region)
instance_csv=$(terraform -chdir="$root" output -raw server_instance_ids_csv)
IFS=, read -r -a instances <<<"$instance_csv"
(( ${#instances[@]} > 0 )) || {
  echo "steward-cluster-wait: Terraform produced no server instances" >&2
  exit 2
}

for instance in "${instances[@]}"; do
  echo "steward-cluster-wait: waiting for Session Manager on $instance"
  ready=false
  for _ in $(seq 1 90); do
    ping_status=$(aws --region "$region" ssm describe-instance-information \
      --filters "Key=InstanceIds,Values=$instance" \
      --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)
    if [[ $ping_status == Online ]]; then
      ready=true
      break
    fi
    sleep 10
  done
  [[ $ready == true ]] || {
    echo "steward-cluster-wait: $instance did not become a managed instance within 15 minutes" >&2
    exit 1
  }

  # shellcheck disable=SC2016 # The command substitutions run remotely through SSM.
  command_id=$(aws --region "$region" ssm send-command \
    --instance-ids "$instance" \
    --document-name AWS-RunShellScript \
    --parameters 'commands=["set -eu; for i in $(seq 1 360); do test -f /var/lib/steward-cluster-bootstrap/complete && break; sleep 10; done; test -f /var/lib/steward-cluster-bootstrap/complete; node=$(sed -n s/^node=//p /var/lib/steward-cluster-bootstrap/complete); sudo /usr/local/libexec/steward/install-cluster doctor --node \"$node\""],executionTimeout=["3700"]' \
    --query 'Command.CommandId' --output text)
  command_status=Pending
  for _ in $(seq 1 390); do
    command_status=$(aws --region "$region" ssm get-command-invocation \
      --command-id "$command_id" --instance-id "$instance" \
      --query Status --output text 2>/dev/null || true)
    case "$command_status" in
      Success)
        break
        ;;
      Pending|InProgress|Delayed|'')
        sleep 10
        ;;
      *)
        aws --region "$region" ssm get-command-invocation \
          --command-id "$command_id" --instance-id "$instance" \
          --query '{status:Status,stdout:StandardOutputContent,stderr:StandardErrorContent}'
        exit 1
        ;;
    esac
  done
  if [[ $command_status != Success ]]; then
    echo "steward-cluster-wait: bootstrap doctor timed out on $instance" >&2
    aws --region "$region" ssm get-command-invocation \
      --command-id "$command_id" --instance-id "$instance" \
      --query '{status:Status,stdout:StandardOutputContent,stderr:StandardErrorContent}'
    exit 1
  fi
  aws --region "$region" ssm get-command-invocation \
    --command-id "$command_id" --instance-id "$instance" \
    --query '{status:Status,output:StandardOutputContent}'
done

echo "steward-cluster-wait: every server passed the real cluster doctor"
terraform -chdir="$root" output session_commands
