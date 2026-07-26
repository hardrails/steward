output "cluster_name" {
  value = var.name
}

output "server_instance_ids" {
  description = "Bootstrap server followed by joining servers."
  value       = concat([aws_instance.bootstrap.id], aws_instance.joining[*].id)
}

output "server_private_ips" {
  description = "Private server addresses in RKE2 sequence order."
  value       = concat([aws_instance.bootstrap.private_ip], aws_instance.joining[*].private_ip)
}

output "rke2_registration_url" {
  description = "Private supervisor endpoint used during initial server joins."
  value       = "https://${aws_instance.bootstrap.private_ip}:9345"
}

output "security_group_id" {
  value = aws_security_group.cluster.id
}

output "selected_ami_id" {
  description = "Concrete AMI selected for this apply. Pin this value for reviewed rebuilds."
  value       = local.ami_id
}

output "steward_release_version" {
  description = "Steward release recorded for the running cluster."
  value       = terraform_data.release_contract.output.steward_release_version
}

output "formation_contract" {
  description = "Non-secret topology and Steward release identity recorded for the running cluster."
  value = {
    server_count             = terraform_data.topology_contract.output
    steward_release_version  = terraform_data.release_contract.output.steward_release_version
    steward_installer_sha256 = terraform_data.release_contract.output.steward_installer_sha256
  }
}

output "bootstrap_completion_marker" {
  value = "/var/lib/steward-cluster-bootstrap/complete"
}

output "token_rendezvous" {
  description = "Metadata only. The plaintext token is created and consumed by EC2 identities and never enters Terraform."
  value = {
    parameter_name          = local.token_parameter_name
    expires_hours           = var.rendezvous_ttl_hours
    terraform_has_plaintext = false
  }
}

output "session_commands" {
  description = "Copy-paste Session Manager commands; no inbound SSH rule is required."
  value = var.enable_session_manager ? [
    for id in concat([aws_instance.bootstrap.id], aws_instance.joining[*].id) :
    "aws ssm start-session --target ${id} --region ${local.aws_region}"
  ] : []
}

output "doctor_commands" {
  description = "Commands to run inside each Session Manager shell."
  value = [
    for index in range(var.server_count) :
    "sudo /usr/local/libexec/steward/install-cluster doctor --node ${var.name}-server-${index + 1}"
  ]
}

output "first_operator_check" {
  description = "Run on the first server after cloud-init completes."
  value       = "sudo /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes -o wide"
}
