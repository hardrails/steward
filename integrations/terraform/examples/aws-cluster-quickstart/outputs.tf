output "cluster_name" {
  value = module.steward_cluster.cluster_name
}

output "server_instance_ids" {
  value = module.steward_cluster.server_instance_ids
}

output "server_instance_ids_csv" {
  value = join(",", module.steward_cluster.server_instance_ids)
}

output "server_private_ips" {
  value = module.steward_cluster.server_private_ips
}

output "selected_ami_id" {
  value = module.steward_cluster.selected_ami_id
}

output "aws_region" {
  value = data.aws_region.current.region
}

output "session_commands" {
  value = module.steward_cluster.session_commands
}

output "doctor_commands" {
  value = module.steward_cluster.doctor_commands
}

output "first_operator_check" {
  value = module.steward_cluster.first_operator_check
}
