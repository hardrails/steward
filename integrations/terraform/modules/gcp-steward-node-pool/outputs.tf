output "instance_group_manager_id" {
  value = google_compute_region_instance_group_manager.this.id
}

output "instance_group" {
  value = google_compute_region_instance_group_manager.this.instance_group
}

output "instance_template_self_link" {
  value = google_compute_instance_template.this.self_link
}

output "bootstrap_sha256" {
  value = module.bootstrap.cloud_init_sha256
}

output "requires_enrollment" {
  value = module.bootstrap.requires_enrollment
}

output "next_steps" {
  value = [
    "Wait for /var/lib/steward-bootstrap/complete on each new instance.",
    "Prepare and securely deliver one node-specific enrollment package; never place it in Terraform or Compute Engine metadata.",
    "Run stewardctl site node activate on the destination and then ${module.bootstrap.node_readiness_command}.",
    "Before reducing target size, cordon and drain the selected Steward node, then resize the Managed Instance Group.",
  ]
}
