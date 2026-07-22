output "autoscaling_group_name" {
  description = "AWS Auto Scaling Group to connect to the site's capacity policy and drain automation."
  value       = aws_autoscaling_group.this.name
}

output "launch_template_id" {
  value = aws_launch_template.this.id
}

output "bootstrap_sha256" {
  description = "Digest of the non-secret first-boot document used by this pool generation."
  value       = module.bootstrap.cloud_init_sha256
}

output "requires_enrollment" {
  description = "Always true: instances are intentionally staged without reusable authority."
  value       = module.bootstrap.requires_enrollment
}

output "next_steps" {
  description = "Security-critical handoff required before a VM becomes Steward scheduling capacity."
  value = [
    "Wait for /var/lib/steward-bootstrap/complete on each new instance.",
    "Prepare and securely deliver one node-specific enrollment package; never place it in Terraform or EC2 user data.",
    "Run stewardctl site node activate on the destination and then ${module.bootstrap.node_readiness_command}.",
    "Before reducing desired capacity, cordon and drain the selected Steward node, then allow Auto Scaling termination.",
  ]
}
