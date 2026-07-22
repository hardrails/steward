output "scale_set_id" {
  value = azurerm_linux_virtual_machine_scale_set.this.id
}

output "managed_identity_principal_id" {
  description = "Unprivileged system-assigned identity available for a future attested-enrollment profile. This module grants it no role."
  value       = azurerm_linux_virtual_machine_scale_set.this.identity[0].principal_id
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
    "Prepare and securely deliver one node-specific enrollment package; never place it in Terraform or VMSS custom data.",
    "Run stewardctl site node activate on the destination and then ${module.bootstrap.node_readiness_command}.",
    "Before reducing instance count, cordon and drain the selected Steward node, then update the scale set capacity.",
    "Apply image-model changes to instances in deliberate batches; automatic upgrades remain disabled until Steward readiness is connected to Azure Application Health.",
  ]
}
