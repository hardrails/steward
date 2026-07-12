output "cloud_init" {
  description = "Secret-free cloud-init user data for a Linux server resource."
  value       = local.cloud_init
  precondition {
    condition     = !var.install_gvisor || var.gvisor_version != ""
    error_message = "install_gvisor requires a pinned gvisor_version."
  }
}

output "requires_enrollment" {
  description = "True when a staged node still needs trust/credential delivery over a separate secure channel."
  value       = var.bootstrap_mode == "stage"
}
