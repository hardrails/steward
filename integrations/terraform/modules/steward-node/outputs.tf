output "cloud_init" {
  description = "Secret-free cloud-init user data for a Linux server resource."
  value       = local.cloud_init
  precondition {
    condition     = !var.install_gvisor || var.gvisor_version != ""
    error_message = "install_gvisor requires a pinned gvisor_version."
  }
  precondition {
    condition     = var.bootstrap_mode != "stage" || !var.install_gvisor
    error_message = "install_gvisor cannot be combined with bootstrap_mode=stage because staged installation deliberately does not touch Docker; preinstall gVisor in the image or use local bootstrap."
  }
  precondition {
    condition     = length(local.cloud_init) <= 16384
    error_message = "rendered cloud-init exceeds the 16 KiB portable user-data ceiling. Use shorter credential-free mirror URLs or an image with Steward already staged."
  }
}

output "requires_enrollment" {
  description = "True when a staged node still needs trust/credential delivery over a separate secure channel."
  value       = var.bootstrap_mode == "stage"
}

output "cloud_init_sha256" {
  description = "SHA-256 of the rendered non-secret cloud-init for rollout and audit correlation."
  value       = sha256(local.cloud_init)
}

output "bootstrap_completion_marker" {
  description = "Root-only marker written after the exact release has been staged successfully. This is installation readiness, not Steward node readiness."
  value       = "/var/lib/steward-bootstrap/complete"
}

output "node_readiness_command" {
  description = "Host-local command to run after enrollment. Exit zero means the complete Steward node doctor passed."
  value       = "sudo /usr/local/libexec/steward/node-doctor --json"
}
