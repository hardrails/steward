output "cloud_init" {
  description = "Secret-free, one-shot cloud-init user data for a systemd Linux server."
  value       = local.cloud_init
  sensitive   = false

  precondition {
    condition = (
      length(local.cloud_init) <= local.max_cloud_init_bytes &&
      length(base64encode(local.cloud_init)) <= local.max_cloud_init_b64
    )
    error_message = "rendered Steward Control cloud-init exceeds the 16 KiB safety ceiling."
  }
}

output "control_url" {
  description = "Loopback Steward Control URL created by bootstrap; use it on the host or through an authenticated tunnel."
  value       = local.control_url
  sensitive   = false
}

output "site_admin_token_path" {
  description = "Fixed owner-only path where first bootstrap writes the site-administrator token on the controller host; this is path metadata, not the token."
  value       = local.admin_token_path
  sensitive   = false
}

output "bootstrap_completion_path" {
  description = "Root-only on-host marker that binds completed bootstrap to the installed release and controller binary digest."
  value       = local.completion_stamp_path
  sensitive   = false
}

output "operator_handoff" {
  description = "Non-secret next-step metadata for retrieving the locally generated administrator credential."
  value = {
    token_path        = local.admin_token_path
    loopback_endpoint = local.control_url
    tunnel_target     = local.control_address
    next_step         = "Retrieve the token file through an authenticated host channel, move it into protected operator storage, remove the on-host copy, then use stewardctl through a tunnel or a separately configured TLS endpoint."
  }
  sensitive = false
}
