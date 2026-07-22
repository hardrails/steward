module "bootstrap" {
  source = "../steward-node"

  release_version  = var.release_version
  installer_url    = var.installer_url
  installer_sha256 = var.installer_sha256
  release_mirror   = var.release_mirror
  bootstrap_mode   = "stage"
}

locals {
  labels = merge(var.labels, {
    steward-role      = "node"
    steward-bootstrap = substr(module.bootstrap.cloud_init_sha256, 0, 16)
  })
}

resource "google_compute_instance_template" "this" {
  project        = var.project_id
  name_prefix    = "${var.name}-"
  machine_type   = var.machine_type
  can_ip_forward = false

  labels = local.labels

  disk {
    auto_delete  = true
    boot         = true
    disk_size_gb = var.root_volume_gib
    disk_type    = "pd-balanced"
    source_image = var.source_image
    disk_encryption_key {
      kms_key_self_link = var.kms_key_self_link
    }
  }

  network_interface {
    subnetwork = var.subnetwork_self_link
  }

  metadata = {
    block-project-ssh-keys = "TRUE"
    enable-oslogin         = "TRUE"
    user-data              = module.bootstrap.cloud_init
  }

  service_account {
    email  = var.service_account_email
    scopes = []
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    provisioning_model  = "STANDARD"
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_region_instance_group_manager" "this" {
  project            = var.project_id
  name               = var.name
  base_instance_name = var.name
  region             = var.region
  target_size        = var.capacity
  target_pools       = []

  distribution_policy_zones = length(var.zones) == 0 ? null : var.zones

  version {
    name              = "primary"
    instance_template = google_compute_instance_template.this.self_link
  }

  update_policy {
    type                           = "OPPORTUNISTIC"
    minimal_action                 = "REPLACE"
    most_disruptive_allowed_action = "REPLACE"
  }

  wait_for_instances_status = "STABLE"

  lifecycle {
    # Terraform creates initial capacity but must not select a live Steward node
    # for replacement or scale-in. Resize through a post-drain fleet operation.
    ignore_changes = [target_size]
  }
}
