module "bootstrap" {
  source = "../steward-node"

  release_version  = var.release_version
  installer_url    = var.installer_url
  installer_sha256 = var.installer_sha256
  release_mirror   = var.release_mirror
  bootstrap_mode   = "stage"
}

resource "azurerm_linux_virtual_machine_scale_set" "this" {
  name                = var.name
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = var.sku
  instances           = var.capacity
  zones               = var.zones
  zone_balance        = true

  admin_username                  = "steward-admin"
  disable_password_authentication = true
  custom_data                     = base64encode(module.bootstrap.cloud_init)
  source_image_id                 = var.source_image_id
  upgrade_mode                    = "Manual"

  computer_name_prefix                              = "steward"
  encryption_at_host_enabled                        = true
  secure_boot_enabled                               = true
  vtpm_enabled                                      = true
  overprovision                                     = false
  single_placement_group                            = false
  do_not_run_extensions_on_overprovisioned_machines = true

  admin_ssh_key {
    username   = "steward-admin"
    public_key = trimspace(var.admin_ssh_public_key)
  }

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching                = "ReadWrite"
    storage_account_type   = "Premium_LRS"
    disk_size_gb           = var.root_volume_gib
    disk_encryption_set_id = var.disk_encryption_set_id
  }

  network_interface {
    name                      = "private"
    primary                   = true
    network_security_group_id = var.network_security_group_id

    ip_configuration {
      name      = "private"
      primary   = true
      subnet_id = var.subnet_id
    }
  }

  boot_diagnostics {}

  tags = merge(var.tags, {
    "steward.io/role"    = "node"
    "steward.io/release" = var.release_version
  })

  lifecycle {
    precondition {
      condition     = length(module.bootstrap.cloud_init) <= 65535
      error_message = "rendered cloud-init exceeds Azure custom-data capacity."
    }
  }
}
