# Azure Steward node pool

This module creates a private zonal Linux Virtual Machine Scale Set from existing
network, image, Network Security Group, and Disk Encryption Set resources. It uses
no password, creates no public IP, enables host encryption, Secure Boot, vTPM,
customer-managed disk encryption, boot diagnostics, and an otherwise unprivileged
system-assigned identity.

```hcl
module "steward_nodes" {
  source = "./steward/integrations/terraform/modules/azure-steward-node-pool"

  name                      = "agents-prod"
  resource_group_name       = azurerm_resource_group.site.name
  location                  = azurerm_resource_group.site.location
  subnet_id                 = azurerm_subnet.private.id
  network_security_group_id = azurerm_network_security_group.steward_nodes.id
  source_image_id           = var.approved_steward_image_id
  disk_encryption_set_id    = azurerm_disk_encryption_set.steward_nodes.id
  admin_ssh_public_key      = var.break_glass_ssh_public_key

  release_version  = var.steward_release
  installer_url    = var.steward_installer_url
  installer_sha256 = var.steward_installer_sha256
  release_mirror   = var.steward_release_mirror
}
```

The approved image must include Docker, gVisor, systemd, cloud-init, curl,
`timeout`, and `sha256sum`. The system-assigned identity has no Azure role; it is a
future attestation anchor, not ambient cloud authority.

First boot stages the exact release but does not enroll the VM as a Steward node.
Deliver one short-lived, node-specific enrollment package through a separate
approved channel and require the node doctor to pass before placement.

Upgrade mode is deliberately `Manual`. Azure requires a valid Application Health
signal for safe rolling upgrade and automatic repair, while Steward's complete
readiness check is local and authenticated. Treating raw VM health as node
readiness would allow an installed but unenrolled node to pass. Terraform also
ignores later `instances` changes. Apply model changes or capacity changes to
explicit, already drained instances until the attested enrollment and health
integration is qualified.
