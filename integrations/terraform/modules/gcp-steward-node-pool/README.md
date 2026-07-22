# Google Cloud Steward node pool

This module creates a private regional Managed Instance Group from existing
network, image, service-account, and Cloud KMS resources. Instances have no
external IP, project SSH keys are blocked, OS Login is enabled, Shielded VM secure
boot/vTPM/integrity monitoring are enabled, and image changes roll out with one
surge VM and zero planned unavailability.

```hcl
module "steward_nodes" {
  source = "./steward/integrations/terraform/modules/gcp-steward-node-pool"

  name                 = "agents-prod"
  project_id           = var.project_id
  region               = var.region
  subnetwork_self_link = google_compute_subnetwork.private.self_link
  source_image         = var.approved_steward_image
  service_account_email = google_service_account.steward_nodes.email
  kms_key_self_link    = google_kms_crypto_key.steward_nodes.id

  release_version  = var.steward_release
  installer_url    = var.steward_installer_url
  installer_sha256 = var.steward_installer_sha256
  release_mirror   = var.steward_release_mirror
}
```

The service account needs only the access required by the surrounding network and
approved artifact path; this module grants no IAM role and requests no OAuth scope.
The image must include Docker, gVisor, systemd, cloud-init, curl, `timeout`, and
`sha256sum`.

First boot stages the exact release but does not enroll the VM as a Steward node.
Deliver one short-lived, node-specific enrollment package through a separate
approved channel and require the node doctor to pass before placement.

The group intentionally has no application autohealing or autoscaler. A Compute
Engine VM can be healthy while Steward is not enrolled, and automatic scale-in can
terminate an active agent without a drain. Add those behaviors only after their
health and termination actions are joined to Steward's readiness, cordon, and drain
contracts.
