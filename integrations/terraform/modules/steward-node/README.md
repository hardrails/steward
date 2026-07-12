# Steward node Terraform bootstrap module

This provider-neutral module renders secret-free cloud-init. It pins the installer
by SHA-256 and the release by exact tag, then either stages Steward or creates a
loopback-only node. Pass `module.steward.cloud_init` to your cloud server's user-data
field.

Use `bootstrap_mode = "stage"` for enterprise nodes. Deliver the enrollment
credentials later through an authenticated, ephemeral channel and run Steward's
transactional configurator. Do not pass credentials, private keys, tokens, or secret
manager results into this module: Terraform records inputs and rendered user data in
state.

`bootstrap_mode = "local"` is useful for an isolated evaluation server. It generates
node-local tokens on the host and exposes only loopback services.

This module provisions software, not agent instances. Agent lifecycle remains in
Steward because it uses signed generation fences, receipts, and runtime
reconciliation that do not map safely to Terraform's refresh model yet.
