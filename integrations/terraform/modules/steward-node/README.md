# Steward node Terraform bootstrap module

This provider-neutral module renders one-shot cloud-init designed for non-secret
bootstrap. It pins the installer by SHA-256 and the release by exact tag, then either
stages Steward or creates a loopback-only node. Pass `module.steward.cloud_init` to
your cloud server's user-data field. A completion marker prevents accidental
bootstrap replay. The marker records the version read from the installed
`release.json`; bootstrap fails if that manifest does not match `release_version`.

For an operator-controlled mirror, set `release_mirror` with the exact package URL,
checksum-manifest URL, and independent SHA-256 pins for both files. Cloud-init
verifies both downloads before invoking the installer; the installer then verifies
that the pinned manifest authorizes the package. Leaving `release_mirror = null`
uses the public release endpoint.

```hcl
release_mirror = {
  artifact_url    = "https://mirror.example/steward-node_<tag>_amd64.deb"
  artifact_sha256 = "<package sha256>"
  manifest_url    = "https://mirror.example/checksums.txt"
  manifest_sha256 = "<manifest sha256>"
}
```

Use `bootstrap_mode = "stage"` for production nodes that will enroll later. Deliver
the node credential, evidence config, receipt key pair, CA, and signed-admission
trust through an authenticated, short-lived channel, then run Steward's
all-or-nothing node configurator. The receipt key must be the same key used during
enrollment proof-of-possession. Do not pass credentials, private keys, tokens, or
secret-manager results into this module. Do not put credentials in URL user
information or query strings. Terraform records every input and rendered user data
in state, and a cloud provider may retain user-data history. Treat every module
value as recoverable by those administrators.

`bootstrap_mode = "local"` is useful for an isolated evaluation server. It generates
node-local tokens on the host and exposes only loopback services.

`install_gvisor` is intentionally rejected with staged bootstrap because staging
must not require a live Docker daemon. Preinstall gVisor in the machine image for
production nodes that will enroll later, or use local bootstrap with a pinned
`gvisor_version`.

This module provisions software, not agent instances. Terraform can retry or replay
a resource action while reconciling desired and observed state. It cannot safely
choose a new signed instance generation or determine the outcome of a partially
applied runtime mutation. Steward therefore retains agent lifecycle, replay fences,
receipts, and runtime reconciliation.
