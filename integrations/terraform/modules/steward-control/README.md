# Steward Control Terraform bootstrap module

This provider-neutral module renders secret-free cloud-init for the bundled
Steward Control service. It verifies `install-control.sh` against an independent
SHA-256 pin, verifies the release checksum manifest against a second required
independent pin, installs one exact semantic release, and starts the controller
on `127.0.0.1:8443`. It uses no Terraform provider and creates no cloud resources.

The installer creates or safely recovers the first site-administrator token at
`/root/steward-control-admin.token`. The file is root-owned, mode `0600`, and
created without overwriting an existing path. Bootstrap requires root ownership,
root group, mode `0600`, and one hard link. Before recording completion,
bootstrap reads the bearer into memory and proves it against the controller's
bounded tenant-list API on literal loopback. Before every request and again after a
successful response, it requires the active systemd `MainPID`, installed binary,
service UID, exact process arguments, and root-owned loopback configuration to
agree. The pinned installer has already proved the same bearer against an
ephemeral instance of the installed binary before publishing it. The fixed-listener
proof disables proxies, redirects, and curl configuration files, and sends the
bearer through curl's standard-input configuration so the value does not enter
process arguments. The module exposes the path, never the token value; no token
enters Terraform state, user-data, or bootstrap logs.

## Use the module

Pass `module.steward_control.cloud_init` to the user-data field of a systemd Linux
server resource:

```hcl
variable "steward_release_tag" {
  type = string
}

variable "steward_control_installer_sha256" {
  type = string
}

variable "steward_control_manifest_sha256" {
  type = string
}

module "steward_control" {
  source = "./integrations/terraform/modules/steward-control"

  release_version = var.steward_release_tag
  installer_url = format(
    "https://github.com/hardrails/steward/releases/download/%s/install-control.sh",
    var.steward_release_tag,
  )
  installer_sha256 = var.steward_control_installer_sha256
  manifest_sha256  = var.steward_control_manifest_sha256
}
```

Obtain the installer and `checksums.txt` digests through a channel independent of
their download URLs. The module always downloads and verifies the exact-tag
manifest before running the installer, then passes that local manifest to the
installer so a mutable release origin cannot substitute both the manifest and
controller archive. The tag must be an exact `vMAJOR.MINOR.PATCH` semantic release
tag. Each fetch disables curl configuration files, runs with an operating-system
file-size limit, removes partial failures, and accepts only a non-empty, single-link
regular file within that limit before checksum verification. `latest`, build
metadata, whitespace, URL user information, query strings, and fragments are
rejected because those URL fields commonly carry credentials.
Validation cannot tell whether an arbitrary path segment is a secret, so use only
public or non-secret internal paths. Release tags are limited to 128 characters and
each URL to 512 printable ASCII characters. The cloud-init document must
remain at or below 16 KiB; its base64 encoding must remain at or below 21,848 bytes.
For a provider field that requires encoded user data, use
`base64encode(module.steward_control.cloud_init)`.

The target must be an `amd64` or `arm64` systemd Linux image with cloud-init, Bash,
curl, and the standard GNU Linux utilities checked by `install-control.sh`. This
module does not run a package manager or silently change the base image. A missing
prerequisite fails bootstrap before a completion marker is written.

### Use an operator-controlled mirror

Set all three `release_mirror` fields to use a private or air-gapped artifact
mirror. Keep the required `manifest_sha256` at module level. The archive filename
must match the exact release and host architecture, for example
`steward-control_<tag>_linux_amd64.tar.gz` or
`steward-control_<tag>_linux_arm64.tar.gz`.

```hcl
release_mirror = {
  archive_url = format(
    "https://mirror.example/steward-control_%s_linux_amd64.tar.gz",
    var.steward_release_tag,
  )
  archive_sha256 = var.steward_control_archive_sha256
  manifest_url   = "https://mirror.example/checksums.txt"
}
```

Cloud-init independently verifies the installer, controller archive, and checksum
manifest before invoking the installer. The installer then confirms that the
manifest authorizes the archive. When `release_mirror` is set, the bootstrap has
no public artifact fallback: a missing, unreachable, misnamed, or mismatched
mirror file fails the installation.

## Retrieve the administrator credential

After cloud-init succeeds, read `site_admin_token_path` or
`operator_handoff.token_path` from Terraform output. These outputs contain only
the fixed path `/root/steward-control-admin.token`. Retrieve that file through an
authenticated host channel such as SSH, move it into protected operator storage,
then remove the host copy. Reach the loopback API through an authenticated SSH
tunnel or configure a remote TLS endpoint separately.

Do not use a Terraform provisioner to copy or print the token. Provisioner command
lines, output, and connection data can be retained in Terraform or automation
logs. Do not add the token, a TLS private key, a certificate-authority key, an
enrollment capability, or any secret-manager result to this module.

## Terraform and cloud user-data are not secret stores

Terraform records module inputs and rendered cloud-init in state. A remote state
backend, CI system, plan artifact, or cloud provider may retain that user-data for
the lifetime of the server or longer. Anyone who administers those systems may be
able to read it. This module therefore accepts only non-secret download locations,
independent checksums, and an exact release identity. Its outputs contain paths
and instructions, never credential contents.

The first bootstrap is deliberately loopback-only. Deliver a server certificate,
its private key, and any private CA material through a separate authenticated
secret-delivery process. Then reconfigure the controller with the verified
`install-control.sh` workflow. Do not expose the loopback HTTP listener directly
on a network.

Host root and the systemd manager remain trusted. The process checks narrow the
window in which an unrelated local listener could receive the bearer, but they do
not defend against an actor that controls the kernel, `/proc`, or systemd itself.
Use a host and cloud trust model appropriate for site-administrator authority.

## Bootstrap is not an upgrade mechanism

The root-only completion marker records both the release reported by the installed
controller and the installed binary's SHA-256 digest. A replay with the same
release validates that identity and exits without downloading or running the
installer. An interrupted run without a completion marker re-enters the installer's
bounded recovery path and cannot complete until the on-host bearer authenticates
to that controller. A replay with a different `release_version` fails; changing
user-data never upgrades or downgrades an existing controller.

Back up the controller state and use Steward's explicit transactional installer
for upgrades. Do not edit, remove, or repurpose the completion marker to force an
upgrade.

Some cloud providers replace a server when its user-data changes. Treat these
bootstrap inputs as immutable for an initialized controller, protect
`/var/lib/steward-control` with the documented backup process, and use the cloud
resource's deletion protection when appropriate. A replacement server is a new
controller, not a safe in-place upgrade.

## Inputs and outputs

| Input | Required | Meaning |
| --- | --- | --- |
| `release_version` | yes | Exact semantic Steward release tag, at most 128 characters. |
| `installer_url` | yes | Credential-free URL of `install-control.sh`, at most 512 characters. |
| `installer_sha256` | yes | Independently obtained lowercase SHA-256 of the installer. |
| `manifest_sha256` | yes | Independently obtained lowercase SHA-256 of the exact release `checksums.txt`. |
| `release_mirror` | no | Controller archive URL and SHA-256 plus manifest URL, each URL at most 512 characters; `null` uses the public exact-tag endpoints with the required manifest pin. |

| Output | Meaning |
| --- | --- |
| `cloud_init` | Secret-free cloud-init document for server user-data. |
| `control_url` | On-host loopback API URL. |
| `site_admin_token_path` | Non-secret path of the first administrator token. |
| `bootstrap_completion_path` | Non-secret path of the root-only identity marker. |
| `operator_handoff` | Token path, tunnel target, and next-step instructions without secret content. |

## Verify the module

Run the hermetic static checks and, when Terraform is installed, formatting,
validation, render, and negative-input tests:

```console
./integrations/terraform/modules/steward-control/tests/test.sh
```
