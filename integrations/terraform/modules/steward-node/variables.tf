variable "release_version" {
  description = "Exact Steward release tag; latest is deliberately forbidden."
  type        = string
  validation {
    condition     = can(regex("^v[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z.-]+)?$", var.release_version))
    error_message = "release_version must be an exact vMAJOR.MINOR.PATCH tag."
  }
}
variable "installer_url" {
  description = "HTTPS or private HTTP URL of install-steward.sh."
  type        = string
  validation {
    condition     = can(regex("^https?://[^[:space:]]+$", var.installer_url))
    error_message = "installer_url must be one HTTP(S) URL without whitespace."
  }
}

variable "installer_sha256" {
  description = "Out-of-band SHA-256 of install-steward.sh."
  type        = string
  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.installer_sha256))
    error_message = "installer_sha256 must contain 64 lowercase hexadecimal characters."
  }
}

variable "release_mirror" {
  description = "Optional fully pinned release package and checksum manifest from an operator-controlled mirror."
  type = object({
    artifact_url    = string
    artifact_sha256 = string
    manifest_url    = string
    manifest_sha256 = string
  })
  default = null
  validation {
    condition = var.release_mirror == null || (
      can(regex("^https?://[^[:space:]]+\\.(deb|rpm|tar\\.gz)([?#][^[:space:]]*)?$", var.release_mirror.artifact_url)) &&
      can(regex("^[a-f0-9]{64}$", var.release_mirror.artifact_sha256)) &&
      can(regex("^https?://[^[:space:]]+$", var.release_mirror.manifest_url)) &&
      can(regex("^[a-f0-9]{64}$", var.release_mirror.manifest_sha256))
    )
    error_message = "release_mirror must contain HTTP(S) artifact/manifest URLs and lowercase SHA-256 pins; the artifact URL must end in .deb, .rpm, or .tar.gz."
  }
}

variable "bootstrap_mode" {
  description = "stage installs files without credentials; local creates a loopback-only node."
  type        = string
  default     = "stage"
  validation {
    condition     = contains(["stage", "local"], var.bootstrap_mode)
    error_message = "bootstrap_mode must be stage or local."
  }
}

variable "install_gvisor" {
  description = "Allow the Steward installer to install/register gVisor when missing."
  type        = bool
  default     = false
}

variable "gvisor_version" {
  description = "Pinned official gVisor release version; latest is forbidden in repeatable builds."
  type        = string
  default     = ""
  validation {
    condition     = var.gvisor_version == "" || can(regex("^[0-9]{8}(?:\\.[0-9]+)?$", var.gvisor_version))
    error_message = "gvisor_version must be empty or a pinned YYYYMMDD[.N] release."
  }
}
