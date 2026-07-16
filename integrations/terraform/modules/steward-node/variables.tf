variable "release_version" {
  description = "Exact Steward semantic release tag; latest and build metadata are deliberately forbidden."
  type        = string
  validation {
    condition = (
      length(var.release_version) <= 128 &&
      can(regex("^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\\.([0-9A-Za-z-]+))*)?$", var.release_version)) &&
      alltrue([
        for identifier in split(".", join("-", slice(split("-", var.release_version), 1, length(split("-", var.release_version))))) :
        length(regexall("^[0-9]+$", identifier)) == 0 || identifier == "0" || !startswith(identifier, "0")
      ])
    )
    error_message = "release_version must be one exact semantic vMAJOR.MINOR.PATCH tag no longer than 128 characters; latest, build metadata, and numeric prerelease identifiers with leading zeroes are not allowed."
  }
}
variable "installer_url" {
  description = "Credential-free HTTP(S) URL of install-steward.sh. Query strings and fragments are forbidden because Terraform records this value in state."
  type        = string
  validation {
    condition = (
      length(var.installer_url) <= 512 &&
      can(regex("^[\\x21-\\x7E]+$", var.installer_url)) &&
      can(regex("^https?://[^/@[:space:]?#]+(/[^[:space:]?#]*)?$", var.installer_url)) &&
      length(regexall("^https?://[^/]*@", var.installer_url)) == 0
    )
    error_message = "installer_url must be one credential-free ASCII HTTP(S) URL no longer than 512 characters and without whitespace, a query string, or a fragment."
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
  description = "Optional fully pinned release package and checksum manifest from an operator-controlled mirror. URLs cannot contain credentials, query strings, or fragments because Terraform records them in state."
  type = object({
    artifact_url    = string
    artifact_sha256 = string
    manifest_url    = string
    manifest_sha256 = string
  })
  default = null
  validation {
    condition = var.release_mirror == null ? true : (
      length(var.release_mirror.artifact_url) <= 512 &&
      can(regex("^[\\x21-\\x7E]+$", var.release_mirror.artifact_url)) &&
      can(regex("^https?://[^/@[:space:]?#]+/[^[:space:]?#]+\\.(deb|rpm|tar\\.gz)$", var.release_mirror.artifact_url)) &&
      length(regexall("^https?://[^/]*@", var.release_mirror.artifact_url)) == 0 &&
      can(regex("^[a-f0-9]{64}$", var.release_mirror.artifact_sha256)) &&
      length(var.release_mirror.manifest_url) <= 512 &&
      can(regex("^[\\x21-\\x7E]+$", var.release_mirror.manifest_url)) &&
      can(regex("^https?://[^/@[:space:]?#]+(/[^[:space:]?#]*)?$", var.release_mirror.manifest_url)) &&
      length(regexall("^https?://[^/]*@", var.release_mirror.manifest_url)) == 0 &&
      can(regex("^[a-f0-9]{64}$", var.release_mirror.manifest_sha256))
    )
    error_message = "release_mirror must contain credential-free ASCII HTTP(S) artifact/manifest URLs no longer than 512 characters and without whitespace, query strings, or fragments, plus lowercase SHA-256 pins; artifact_url must end in .deb, .rpm, or .tar.gz."
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
    condition     = length(var.gvisor_version) <= 64 && (var.gvisor_version == "" || can(regex("^[0-9]{8}(?:\\.[0-9]+)?$", var.gvisor_version)))
    error_message = "gvisor_version must be empty or a pinned YYYYMMDD[.N] release."
  }
}
