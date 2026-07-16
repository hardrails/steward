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
  description = "Credential-free HTTP(S) URL of install-control.sh. Query strings and fragments are forbidden."
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
  description = "Out-of-band SHA-256 of install-control.sh."
  type        = string

  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.installer_sha256))
    error_message = "installer_sha256 must contain exactly 64 lowercase hexadecimal characters."
  }
}

variable "manifest_sha256" {
  description = "Out-of-band SHA-256 of the exact release checksums.txt manifest that binds the controller archives."
  type        = string

  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.manifest_sha256))
    error_message = "manifest_sha256 must contain exactly 64 lowercase hexadecimal characters."
  }
}

variable "release_mirror" {
  description = "Optional Steward Control archive and checksum-manifest URLs from an operator-controlled mirror; manifest_sha256 remains the required independent manifest pin."
  type = object({
    archive_url    = string
    archive_sha256 = string
    manifest_url   = string
  })
  default = null

  validation {
    condition = var.release_mirror == null ? true : (
      length(var.release_mirror.archive_url) <= 512 &&
      can(regex("^[\\x21-\\x7E]+$", var.release_mirror.archive_url)) &&
      can(regex("^https?://[^/@[:space:]?#]+/[^[:space:]?#]+\\.tar\\.gz$", var.release_mirror.archive_url)) &&
      length(regexall("^https?://[^/]*@", var.release_mirror.archive_url)) == 0 &&
      can(regex("^[a-f0-9]{64}$", var.release_mirror.archive_sha256)) &&
      length(var.release_mirror.manifest_url) <= 512 &&
      can(regex("^[\\x21-\\x7E]+$", var.release_mirror.manifest_url)) &&
      can(regex("^https?://[^/@[:space:]?#]+(/[^[:space:]?#]*)?$", var.release_mirror.manifest_url)) &&
      length(regexall("^https?://[^/]*@", var.release_mirror.manifest_url)) == 0
    )
    error_message = "release_mirror must be null or contain credential-free ASCII HTTP(S) archive/manifest URLs no longer than 512 characters and without query strings, fragments, or whitespace, plus an independent lowercase archive SHA-256 pin; archive_url must end in .tar.gz."
  }
}
