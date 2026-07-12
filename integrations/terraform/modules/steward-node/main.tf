locals {
  install_mode_args = var.bootstrap_mode == "stage" ? "--stage-only" : "--local-only"
  gvisor_args       = var.install_gvisor ? "--install-gvisor --gvisor-version ${var.gvisor_version}" : ""
  mirror_enabled    = var.release_mirror != null
  artifact_url      = try(var.release_mirror.artifact_url, "")
  artifact_sha256   = try(var.release_mirror.artifact_sha256, "")
  manifest_url      = try(var.release_mirror.manifest_url, "")
  manifest_sha256   = try(var.release_mirror.manifest_sha256, "")
  bootstrap_script  = <<-SCRIPT
    #!/usr/bin/env bash
    set -Eeuo pipefail
    umask 077
    stamp_dir=/var/lib/steward-bootstrap
    stamp=$stamp_dir/complete
    if [[ -L $stamp_dir ]]; then
      echo 'steward-bootstrap: refusing symlinked state directory' >&2
      exit 2
    fi
    install -d -o root -g root -m 0700 "$stamp_dir"
    if [[ -e $stamp || -L $stamp ]]; then
      if [[ ! -f $stamp || -L $stamp || $(stat -c '%u:%a' "$stamp") != 0:600 ]]; then
        echo 'steward-bootstrap: refusing invalid completion marker' >&2
        exit 2
      fi
      installed=$(head -c 128 "$stamp")
      if [[ ! $installed =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
        echo 'steward-bootstrap: completion marker is malformed' >&2
        exit 2
      fi
      if [[ $installed != '${var.release_version}' ]]; then
        echo "steward-bootstrap: release $installed already completed; bootstrap does not upgrade to ${var.release_version}" >&2
        exit 2
      fi
      installed_manifest="/opt/steward/releases/$installed/release.json"
      if [[ ! -f $installed_manifest || -L $installed_manifest ]]; then
        echo "steward-bootstrap: completion marker has no valid installed manifest: $installed_manifest" >&2
        exit 2
      fi
      installed_manifest_mode=$(stat -c '%a' "$installed_manifest")
      if [[ $(stat -c '%u' "$installed_manifest") != 0 ]] || (( (8#$installed_manifest_mode & 0022) != 0 )); then
        echo 'steward-bootstrap: installed release manifest must be root-owned and not group- or world-writable' >&2
        exit 2
      fi
      manifest_version=$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' "$installed_manifest")
      if [[ $manifest_version != "$installed" ]]; then
        echo "steward-bootstrap: completion marker and installed manifest disagree" >&2
        exit 2
      fi
      echo "steward-bootstrap: release $installed already completed; refusing to replay first-boot installation"
      exit 0
    fi
    installer_url=$(printf '%s' '${base64encode(var.installer_url)}' | base64 -d)
    installer_expected=$(printf '%s' '${base64encode(var.installer_sha256)}' | base64 -d)
    mirror_enabled='${local.mirror_enabled}'
    work=$(mktemp -d /var/tmp/steward-bootstrap.XXXXXX)
    trap 'rm -rf "$work"' EXIT
    fetch() {
      curl --fail --silent --show-error --location --proto '=https,http' "$1" -o "$2"
    }
    verify() {
      local actual
      actual=$(sha256sum "$1" | awk '{print $1}')
      if [[ $actual != "$2" ]]; then
        echo "steward-bootstrap: checksum mismatch for $1" >&2
        exit 1
      fi
    }
    fetch "$installer_url" "$work/install-steward.sh"
    verify "$work/install-steward.sh" "$installer_expected"
    chmod 0700 "$work/install-steward.sh"
    if [[ $mirror_enabled == true ]]; then
      artifact_url=$(printf '%s' '${base64encode(local.artifact_url)}' | base64 -d)
      artifact_expected=$(printf '%s' '${base64encode(local.artifact_sha256)}' | base64 -d)
      manifest_url=$(printf '%s' '${base64encode(local.manifest_url)}' | base64 -d)
      manifest_expected=$(printf '%s' '${base64encode(local.manifest_sha256)}' | base64 -d)
      artifact_name=$(basename "$(printf '%s' "$artifact_url" | sed 's/[?#].*$//')")
      case "$artifact_name" in
        *.deb|*.rpm|*.tar.gz) ;;
        *) echo 'steward-bootstrap: mirrored artifact has an unsupported filename' >&2; exit 2 ;;
      esac
      fetch "$artifact_url" "$work/$artifact_name"
      fetch "$manifest_url" "$work/checksums.txt"
      verify "$work/$artifact_name" "$artifact_expected"
      verify "$work/checksums.txt" "$manifest_expected"
      bash "$work/install-steward.sh" --non-interactive --yes \
        --version '${var.release_version}' ${local.install_mode_args} ${local.gvisor_args} \
        --artifact "$work/$artifact_name" --checksums "$work/checksums.txt"
    else
      bash "$work/install-steward.sh" --non-interactive --yes \
        --version '${var.release_version}' ${local.install_mode_args} ${local.gvisor_args}
    fi
    release_manifest='/opt/steward/releases/${var.release_version}/release.json'
    if [[ ! -f $release_manifest || -L $release_manifest ]]; then
      echo "steward-bootstrap: installed release manifest is missing or invalid: $release_manifest" >&2
      exit 1
    fi
    manifest_mode=$(stat -c '%a' "$release_manifest")
    if [[ $(stat -c '%u' "$release_manifest") != 0 ]] || (( (8#$manifest_mode & 0022) != 0 )); then
      echo 'steward-bootstrap: installed release manifest must be root-owned and not group- or world-writable' >&2
      exit 1
    fi
    installed=$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' "$release_manifest")
    if [[ $installed != '${var.release_version}' ]]; then
      echo "steward-bootstrap: installed manifest reports '$${installed:-<invalid>}', expected '${var.release_version}'" >&2
      exit 1
    fi
    stamp_tmp=$(mktemp "$stamp_dir/.complete.XXXXXX")
    printf '%s\n' "$installed" > "$stamp_tmp"
    chmod 0600 "$stamp_tmp"
    mv -f "$stamp_tmp" "$stamp"
    echo "steward-bootstrap: completed ${var.bootstrap_mode} bootstrap for $installed"
  SCRIPT

  cloud_init = <<-CLOUD
    #cloud-config
    package_update: false
    write_files:
      - path: /usr/local/sbin/steward-bootstrap
        owner: root:root
        permissions: '0700'
        encoding: b64
        content: ${base64encode(local.bootstrap_script)}
    runcmd:
      - [ /usr/local/sbin/steward-bootstrap ]
  CLOUD
}
