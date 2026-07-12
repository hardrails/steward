locals {
  install_mode_args = var.bootstrap_mode == "stage" ? "--stage-only" : "--local-only"
  gvisor_args       = var.install_gvisor ? "--install-gvisor --gvisor-version ${var.gvisor_version}" : ""
  bootstrap_script  = <<-SCRIPT
    #!/usr/bin/env bash
    set -Eeuo pipefail
    umask 077
    installer_url=$(printf '%s' '${base64encode(var.installer_url)}' | base64 -d)
    expected=$(printf '%s' '${base64encode(var.installer_sha256)}' | base64 -d)
    work=$(mktemp -d /var/tmp/steward-bootstrap.XXXXXX)
    trap 'rm -rf "$work"' EXIT
    curl --fail --silent --show-error --location --proto '=https,http' "$installer_url" -o "$work/install-steward.sh"
    actual=$(sha256sum "$work/install-steward.sh" | awk '{print $1}')
    if [[ $actual != "$expected" ]]; then
      echo 'steward-bootstrap: installer checksum mismatch' >&2
      exit 1
    fi
    chmod 0700 "$work/install-steward.sh"
    bash "$work/install-steward.sh" --non-interactive --yes \
      --version '${var.release_version}' ${local.install_mode_args} ${local.gvisor_args}
    echo 'steward-bootstrap: completed ${var.bootstrap_mode} bootstrap for ${var.release_version}'
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
