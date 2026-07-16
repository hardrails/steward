locals {
  control_address       = "127.0.0.1:8443"
  control_url           = "http://${local.control_address}"
  admin_token_path      = "/root/steward-control-admin.token"
  completion_stamp_path = "/var/lib/steward-control-bootstrap/complete"
  max_cloud_init_bytes  = 16384
  max_cloud_init_b64    = 21848
  mirror_enabled        = var.release_mirror != null
  default_manifest_url  = "https://github.com/hardrails/steward/releases/download/${var.release_version}/checksums.txt"
  archive_url           = try(var.release_mirror.archive_url, "")
  archive_sha256        = try(var.release_mirror.archive_sha256, "")
  manifest_url          = try(var.release_mirror.manifest_url, local.default_manifest_url)

  bootstrap_script = <<-SCRIPT
    #!/bin/bash -p
    set -Eeuo pipefail
    if ! shopt -q -o privileged; then
      echo 'steward-control-bootstrap: privileged Bash mode (-p) is required' >&2
      exit 1
    fi
    PATH=/usr/sbin:/usr/bin:/sbin:/bin
    export PATH LC_ALL=C LANG=C
    unset BASH_ENV CDPATH CURL_HOME ENV GLOBIGNORE XDG_CONFIG_HOME
    unset CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR
    unset TAR_OPTIONS GZIP POSIXLY_CORRECT TMPDIR
    IFS=$' \t\n'
    umask 077

    readonly expected_release='${var.release_version}'
    readonly control_address='${local.control_address}'
    readonly control_url='${local.control_url}'
    readonly admin_token_path='${local.admin_token_path}'
    readonly control_config=/etc/steward-control/control.env
    readonly control_state_dir=/var/lib/steward-control
    readonly control_auth_key=/var/lib/steward-control/auth.key
    readonly control_witness_private_key=/var/lib/steward-control/witness.private.pem
    readonly control_witness_public_key=/var/lib/steward-control/witness.public.pem
    readonly control_service=steward-control.service
    readonly proc_root=/proc
    readonly stamp_dir=/var/lib/steward-control-bootstrap
    readonly stamp=$stamp_dir/complete
    readonly release_dir=/opt/steward-control/releases/$expected_release
    readonly release_binary=$release_dir/steward-control
    readonly current_link=/opt/steward-control/current
    readonly binary_link=/usr/local/bin/steward-control
    readonly bootstrap_runtime_dir=/run/steward-control-terraform
    readonly bootstrap_lock=$bootstrap_runtime_dir/bootstrap.lock

    fail() {
      echo "steward-control-bootstrap: $1" >&2
      exit 1
    }

    if (( EUID != 0 )); then
      fail 'cloud-init bootstrap must run as root'
    fi
    for command in base64 bash basename chmod chown curl flock grep id install mktemp mv readlink rm sed sha256sum sleep stat systemctl timeout uname wc; do
      command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
    done
    [[ $(uname -s) == Linux ]] || fail 'Steward Control bootstrap requires Linux'

    if [[ -e $bootstrap_runtime_dir || -L $bootstrap_runtime_dir ]]; then
      [[ -d $bootstrap_runtime_dir && ! -L $bootstrap_runtime_dir &&
        $(stat -c '%u:%g:%a' -- "$bootstrap_runtime_dir") == 0:0:700 ]] ||
        fail 'private bootstrap runtime directory has unsafe metadata'
    else
      install -d -o root -g root -m 0700 "$bootstrap_runtime_dir"
    fi
    if [[ -e $bootstrap_lock || -L $bootstrap_lock ]]; then
      [[ -f $bootstrap_lock && ! -L $bootstrap_lock &&
        $(stat -c '%u:%g:%a:%h' -- "$bootstrap_lock") == 0:0:600:1 ]] ||
        fail 'private bootstrap lock has unsafe metadata'
    else
      install -o root -g root -m 0600 /dev/null "$bootstrap_lock"
    fi
    exec 9<>"$bootstrap_lock"
    [[ $(stat -Lc '%u:%g:%a:%h' -- /proc/$$/fd/9) == 0:0:600:1 ]] ||
      fail 'opened bootstrap lock has unsafe metadata'
    flock -w 30 9 || fail 'another Steward Control bootstrap is active'

    if [[ -e $stamp_dir || -L $stamp_dir ]]; then
      if [[ ! -d $stamp_dir || -L $stamp_dir || $(stat -c '%u:%a' -- "$stamp_dir") != 0:700 ]]; then
        fail 'completion directory must be a root-owned, non-symlink directory with mode 0700'
      fi
    else
      install -d -o root -g root -m 0700 "$stamp_dir"
    fi

    installed_digest=
    validate_installed_release() {
      local expected_digest=$1 directory_mode binary_mode actual_digest version_output
      if [[ ! -d $release_dir || -L $release_dir || $(stat -c '%u' -- "$release_dir") != 0 ]]; then
        fail "installed release directory is missing or unsafe: $release_dir"
      fi
      directory_mode=$(stat -c '%a' -- "$release_dir")
      if (( (8#$directory_mode & 0022) != 0 )); then
        fail 'installed release directory must not be group- or world-writable'
      fi
      if [[ ! -f $release_binary || -L $release_binary || $(stat -c '%u' -- "$release_binary") != 0 ]]; then
        fail "installed controller binary is missing or unsafe: $release_binary"
      fi
      binary_mode=$(stat -c '%a' -- "$release_binary")
      if (( (8#$binary_mode & 0022) != 0 )); then
        fail 'installed controller binary must not be group- or world-writable'
      fi
      if (( $(stat -c '%s' -- "$release_binary") <= 0 || $(stat -c '%s' -- "$release_binary") > 268435456 )); then
        fail 'installed controller binary has an invalid size'
      fi
      actual_digest=$(sha256sum "$release_binary" | sed 's/[[:space:]].*$//')
      [[ $actual_digest =~ ^[a-f0-9]{64}$ ]] || fail 'installed controller binary has an invalid digest'
      if [[ -n $expected_digest && $actual_digest != "$expected_digest" ]]; then
        fail 'installed controller binary no longer matches the completed bootstrap identity'
      fi
      version_output=$(mktemp "$stamp_dir/.version.XXXXXX")
      if ! (ulimit -f 8; exec timeout -k 1 5 "$release_binary" -version) >"$version_output" 2>&1; then
        rm -f -- "$version_output"
        fail 'installed controller version check failed or exceeded its bound'
      fi
      if (( $(wc -c <"$version_output") != $${#expected_release} + 17 )) ||
        ! grep -Fqx -- "steward-control $expected_release" "$version_output"; then
        rm -f -- "$version_output"
        fail 'installed controller reports an unexpected release'
      fi
      rm -f -- "$version_output"
      [[ -L $current_link && $(readlink -- "$current_link") == "$release_dir" ]] || fail 'current controller release link is missing or unexpected'
      [[ -L $binary_link && $(readlink -- "$binary_link") == "$current_link/steward-control" ]] || fail 'controller command link is missing or unexpected'
      installed_digest=$actual_digest
    }

    if [[ -e $stamp || -L $stamp ]]; then
      if [[ ! -f $stamp || -L $stamp || $(stat -c '%u:%a' -- "$stamp") != 0:600 || $(stat -c '%s' -- "$stamp") -gt 256 ]]; then
        fail 'completion marker must be a bounded root-owned regular file with mode 0600'
      fi
      release_line=
      digest_line=
      {
        IFS= read -r release_line || fail 'completion marker is truncated'
        IFS= read -r digest_line || fail 'completion marker is truncated'
        if IFS= read -r _; then fail 'completion marker has unexpected data'; fi
      } <"$stamp"
      [[ $release_line == release=* ]] || fail 'completion marker has no release identity'
      [[ $digest_line == binary_sha256=* ]] || fail 'completion marker has no binary identity'
      marker_release=$(printf '%s' "$release_line" | sed 's/^release=//')
      marker_digest=$(printf '%s' "$digest_line" | sed 's/^binary_sha256=//')
      [[ $marker_digest =~ ^[a-f0-9]{64}$ ]] || fail 'completion marker has an invalid binary identity'
      if [[ $marker_release != "$expected_release" ]]; then
        fail "bootstrap completed release $marker_release; cloud-init does not upgrade to $expected_release"
      fi
      validate_installed_release "$marker_digest"
      echo "steward-control-bootstrap: release $marker_release already completed; refusing to replay first-boot installation"
      exit 0
    fi

    installer_url=$(printf '%s' '${base64encode(var.installer_url)}' | base64 -d)
    installer_expected=$(printf '%s' '${base64encode(var.installer_sha256)}' | base64 -d)
    readonly mirror_enabled='${local.mirror_enabled}'
    work=$(mktemp -d /run/steward-control-bootstrap.XXXXXX)
    [[ ! -L $work && $(stat -c '%u:%g:%a' -- "$work") == 0:0:700 ]] ||
      fail 'private bootstrap staging directory could not be secured'
    trap 'rm -rf "$work"' EXIT

    fetch() {
      local url=$1 output=$2 limit=$3 file_blocks size links
      [[ $limit =~ ^[1-9][0-9]*$ ]] || return 2
      file_blocks=$(( (limit + 1023) / 1024 ))
      rm -f -- "$output"
      if ! (
        ulimit -c 0 || exit 1
        ulimit -f "$file_blocks" || exit 1
        exec curl -q --proto '=https,http' --proto-redir '=https,http' --location --fail --silent --show-error \
          --retry 3 --retry-connrefused --max-time 180 --max-filesize "$limit" --output "$output" "$url"
      ); then
        rm -f -- "$output"
        return 1
      fi
      if [[ ! -f $output || -L $output ]]; then
        rm -f -- "$output"
        return 1
      fi
      links=$(stat -c '%h' -- "$output" 2>/dev/null) || {
        rm -f -- "$output"
        return 1
      }
      size=$(stat -c '%s' -- "$output" 2>/dev/null) || {
        rm -f -- "$output"
        return 1
      }
      if [[ $links != 1 || ! $size =~ ^[0-9]+$ ]] || (( size <= 0 || size > limit )); then
        rm -f -- "$output"
        return 1
      fi
    }
    verify() {
      local file=$1 expected=$2 actual
      actual=$(sha256sum "$file" | sed 's/[[:space:]].*$//')
      [[ $actual == "$expected" ]] || fail "checksum mismatch for $(basename -- "$file")"
    }

    validate_control_config() {
      local expected actual size
      [[ -f $control_config && ! -L $control_config ]] || return 1
      [[ $(stat -c '%u:%g:%a:%h' -- "$control_config" 2>/dev/null) == 0:0:600:1 ]] || return 1
      printf -v expected 'STEWARD_CONTROL_ADDR=%s\nSTEWARD_CONTROL_STATE_DIR=%s\nSTEWARD_CONTROL_AUTH_KEY_FILE=%s\nSTEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE=%s\nSTEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE=%s\nSTEWARD_CONTROL_TLS_CERT_FILE=\nSTEWARD_CONTROL_TLS_KEY_FILE=\nSTEWARD_CONTROL_ENABLE_METRICS=false\nSTEWARD_CONTROL_NODE_STALE_AFTER=2m\nSTEWARD_CONTROL_EVIDENCE_STALE_AFTER=5m\nSTEWARD_CONTROL_COMMAND_OVERDUE_AFTER=5m\nSTEWARD_CONTROL_CAPACITY_WARNING_PERCENT=80' \
        "$control_address" "$control_state_dir" "$control_auth_key" \
        "$control_witness_private_key" "$control_witness_public_key"
      size=$(stat -c '%s' -- "$control_config" 2>/dev/null) || return 1
      (( size == $${#expected} + 1 )) || return 1
      actual=$(<"$control_config")
      [[ $actual == "$expected" ]]
    }

    controller_pid=
    controller_uid=
    process_arguments_match() {
      local pid=$1 index argument
      local -a actual=() expected=(
        "$binary_link"
        "-addr=$control_address"
        "-state-dir=$control_state_dir"
        "-auth-key-file=$control_auth_key"
        "-witness-private-key-file=$control_witness_private_key"
        "-witness-public-key-file=$control_witness_public_key"
        -tls-cert-file=
        -tls-key-file=
        -enable-metrics=false
        -node-stale-after=2m
        -evidence-stale-after=5m
        -command-overdue-after=5m
        -capacity-warning-percent=80
      )
      [[ -r $proc_root/$pid/cmdline ]] || return 1
      while IFS= read -r -d '' argument; do actual+=("$argument"); done <"$proc_root/$pid/cmdline"
      (( $${#actual[@]} == $${#expected[@]} )) || return 1
      for index in "$${!expected[@]}"; do
        [[ $${actual[$index]} == "$${expected[$index]}" ]] || return 1
      done
    }

    capture_controller_identity() {
      local pid uid executable pid_uid
      systemctl is-active --quiet "$control_service" >/dev/null 2>&1 || return 1
      pid=$(systemctl show --property MainPID --value "$control_service" 2>/dev/null) || return 1
      [[ $pid =~ ^[0-9]+$ ]] && (( pid > 1 )) || return 1
      executable=$(readlink -f -- "$proc_root/$pid/exe" 2>/dev/null) || return 1
      [[ $executable == "$release_binary" ]] || return 1
      process_arguments_match "$pid" || return 1
      uid=$(id -u steward-control 2>/dev/null) || return 1
      [[ $uid =~ ^[0-9]+$ ]] && (( uid > 0 )) || return 1
      pid_uid=$(stat -c '%u' -- "$proc_root/$pid" 2>/dev/null) || return 1
      [[ $pid_uid == "$uid" ]] || return 1
      validate_control_config || return 1
      controller_pid=$pid
      controller_uid=$uid
    }

    controller_identity_matches() {
      local expected_pid=$1 expected_uid=$2 pid executable pid_uid
      systemctl is-active --quiet "$control_service" >/dev/null 2>&1 || return 1
      pid=$(systemctl show --property MainPID --value "$control_service" 2>/dev/null) || return 1
      [[ $pid == "$expected_pid" ]] || return 1
      executable=$(readlink -f -- "$proc_root/$pid/exe" 2>/dev/null) || return 1
      [[ $executable == "$release_binary" ]] || return 1
      process_arguments_match "$pid" || return 1
      pid_uid=$(stat -c '%u' -- "$proc_root/$pid" 2>/dev/null) || return 1
      [[ $pid_uid == "$expected_uid" ]]
    }

    prove_bootstrap_token() {
      local token='' token_bytes='' response='' status='' response_bytes='' proven_pid='' proven_uid=''
      set +x
      controller_pid=
      controller_uid=
      capture_controller_identity || return 1
      proven_pid=$controller_pid
      proven_uid=$controller_uid
      token_bytes=$(wc -c <"$admin_token_path") || return 1
      IFS= read -r token <"$admin_token_path" || return 1
      if [[ ! $token =~ ^steward_cp_v1_bootstrap-cred-[a-f0-9]{32}_[A-Za-z0-9_-]{43}$ ]] ||
        (( token_bytes != $${#token} + 1 )); then
        unset token
        return 1
      fi
      response=$work/site-admin-proof.json
      for _ in {1..40}; do
        if ! controller_identity_matches "$proven_pid" "$proven_uid"; then
          unset token
          return 1
        fi
        status=
        if status=$(
          printf 'header = "Authorization: Bearer %s"\n' "$token" |
            curl -q --config - --proxy '' --noproxy '*' --proto '=http' \
              --silent --output "$response" --write-out '%%{http_code}' \
              --connect-timeout 1 --max-time 2 --max-filesize 16384 \
              "$control_url/v1/tenants?limit=1" 2>/dev/null
        ); then
          :
        else
          status=000
        fi
        case "$status" in
          200)
            unset token
            [[ -f $response && ! -L $response ]] || return 1
            response_bytes=$(wc -c <"$response") || return 1
            (( response_bytes > 0 && response_bytes <= 16384 )) || return 1
            grep -Fq '"tenants":[' "$response" || return 1
            controller_identity_matches "$proven_pid" "$proven_uid" || return 1
            return 0
            ;;
          000 | 503) sleep 0.25 ;;
          *) unset token; return 1 ;;
        esac
      done
      unset token
      return 1
    }

    fetch "$installer_url" "$work/install-control.sh" 4194304
    verify "$work/install-control.sh" "$installer_expected"
    chmod 0700 "$work/install-control.sh"
    manifest_url=$(printf '%s' '${base64encode(local.manifest_url)}' | base64 -d)
    manifest_expected=$(printf '%s' '${base64encode(var.manifest_sha256)}' | base64 -d)
    fetch "$manifest_url" "$work/checksums.txt" 4194304
    verify "$work/checksums.txt" "$manifest_expected"

    if [[ $mirror_enabled == true ]]; then
      archive_url=$(printf '%s' '${base64encode(local.archive_url)}' | base64 -d)
      archive_expected=$(printf '%s' '${base64encode(local.archive_sha256)}' | base64 -d)
      case "$(uname -m)" in
        x86_64 | amd64) goarch=amd64 ;;
        aarch64 | arm64) goarch=arm64 ;;
        *) fail "unsupported architecture: $(uname -m)" ;;
      esac
      archive_name=$(basename -- "$archive_url")
      expected_name=$(printf 'steward-control_%s_linux_%s.tar.gz' "$expected_release" "$goarch")
      [[ $archive_name == "$expected_name" ]] || fail "mirror must provide $expected_name for this host"
      fetch "$archive_url" "$work/$archive_name" 268435456
      verify "$work/$archive_name" "$archive_expected"
      /bin/bash -p "$work/install-control.sh" --non-interactive --yes \
        --version "$expected_release" --addr "$control_address" \
        --admin-token-out "$admin_token_path" \
        --artifact "$work/$archive_name" --checksums "$work/checksums.txt"
    else
      /bin/bash -p "$work/install-control.sh" --non-interactive --yes \
        --version "$expected_release" --addr "$control_address" \
        --admin-token-out "$admin_token_path" --checksums "$work/checksums.txt"
    fi

    if [[ ! -f $admin_token_path || -L $admin_token_path || $(stat -c '%u:%g:%a:%h' -- "$admin_token_path") != 0:0:600:1 ]]; then
      fail "site-administrator token was not created safely at $admin_token_path"
    fi
    token_size=$(stat -c '%s' -- "$admin_token_path")
    if (( token_size <= 0 || token_size > 4096 )); then
      fail 'site-administrator token file has an invalid size'
    fi
    if ! prove_bootstrap_token; then
      fail 'site-administrator token did not authenticate to the installed loopback controller'
    fi

    validate_installed_release ""
    stamp_tmp=$(mktemp "$stamp_dir/.complete.XXXXXX")
    printf 'release=%s\nbinary_sha256=%s\n' "$expected_release" "$installed_digest" >"$stamp_tmp"
    chown root:root "$stamp_tmp"
    chmod 0600 "$stamp_tmp"
    mv -f -- "$stamp_tmp" "$stamp"
    echo "steward-control-bootstrap: completed loopback bootstrap for $expected_release"
  SCRIPT

  cloud_init = <<-CLOUD
    #cloud-config
    package_update: false
    write_files:
      - path: /usr/local/sbin/steward-control-bootstrap
        owner: root:root
        permissions: '0700'
        encoding: gzip+base64
        content: ${base64gzip(local.bootstrap_script)}
    runcmd:
      - [ /usr/local/sbin/steward-control-bootstrap ]
  CLOUD
}
