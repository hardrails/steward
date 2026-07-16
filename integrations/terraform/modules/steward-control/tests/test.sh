#!/usr/bin/env bash
set -Eeuo pipefail

module_dir=$(cd "$(dirname "$0")/.." && pwd)
repo_root=$(cd "$module_dir/../../../.." && pwd)

require_text() {
  local file=$1 text=$2
  grep -F -- "$text" "$file" >/dev/null || {
    echo "steward-control Terraform test: missing required text '$text' in $file" >&2
    exit 1
  }
}

reject_text() {
  local file=$1 text=$2
  if grep -F -- "$text" "$file" >/dev/null; then
    echo "steward-control Terraform test: forbidden text '$text' in $file" >&2
    exit 1
  fi
}

require_text "$module_dir/main.tf" 'admin_token_path      = "/root/steward-control-admin.token"'
require_text "$module_dir/main.tf" "readonly admin_token_path='\${local.admin_token_path}'"
require_text "$module_dir/main.tf" "readonly mirror_enabled='\${local.mirror_enabled}'"
require_text "$module_dir/main.tf" "--artifact \"\$work/\$archive_name\" --checksums \"\$work/checksums.txt\""
require_text "$module_dir/main.tf" 'binary_sha256=%s'
require_text "$module_dir/main.tf" 'cloud-init does not upgrade'
require_text "$module_dir/main.tf" '127.0.0.1:8443'
require_text "$module_dir/main.tf" 'max_cloud_init_bytes  = 16384'
require_text "$module_dir/main.tf" 'max_cloud_init_b64    = 21848'
require_text "$module_dir/main.tf" '#!/bin/bash -p'
require_text "$module_dir/main.tf" "shopt -q -o privileged"
require_text "$module_dir/main.tf" 'PATH=/usr/sbin:/usr/bin:/sbin:/bin'
require_text "$module_dir/main.tf" 'unset BASH_ENV CDPATH CURL_HOME ENV GLOBIGNORE XDG_CONFIG_HOME'
require_text "$module_dir/main.tf" "timeout -k 1 5 \"\$release_binary\" -version"
require_text "$module_dir/main.tf" 'ulimit -c 0 || exit 1'
require_text "$module_dir/main.tf" "ulimit -f \"\$file_blocks\" || exit 1"
require_text "$module_dir/main.tf" "exec curl -q --proto '=https,http'"
require_text "$module_dir/main.tf" "[[ ! -f \$output || -L \$output ]]"
require_text "$module_dir/main.tf" "[[ \$links != 1 || ! \$size =~ ^[0-9]+\$ ]] || (( size <= 0 || size > limit ))"
require_text "$module_dir/main.tf" "stat -c '%u:%g:%a:%h'"
require_text "$module_dir/main.tf" "systemctl is-active --quiet \"\$control_service\""
require_text "$module_dir/main.tf" "systemctl show --property MainPID --value \"\$control_service\""
require_text "$module_dir/main.tf" "readlink -f -- \"\$proc_root/\$pid/exe\""
require_text "$module_dir/main.tf" "while IFS= read -r -d '' argument; do actual+=(\"\$argument\"); done <\"\$proc_root/\$pid/cmdline\""
require_text "$module_dir/main.tf" 'validate_control_config || return 1'
require_text "$module_dir/main.tf" "controller_identity_matches \"\$proven_pid\" \"\$proven_uid\""
require_text "$module_dir/main.tf" "curl -q --config - --proxy '' --noproxy '*' --proto '=http'"
require_text "$module_dir/main.tf" 'site-administrator token did not authenticate'
require_text "$module_dir/main.tf" 'encoding: gzip+base64'
require_text "$module_dir/main.tf" 'base64gzip(local.bootstrap_script)'
require_text "$module_dir/main.tf" 'work=$(mktemp -d /run/steward-control-bootstrap.XXXXXX)'
require_text "$module_dir/main.tf" "[[ ! -L \$work && \$(stat -c '%u:%g:%a' -- \"\$work\") == 0:0:700 ]]"
reject_text "$module_dir/main.tf" 'mktemp -d /tmp/steward-control-bootstrap.'
reject_text "$module_dir/main.tf" 'mktemp -d /var/tmp/steward-control-bootstrap.'
# The container smoke suite executes the real installer with the same protected
# staging shape. Keep that integration tied to this module's local-source argv.
require_text "$repo_root/scripts/control-install-smoke.sh" \
  'terraform_stage=$(mktemp -d /run/steward-control-bootstrap.XXXXXX)'
require_text "$repo_root/scripts/control-install-smoke.sh" 'install_version_from_terraform_stage() {'
require_text "$repo_root/scripts/control-install-smoke.sh" \
  '--artifact "$terraform_stage/$archive" --checksums "$terraform_stage/checksums.txt"'
require_text "$repo_root/scripts/control-install-smoke.sh" \
  'install_version_from_terraform_stage v1.0.0'
grep -Fx -- "ExecStart=/usr/local/bin/steward-control -addr=\${STEWARD_CONTROL_ADDR} -state-dir=\${STEWARD_CONTROL_STATE_DIR} -auth-key-file=\${STEWARD_CONTROL_AUTH_KEY_FILE} -witness-private-key-file=\${STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE} -witness-public-key-file=\${STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE} -tls-cert-file=\${STEWARD_CONTROL_TLS_CERT_FILE} -tls-key-file=\${STEWARD_CONTROL_TLS_KEY_FILE} -enable-metrics=\${STEWARD_CONTROL_ENABLE_METRICS} -node-stale-after=\${STEWARD_CONTROL_NODE_STALE_AFTER} -evidence-stale-after=\${STEWARD_CONTROL_EVIDENCE_STALE_AFTER} -command-overdue-after=\${STEWARD_CONTROL_COMMAND_OVERDUE_AFTER} -capacity-warning-percent=\${STEWARD_CONTROL_CAPACITY_WARNING_PERCENT}" \
  "$repo_root/deploy/systemd/steward-control.service" >/dev/null || {
  echo 'steward-control Terraform test: packaged systemd argv no longer matches the bootstrap identity proof' >&2
  exit 1
}
require_text "$module_dir/variables.tf" 'Query strings and fragments are forbidden.'
require_text "$module_dir/variables.tf" 'archive_sha256'
require_text "$module_dir/variables.tf" 'manifest_sha256'
if sed -n '/^variable "manifest_sha256" {$/,/^}$/p' "$module_dir/variables.tf" | grep -Eq '^[[:space:]]*default[[:space:]]*='; then
  echo 'steward-control Terraform test: manifest_sha256 must remain required' >&2
  exit 1
fi
reject_text "$module_dir/main.tf" "cat \"\$admin_token_path\""
reject_text "$module_dir/main.tf" '--header "Authorization: Bearer'
reject_text "$module_dir/variables.tf" 'variable "tls_'
reject_text "$module_dir/variables.tf" 'variable "admin_token'
if grep -E '^variable ".*(token|secret|password|certificate|private_key)' "$module_dir/variables.tf" >/dev/null; then
  echo 'steward-control Terraform test: module must not accept secret or private-key inputs' >&2
  exit 1
fi
if grep -E '^(provider|resource|data|module) "' "$module_dir"/*.tf >/dev/null; then
  echo 'steward-control Terraform test: bootstrap module must remain provider- and resource-free' >&2
  exit 1
fi

if ! command -v terraform >/dev/null 2>&1; then
  echo 'steward-control Terraform test: static checks passed; terraform is unavailable, so fmt/validate/render checks were skipped'
  exit 0
fi
command -v gzip >/dev/null 2>&1 || {
  echo 'steward-control Terraform test: gzip is required for render checks' >&2
  exit 2
}

work=$(mktemp -d "${TMPDIR:-/tmp}/steward-control-terraform-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
cp -R "$module_dir" "$work/module"

terraform fmt -check -recursive "$work/module" >/dev/null
terraform -chdir="$work/module" init -backend=false -input=false >/dev/null
terraform -chdir="$work/module" validate >/dev/null

mkdir -p "$work/root"
cat >"$work/root/main.tf" <<'HCL'
variable "release_version" {
  type    = string
  default = "v1.2.3"
}
variable "installer_url" {
  type    = string
  default = "https://downloads.example/install-control.sh"
}
variable "installer_sha256" {
  type    = string
  default = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
variable "manifest_sha256" {
  type    = string
  default = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
}
variable "release_mirror" {
  type    = any
  default = null
}
module "control" {
  source = "../module"

  release_version  = var.release_version
  installer_url    = var.installer_url
  installer_sha256 = var.installer_sha256
  manifest_sha256  = var.manifest_sha256
  release_mirror   = var.release_mirror
}
output "cloud_init" {
  value = module.control.cloud_init
}
output "token_path" {
  value = module.control.site_admin_token_path
}
HCL

terraform -chdir="$work/root" init -backend=false -input=false >/dev/null
terraform -chdir="$work/root" validate >/dev/null
terraform -chdir="$work/root" plan -input=false -lock=false -out="$work/public.plan" >/dev/null
terraform -chdir="$work/root" apply -input=false -auto-approve "$work/public.plan" >/dev/null
terraform -chdir="$work/root" output -raw cloud_init >"$work/cloud-init.yaml"

grep -F '#cloud-config' "$work/cloud-init.yaml" >/dev/null
grep -F '127.0.0.1:8443' "$work/cloud-init.yaml" >/dev/null && {
  echo 'steward-control Terraform test: bootstrap internals were not encoded in cloud-init' >&2
  exit 1
}
encoded=$(sed -n 's/^[[:space:]]*content: //p' "$work/cloud-init.yaml")
[[ -n $encoded ]] || {
  echo 'steward-control Terraform test: rendered cloud-init has no encoded bootstrap' >&2
  exit 1
}
printf '%s' "$encoded" | base64 -d | gzip -dc >"$work/bootstrap.sh"
/bin/bash -p -n "$work/bootstrap.sh"
shellcheck "$work/bootstrap.sh"
[[ $(head -n 1 "$work/bootstrap.sh") == '#!/bin/bash -p' ]]
grep -F '127.0.0.1:8443' "$work/bootstrap.sh" >/dev/null
grep -F '/root/steward-control-admin.token' "$work/bootstrap.sh" >/dev/null
grep -F 'mktemp -d /run/steward-control-bootstrap.XXXXXX' "$work/bootstrap.sh" >/dev/null
if grep -F '/var/tmp/steward-control-bootstrap' "$work/bootstrap.sh" >/dev/null; then
  echo 'steward-control Terraform test: local installer inputs are staged below writable /var/tmp' >&2
  exit 1
fi
default_manifest_encoded=$(printf '%s' 'https://github.com/hardrails/steward/releases/download/v1.2.3/checksums.txt' | base64 | tr -d '\n')
grep -F "$default_manifest_encoded" "$work/bootstrap.sh" >/dev/null
grep -F -- "--admin-token-out \"\$admin_token_path\" --checksums \"\$work/checksums.txt\"" "$work/bootstrap.sh" >/dev/null
manifest_fetch_line=$(grep -n "fetch \"\$manifest_url\" \"\$work/checksums.txt\"" "$work/bootstrap.sh" | cut -d: -f1)
manifest_verify_line=$(grep -n "verify \"\$work/checksums.txt\" \"\$manifest_expected\"" "$work/bootstrap.sh" | cut -d: -f1)
installer_run_line=$(grep -m 1 -n "/bin/bash -p \"\$work/install-control.sh\"" "$work/bootstrap.sh" | cut -d: -f1)
[[ -n $manifest_fetch_line && -n $manifest_verify_line && -n $installer_run_line &&
  $manifest_fetch_line -lt $manifest_verify_line && $manifest_verify_line -lt $installer_run_line ]] || {
  echo 'steward-control Terraform test: independently pinned manifest is not verified before installer invocation' >&2
  exit 1
}
if grep -F "cat \"\$admin_token_path\"" "$work/bootstrap.sh" >/dev/null; then
  echo 'steward-control Terraform test: rendered bootstrap reads the administrator token' >&2
  exit 1
fi
proof_line=$(grep -n 'if ! prove_bootstrap_token' "$work/bootstrap.sh" | cut -d: -f1)
stamp_line=$(grep -n "printf 'release=%s" "$work/bootstrap.sh" | cut -d: -f1)
[[ -n $proof_line && -n $stamp_line && $proof_line -lt $stamp_line ]] || {
  echo 'steward-control Terraform test: completion marker is not gated by authenticated token proof' >&2
  exit 1
}
(( $(wc -c <"$work/cloud-init.yaml") <= 16384 )) || {
  echo 'steward-control Terraform test: rendered public cloud-init exceeds 16 KiB' >&2
  exit 1
}
(( $(base64 <"$work/cloud-init.yaml" | tr -d '\n' | wc -c) <= 21848 )) || {
  echo 'steward-control Terraform test: rendered cloud-init exceeds its encoded byte ceiling' >&2
  exit 1
}
(( $(LC_ALL=C tr -d '\11\12\15\40-\176' <"$work/cloud-init.yaml" | wc -c) == 0 )) || {
  echo 'steward-control Terraform test: rendered cloud-init is not ASCII' >&2
  exit 1
}
[[ $(terraform -chdir="$work/root" output -raw token_path) == /root/steward-control-admin.token ]]

grep -Fq 'unset CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR' "$work/bootstrap.sh" || {
  echo 'steward-control Terraform test: bootstrap inherits caller-controlled CA environment' >&2
  exit 1
}
grep -Fq 'unset TAR_OPTIONS GZIP POSIXLY_CORRECT TMPDIR' "$work/bootstrap.sh" || {
  echo 'steward-control Terraform test: bootstrap inherits caller-controlled archive or temporary-path environment' >&2
  exit 1
}
grep -Fq 'readonly bootstrap_runtime_dir=/run/steward-control-terraform' "$work/bootstrap.sh"
grep -Fq '$(stat -c '\''%u:%g:%a:%h'\'' -- "$bootstrap_lock") == 0:0:600:1' "$work/bootstrap.sh"
grep -Fq 'exec 9<>"$bootstrap_lock"' "$work/bootstrap.sh"
grep -Fq 'flock -w 30 9' "$work/bootstrap.sh"
environment_unset_line=$(grep -n 'unset CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR' "$work/bootstrap.sh" | cut -d: -f1)
first_fetch_line=$(grep -n 'fetch "\$installer_url"' "$work/bootstrap.sh" | head -1 | cut -d: -f1)
[[ -n $environment_unset_line && -n $first_fetch_line && $environment_unset_line -lt $first_fetch_line ]] || {
  echo 'steward-control Terraform test: hostile fetch environment is not cleared before network use' >&2
  exit 1
}

cat >"$work/hostile-bash-env" <<EOF
touch '$work/bash-env-executed'
EOF
env BASH_ENV="$work/hostile-bash-env" \
  'BASH_FUNC_curl%%=() { touch '"$work"'/bash-function-executed; }' \
  /bin/bash -p -c 'command -v curl >/dev/null'
if [[ -e $work/bash-env-executed || -e $work/bash-function-executed ]]; then
  echo 'steward-control Terraform test: privileged bootstrap shell imported caller-controlled Bash code' >&2
  exit 1
fi

sed -n '/^fetch() {$/,/^}$/p' "$work/bootstrap.sh" >"$work/fetch.sh"
grep -F 'fetch() {' "$work/fetch.sh" >/dev/null
mkdir -p "$work/fetch-bin"
cat >"$work/fetch-bin/curl" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
output=
advertised_limit=
ulimit -c >"$FETCH_CORE_LIMIT_LOG"
printf '%s\n' "${1:-}" >"$FETCH_FIRST_ARGUMENT_LOG"
if [[ -f ${CURL_HOME:-}/.curlrc && ${1:-} != -q ]]; then
  : >"$FETCH_CURLRC_APPLIED_LOG"
  exit 97
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output=$2; shift 2 ;;
    --max-filesize) advertised_limit=$2; shift 2 ;;
    *) shift ;;
  esac
done
[[ -n $output && -n $advertised_limit ]]
printf '%s\n' "$advertised_limit" >"$FETCH_ADVERTISED_LIMIT_LOG"
case "$FETCH_FIXTURE_MODE" in
  oversize)
    set +e
    dd if=/dev/zero of="$output" bs=1024 count=64 2>/dev/null
    status=$?
    set -e
    observed=$(wc -c <"$output" | tr -d ' ')
    printf '%s\n' "$observed" >"$FETCH_OBSERVED_SIZE_LOG"
    exit "$status"
    ;;
  empty) : >"$output" ;;
  hardlink)
    printf 'payload\n' >"$FETCH_SIDE_FILE"
    ln "$FETCH_SIDE_FILE" "$output"
    ;;
  symlink)
    printf 'payload\n' >"$FETCH_SIDE_FILE"
    ln -s "$FETCH_SIDE_FILE" "$output"
    ;;
  valid) printf 'payload\n' >"$output" ;;
  *) exit 2 ;;
esac
SH
chmod 0700 "$work/fetch-bin/curl"
cat >"$work/fetch-bin/stat" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ $# == 4 && $1 == -c && $3 == -- ]]
case "$2" in
  %h)
    if find "$4" -links +1 -print -quit | grep -q .; then
      printf '%s\n' 2
    else
      printf '%s\n' 1
    fi
    ;;
  %s) wc -c <"$4" | tr -d ' ' ;;
  *) exit 2 ;;
esac
SH
chmod 0700 "$work/fetch-bin/stat"
mkdir -p "$work/hostile-curl-home"
printf '%s\n' 'output = "/root/curlrc-controlled-output"' >"$work/hostile-curl-home/.curlrc"

run_fetch_fixture() {
  local mode=$1 output=$2 limit=$3 side_file=$4
  # shellcheck disable=SC2016 # Expand positional arguments inside the isolated child shell.
  env CURL_HOME="$work/hostile-curl-home" XDG_CONFIG_HOME="$work/hostile-curl-home" \
    FETCH_FIXTURE_MODE="$mode" FETCH_SIDE_FILE="$side_file" \
    FETCH_ADVERTISED_LIMIT_LOG="$work/fetch-advertised-limit.log" \
    FETCH_CORE_LIMIT_LOG="$work/fetch-core-limit.log" \
    FETCH_CURLRC_APPLIED_LOG="$work/fetch-curlrc-applied.log" \
    FETCH_FIRST_ARGUMENT_LOG="$work/fetch-first-argument.log" \
    FETCH_OBSERVED_SIZE_LOG="$work/fetch-observed-size.log" \
    FETCH_FUNCTION="$work/fetch.sh" PATH="$work/fetch-bin:$PATH" \
    bash -c 'source "$FETCH_FUNCTION"; fetch https://mirror.example/unknown-length "$1" "$2"' \
    bash "$output" "$limit"
}

if run_fetch_fixture oversize "$work/oversize.download" 4096 "$work/unused.side" \
  >"$work/oversize-fetch.stdout" 2>"$work/oversize-fetch.stderr"; then
  echo 'steward-control Terraform test: OS file-size limit accepted an oversized unknown-length download' >&2
  exit 1
fi
[[ ! -e $work/oversize.download && ! -L $work/oversize.download ]] || {
  echo 'steward-control Terraform test: failed oversized download left a partial file' >&2
  exit 1
}
[[ $(<"$work/fetch-advertised-limit.log") == 4096 ]]
[[ $(<"$work/fetch-core-limit.log") == 0 ]] || {
  echo 'steward-control Terraform test: fetch curl did not inherit a zero core-file limit' >&2
  exit 1
}
[[ $(<"$work/fetch-first-argument.log") == -q && ! -e $work/fetch-curlrc-applied.log ]] || {
  echo 'steward-control Terraform test: hostile curl configuration was not disabled by first-option -q' >&2
  exit 1
}
observed_size=$(<"$work/fetch-observed-size.log")
if [[ ! $observed_size =~ ^[0-9]+$ ]] || (( observed_size <= 0 || observed_size > 4096 )); then
  echo "steward-control Terraform test: OS limit allowed $observed_size bytes for a 4096-byte download" >&2
  exit 1
fi

if run_fetch_fixture empty "$work/empty.download" 4096 "$work/unused.side" >/dev/null 2>&1; then
  echo 'steward-control Terraform test: empty download passed post-fetch validation' >&2
  exit 1
fi
[[ ! -e $work/empty.download ]]

if run_fetch_fixture hardlink "$work/hardlink.download" 4096 "$work/hardlink.side" >/dev/null 2>&1; then
  echo 'steward-control Terraform test: multiply linked download passed post-fetch validation' >&2
  exit 1
fi
[[ ! -e $work/hardlink.download && -f $work/hardlink.side ]]

if run_fetch_fixture symlink "$work/symlink.download" 4096 "$work/symlink.side" >/dev/null 2>&1; then
  echo 'steward-control Terraform test: symlink download passed post-fetch validation' >&2
  exit 1
fi
[[ ! -e $work/symlink.download && ! -L $work/symlink.download && -f $work/symlink.side ]]

run_fetch_fixture valid "$work/valid.download" 4096 "$work/unused.side" >/dev/null
[[ $(<"$work/valid.download") == payload ]]
[[ $(<"$work/fetch-first-argument.log") == -q && ! -e $work/fetch-curlrc-applied.log ]]

for function_name in validate_control_config process_arguments_match capture_controller_identity controller_identity_matches prove_bootstrap_token; do
  sed -n "/^$function_name() {\$/,/^}\$/p" "$work/bootstrap.sh" >>"$work/prove-bootstrap-token.sh"
done
for function_name in validate_control_config process_arguments_match capture_controller_identity controller_identity_matches prove_bootstrap_token; do
  grep -F "$function_name() {" "$work/prove-bootstrap-token.sh" >/dev/null
done
mkdir -p "$work/fake-bin" "$work/auth-work" "$work/proc/4242"
cat >"$work/control.env" <<'ENV'
STEWARD_CONTROL_ADDR=127.0.0.1:8443
STEWARD_CONTROL_STATE_DIR=/var/lib/steward-control
STEWARD_CONTROL_AUTH_KEY_FILE=/var/lib/steward-control/auth.key
STEWARD_CONTROL_WITNESS_PRIVATE_KEY_FILE=/var/lib/steward-control/witness.private.pem
STEWARD_CONTROL_WITNESS_PUBLIC_KEY_FILE=/var/lib/steward-control/witness.public.pem
STEWARD_CONTROL_TLS_CERT_FILE=
STEWARD_CONTROL_TLS_KEY_FILE=
STEWARD_CONTROL_ENABLE_METRICS=false
STEWARD_CONTROL_NODE_STALE_AFTER=2m
STEWARD_CONTROL_EVIDENCE_STALE_AFTER=5m
STEWARD_CONTROL_COMMAND_OVERDUE_AFTER=5m
STEWARD_CONTROL_CAPACITY_WARNING_PERCENT=80
ENV

cat >"$work/fake-bin/systemctl" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
case ${1:-} in
  is-active) [[ ${IDENTITY_MODE:-valid} != inactive ]] ;;
  show)
    [[ ${2:-} == --property && ${3:-} == MainPID && ${4:-} == --value && ${5:-} == steward-control.service ]]
    printf '%s\n' 4242
    ;;
  *) exit 2 ;;
esac
SH
cat >"$work/fake-bin/id" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ $# == 2 && $1 == -u && $2 == steward-control ]]
printf '%s\n' "$SERVICE_UID"
SH
cat >"$work/fake-bin/readlink" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
path=${!#}
[[ $path == "$PROC_ROOT_FIXTURE/4242/exe" ]]
if [[ ${IDENTITY_MODE:-valid} == wrong-executable ]] ||
  [[ ${IDENTITY_MODE:-valid} == swap-after-curl && -s $CURL_CALLED_LOG ]] ||
  [[ ${IDENTITY_MODE:-valid} == restart-after-503 && -s $CURL_CALLED_LOG ]]; then
  printf '%s\n' /opt/unrelated/controller
else
  printf '%s\n' "$RELEASE_BINARY"
fi
SH
cat >"$work/fake-bin/stat" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
format=${2:-}
path=${!#}
case "$path:$format" in
  "$CONTROL_CONFIG_FIXTURE:%u:%g:%a:%h") printf '%s\n' 0:0:600:1 ;;
  "$CONTROL_CONFIG_FIXTURE:%s") wc -c <"$path" | tr -d ' ' ;;
  "$PROC_ROOT_FIXTURE/4242:%u") printf '%s\n' "$SERVICE_UID" ;;
  *) exit 2 ;;
esac
SH
cat >"$work/fake-bin/curl" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
output=
printf 'called\n' >>"$CURL_CALLED_LOG"
while [[ $# -gt 0 ]]; do
  printf '%s\n' "$1" >>"$CURL_ARGV_LOG"
  case "$1" in
    --output) output=$2; printf '%s\n' "$2" >>"$CURL_ARGV_LOG"; shift 2 ;;
    --write-out | --connect-timeout | --max-time | --max-filesize | --proxy | --noproxy | --proto | --config) shift 2 ;;
    *) shift ;;
  esac
done
IFS= read -r config
valid='header = "Authorization: Bearer steward_cp_v1_bootstrap-cred-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"'
if [[ ${IDENTITY_MODE:-valid} == restart-after-503 ]]; then
  printf '%s\n' '{"status":"starting"}' >"$output"
  printf '503'
elif [[ $config == "$valid" ]]; then
  printf '%s\n' '{"tenants":[]}' >"$output"
  printf '200'
else
  printf '%s\n' '{"error":"unauthorized","message":"one bearer credential is required"}' >"$output"
  printf '401'
fi
SH
chmod 0700 "$work/fake-bin"/*

valid_token=steward_cp_v1_bootstrap-cred-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
stale_token=steward_cp_v1_bootstrap-cred-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
printf '%s\n' "$valid_token" >"$work/valid.token"
printf '%s\n' "$stale_token" >"$work/stale.token"
chmod 0600 "$work/valid.token" "$work/stale.token"
export CURL_ARGV_LOG="$work/curl.argv"
export CURL_CALLED_LOG="$work/curl.called"
export CONTROL_CONFIG_FIXTURE="$work/control.env"
export PROC_ROOT_FIXTURE="$work/proc"
export RELEASE_BINARY=/opt/steward-control/releases/v1.2.3/steward-control
export SERVICE_UID=991
: >"$CURL_ARGV_LOG"
: >"$CURL_CALLED_LOG"
run_proof() {
  local token_path=$1 identity_mode=$2
  local address=127.0.0.1:8443
  [[ $identity_mode != wrong-address ]] || address=127.0.0.1:9443
  printf '%s\0' /usr/local/bin/steward-control \
    "-addr=$address" \
    -state-dir=/var/lib/steward-control \
    -auth-key-file=/var/lib/steward-control/auth.key \
    -witness-private-key-file=/var/lib/steward-control/witness.private.pem \
    -witness-public-key-file=/var/lib/steward-control/witness.public.pem \
    -tls-cert-file= -tls-key-file= \
    -enable-metrics=false \
    -node-stale-after=2m \
    -evidence-stale-after=5m \
    -command-overdue-after=5m \
    -capacity-warning-percent=80 >"$PROC_ROOT_FIXTURE/4242/cmdline"
  # shellcheck disable=SC2016 # Expand PROOF_FUNCTIONS in the isolated child shell.
  env PROOF_FUNCTIONS="$work/prove-bootstrap-token.sh" \
    admin_token_path="$token_path" control_url=http://127.0.0.1:8443 \
    control_address=127.0.0.1:8443 control_config="$CONTROL_CONFIG_FIXTURE" \
    control_state_dir=/var/lib/steward-control control_auth_key=/var/lib/steward-control/auth.key \
    control_witness_private_key=/var/lib/steward-control/witness.private.pem \
    control_witness_public_key=/var/lib/steward-control/witness.public.pem \
    control_service=steward-control.service binary_link=/usr/local/bin/steward-control \
    release_binary="$RELEASE_BINARY" proc_root="$PROC_ROOT_FIXTURE" work="$work/auth-work" \
    PATH="$work/fake-bin:$PATH" IDENTITY_MODE="$identity_mode" \
    bash -c 'source "$PROOF_FUNCTIONS"; prove_bootstrap_token'
}
if ! run_proof "$work/valid.token" valid >"$work/valid-proof.stdout" 2>"$work/valid-proof.stderr"; then
  echo 'steward-control Terraform test: valid controller identity and bearer failed proof' >&2
  sed -n '1,40p' "$work/valid-proof.stderr" >&2
  exit 1
fi
if grep -F "$valid_token" "$CURL_ARGV_LOG" "$work/valid-proof.stdout" "$work/valid-proof.stderr" >/dev/null; then
  echo 'steward-control Terraform test: authenticated proof disclosed the bearer in argv or output' >&2
  exit 1
fi
if run_proof "$work/stale.token" valid >"$work/stale-proof.stdout" 2>"$work/stale-proof.stderr"; then
  echo 'steward-control Terraform test: stale bootstrap bearer passed authenticated proof' >&2
  exit 1
fi
if grep -F "$stale_token" "$CURL_ARGV_LOG" "$work/stale-proof.stdout" "$work/stale-proof.stderr" >/dev/null; then
  echo 'steward-control Terraform test: stale bearer was disclosed in argv or output' >&2
  exit 1
fi

: >"$CURL_ARGV_LOG"
: >"$CURL_CALLED_LOG"
if run_proof "$work/valid.token" wrong-executable >"$work/wrong-identity.stdout" 2>"$work/wrong-identity.stderr"; then
  echo 'steward-control Terraform test: wrong controller process identity received authenticated proof' >&2
  exit 1
fi
[[ ! -s $CURL_CALLED_LOG && ! -s $CURL_ARGV_LOG ]] || {
  echo 'steward-control Terraform test: bearer request began before controller process identity was proven' >&2
  exit 1
}

: >"$CURL_ARGV_LOG"
: >"$CURL_CALLED_LOG"
if run_proof "$work/valid.token" wrong-address >"$work/wrong-address.stdout" 2>"$work/wrong-address.stderr"; then
  echo 'steward-control Terraform test: same controller binary with a wrong listener received authenticated proof' >&2
  exit 1
fi
[[ ! -s $CURL_CALLED_LOG && ! -s $CURL_ARGV_LOG ]] || {
  echo 'steward-control Terraform test: bearer request began before effective controller arguments were proven' >&2
  exit 1
}

: >"$CURL_ARGV_LOG"
: >"$CURL_CALLED_LOG"
if run_proof "$work/valid.token" swap-after-curl >"$work/swapped-identity.stdout" 2>"$work/swapped-identity.stderr"; then
  echo 'steward-control Terraform test: controller process replacement passed post-response identity proof' >&2
  exit 1
fi
if grep -F "$valid_token" "$CURL_ARGV_LOG" "$work/swapped-identity.stdout" "$work/swapped-identity.stderr" >/dev/null; then
  echo 'steward-control Terraform test: replaced-process proof disclosed the bearer in argv or output' >&2
  exit 1
fi

: >"$CURL_ARGV_LOG"
: >"$CURL_CALLED_LOG"
if run_proof "$work/valid.token" restart-after-503 >"$work/restarted-retry.stdout" 2>"$work/restarted-retry.stderr"; then
  echo 'steward-control Terraform test: replacement controller survived retry identity proof' >&2
  exit 1
fi
(( $(wc -l <"$CURL_CALLED_LOG") == 1 )) || {
  echo 'steward-control Terraform test: bearer was retried after controller identity changed' >&2
  exit 1
}
if grep -F "$valid_token" "$CURL_ARGV_LOG" "$work/restarted-retry.stdout" "$work/restarted-retry.stderr" >/dev/null; then
  echo 'steward-control Terraform test: retry identity proof disclosed the bearer in argv or output' >&2
  exit 1
fi

cat >"$work/root/mirror.tfvars" <<'HCL'
release_mirror = {
  archive_url    = "https://mirror.example/steward-control_v1.2.3_linux_arm64.tar.gz"
  archive_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  manifest_url   = "https://mirror.example/checksums.txt"
}
HCL
terraform -chdir="$work/root" plan -input=false -lock=false -var-file=mirror.tfvars -out="$work/mirror.plan" >/dev/null
terraform -chdir="$work/root" apply -input=false -auto-approve "$work/mirror.plan" >/dev/null
terraform -chdir="$work/root" output -raw cloud_init >"$work/mirror-cloud-init.yaml"
mirror_encoded=$(sed -n 's/^[[:space:]]*content: //p' "$work/mirror-cloud-init.yaml")
[[ -n $mirror_encoded ]]
printf '%s' "$mirror_encoded" | base64 -d | gzip -dc >"$work/mirror-bootstrap.sh"
bash -n "$work/mirror-bootstrap.sh"
grep -F "readonly mirror_enabled='true'" "$work/mirror-bootstrap.sh" >/dev/null
grep -F -- "--artifact \"\$work/\$archive_name\" --checksums \"\$work/checksums.txt\"" "$work/mirror-bootstrap.sh" >/dev/null
mirror_stage_line=$(grep -n 'work=$(mktemp -d /run/steward-control-bootstrap.XXXXXX)' \
  "$work/mirror-bootstrap.sh" | cut -d: -f1)
mirror_manifest_line=$(grep -n 'fetch "$manifest_url" "$work/checksums.txt" 4194304' \
  "$work/mirror-bootstrap.sh" | cut -d: -f1)
mirror_archive_line=$(grep -n 'fetch "$archive_url" "$work/$archive_name" 268435456' \
  "$work/mirror-bootstrap.sh" | cut -d: -f1)
mirror_archive_verify_line=$(grep -n 'verify "$work/$archive_name" "$archive_expected"' \
  "$work/mirror-bootstrap.sh" | cut -d: -f1)
mirror_installer_line=$(grep -n -- '--artifact "$work/$archive_name" --checksums "$work/checksums.txt"' \
  "$work/mirror-bootstrap.sh" | cut -d: -f1)
[[ -n $mirror_stage_line && -n $mirror_manifest_line && -n $mirror_archive_line &&
  -n $mirror_archive_verify_line && -n $mirror_installer_line &&
  $mirror_stage_line -lt $mirror_manifest_line && $mirror_manifest_line -lt $mirror_archive_line &&
  $mirror_archive_line -lt $mirror_archive_verify_line &&
  $mirror_archive_verify_line -lt $mirror_installer_line ]] || {
  echo 'steward-control Terraform test: protected local sources are not staged and verified before installer execution' >&2
  exit 1
}

expect_invalid() {
  local name=$1
  shift
  if terraform -chdir="$work/root" plan -input=false -lock=false "$@" >"$work/$name.log" 2>&1; then
    echo "steward-control Terraform test: invalid case '$name' unexpectedly planned" >&2
    exit 1
  fi
}

expect_invalid latest -var=release_version=latest
expect_invalid core-leading-zero -var=release_version=v01.2.3
expect_invalid numeric-prerelease-zero -var=release_version=v1.2.3-01
expect_invalid numeric-dotted-prerelease-zero -var=release_version=v1.2.3-alpha.01
terraform -chdir="$work/root" plan -input=false -lock=false -var=release_version=v1.2.3-alpha.01-bar >/dev/null
expect_invalid build-metadata -var=release_version=v1.2.3+build.1
long_release="v1.2.3-$(printf 'a%.0s' {1..122})"
expect_invalid release-too-long "-var=release_version=$long_release"
expect_invalid installer-query '-var=installer_url=https://downloads.example/install-control.sh?token=secret'
expect_invalid installer-userinfo '-var=installer_url=https://user:secret@downloads.example/install-control.sh'
expect_invalid installer-whitespace '-var=installer_url=https://downloads.example/install control.sh'
expect_invalid installer-unicode '-var=installer_url=https://downloads.example/café/install-control.sh'
expect_invalid installer-sha-uppercase '-var=installer_sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
expect_invalid manifest-sha-uppercase '-var=manifest_sha256=DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD'
long_installer_url="https://downloads.example/$(printf 'a%.0s' {1..487})"
expect_invalid installer-url-too-long "-var=installer_url=$long_installer_url"

cat >"$work/root/incomplete-mirror.tfvars" <<'HCL'
release_mirror = {
  archive_url    = "https://mirror.example/steward-control_v1.2.3_linux_arm64.tar.gz"
  archive_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}
HCL
expect_invalid incomplete-mirror -var-file=incomplete-mirror.tfvars

cat >"$work/root/query-mirror.tfvars" <<'HCL'
release_mirror = {
  archive_url    = "https://mirror.example/steward-control_v1.2.3_linux_arm64.tar.gz?token=secret"
  archive_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  manifest_url   = "https://mirror.example/checksums.txt"
}
HCL
expect_invalid query-mirror -var-file=query-mirror.tfvars

cat >"$work/root/unicode-mirror.tfvars" <<'HCL'
release_mirror = {
  archive_url    = "https://mirror.example/steward-control_v1.2.3_linux_arm64.tar.gz"
  archive_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  manifest_url   = "https://mirror.example/checksums-café.txt"
}
HCL
expect_invalid unicode-mirror -var-file=unicode-mirror.tfvars

cat >"$work/root/uppercase-mirror-sha.tfvars" <<'HCL'
release_mirror = {
  archive_url    = "https://mirror.example/steward-control_v1.2.3_linux_arm64.tar.gz"
  archive_sha256 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
  manifest_url   = "https://mirror.example/checksums.txt"
}
HCL
expect_invalid uppercase-mirror-sha -var-file=uppercase-mirror-sha.tfvars

url_with_size() {
  local prefix=$1 suffix=$2 character=$3 target=512 fill
  fill=$((target - ${#prefix} - ${#suffix}))
  printf '%s' "$prefix"
  printf "%${fill}s" '' | tr ' ' "$character"
  printf '%s' "$suffix"
}
max_installer_url=$(url_with_size 'https://downloads.example/' '.sh' a)
max_archive_url=$(url_with_size 'https://mirror.example/' '.tar.gz' b)
max_manifest_url=$(url_with_size 'https://mirror.example/' '' c)
max_release="v1.2.3-$(printf 'a%.0s' {1..121})"
cat >"$work/root/max-size.tfvars" <<HCL
release_version = "$max_release"
installer_url = "$max_installer_url"
release_mirror = {
  archive_url    = "$max_archive_url"
  archive_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  manifest_url   = "$max_manifest_url"
}
HCL
terraform -chdir="$work/root" plan -input=false -lock=false -var-file=max-size.tfvars -out="$work/max-size.plan" >/dev/null
terraform -chdir="$work/root" apply -input=false -auto-approve "$work/max-size.plan" >/dev/null
terraform -chdir="$work/root" output -raw cloud_init >"$work/max-size-cloud-init.yaml"
(( $(wc -c <"$work/max-size-cloud-init.yaml") <= 16384 )) || {
  echo 'steward-control Terraform test: maximum valid inputs exceed the 16 KiB cloud-init ceiling' >&2
  exit 1
}

echo 'steward-control Terraform test: static, fmt, validate, render, and negative-input checks passed'
