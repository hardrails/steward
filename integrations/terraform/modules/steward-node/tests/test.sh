#!/usr/bin/env bash
set -Eeuo pipefail

module=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/steward-node-terraform-test.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

terraform -chdir="$module" fmt -check
terraform -chdir="$module" init -backend=false -input=false >/dev/null
terraform -chdir="$module" validate >/dev/null

cat >"$work/main.tf" <<EOF
variable "release_version" {
  type    = string
  default = "v1.2.3"
}
variable "installer_url" {
  type    = string
  default = "https://mirror.invalid/install-steward.sh"
}
variable "release_mirror" {
  type = any
  default = {
    artifact_url    = "https://mirror.invalid/steward_v1.2.3_linux_amd64.tar.gz"
    artifact_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    manifest_url    = "https://mirror.invalid/checksums.txt"
    manifest_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  }
}
module "node" {
  source           = "$module"
  release_version  = var.release_version
  installer_url    = var.installer_url
  installer_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  release_mirror   = var.release_mirror
}
output "bootstrap" { value = module.node.cloud_init }
EOF
terraform -chdir="$work" init -backend=false -input=false >/dev/null
terraform -chdir="$work" apply -auto-approve -input=false >/dev/null

reject_plan() {
	local label=$1
	shift
	if terraform -chdir="$work" plan -input=false -lock=false "$@" >/dev/null 2>&1; then
		echo "steward-node Terraform test: accepted $label" >&2
		exit 1
	fi
}
reject_plan 'a leading-zero release component' -var 'release_version=v01.2.3'
reject_plan 'a leading-zero numeric prerelease identifier' -var 'release_version=v1.2.3-01'
reject_plan 'installer credentials persisted in Terraform state' \
	-var 'installer_url=https://operator:secret@mirror.invalid/install-steward.sh'
reject_plan 'an installer query string persisted in Terraform state' \
	-var 'installer_url=https://mirror.invalid/install-steward.sh?token=secret'
long_url="https://mirror.invalid/$(printf 'a%.0s' {1..500})"
reject_plan 'an installer URL longer than 512 bytes' -var "installer_url=$long_url"
reject_plan 'mirror credentials persisted in Terraform state' \
	-var 'release_mirror={artifact_url="https://operator:secret@mirror.invalid/steward_v1.2.3_linux_amd64.tar.gz",artifact_sha256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",manifest_url="https://mirror.invalid/checksums.txt",manifest_sha256="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}'
terraform -chdir="$work" output -raw bootstrap >"$work/cloud-init"
encoded=$(sed -n 's/^[[:space:]]*content: //p' "$work/cloud-init")
[[ -n $encoded ]]
printf '%s' "$encoded" | base64 -d >"$work/bootstrap"

grep -Fq '#!/bin/bash -p' "$work/bootstrap"
grep -Fq 'curl -q --fail' "$work/bootstrap"
grep -Fq 'unset CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR' "$work/bootstrap"
grep -Fq "ulimit -f \"\$blocks\"" "$work/bootstrap"
grep -Fq "fetch \"\$installer_url\" \"\$work/install-steward.sh\" 4194304" "$work/bootstrap"
grep -Fq "fetch \"\$artifact_url\" \"\$work/\$artifact_name\" 268435456" "$work/bootstrap"
grep -Fq "fetch \"\$manifest_url\" \"\$work/checksums.txt\" 4194304" "$work/bootstrap"
if grep -Eq "(^|[[:space:]])bash[[:space:]]+\"\\\$work/install-steward\\.sh\"" "$work/bootstrap"; then
	echo "steward-node Terraform test: bootstrap bypasses installer privileged mode" >&2
	exit 1
fi

# Extract the rendered fetch primitive and replace curl with a deterministic
# unknown-length writer. RLIMIT_FSIZE must stop it and remove the partial file.
sed -n '/^fetch() {$/,/^}$/p' "$work/bootstrap" >"$work/fetch.sh"
grep -Fq 'fetch() {' "$work/fetch.sh"
mkdir "$work/fake-bin"
cat >"$work/fake-bin/curl" <<'EOF'
#!/bin/bash -p
set -euo pipefail
: >"${STEWARD_FAKE_CURL_MARKER:?}"
output=
while (( $# > 0 )); do
	case "$1" in --output) output=${2:-}; shift 2 ;; *) shift ;; esac
done
exec dd if=/dev/zero of="$output" bs=1048576 count=32 status=none
EOF
chmod 0755 "$work/fake-bin/curl"
if command -v timeout >/dev/null 2>&1; then
	(
		PATH="$work/fake-bin:/usr/sbin:/usr/bin:/sbin:/bin"
		export STEWARD_FAKE_CURL_MARKER="$work/fake-curl-ran"
		# shellcheck source=/dev/null
		source "$work/fetch.sh"
		if fetch https://unknown-length.invalid "$work/partial" 1048576; then
			exit 1
		fi
		[[ -f $STEWARD_FAKE_CURL_MARKER && ! -e $work/partial ]]
	)
else
	echo "steward-node Terraform test: timeout unavailable; dynamic fetch cap check skipped"
fi

echo "steward-node Terraform test: bounded secret-free bootstrap passed"
