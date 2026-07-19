#!/bin/bash -p
# Install Steward's native macOS operator and development binaries from a
# checksummed GitHub release or an offline release directory.
set -Eeuo pipefail
set +x
if ! shopt -qo privileged; then
	echo "install-macos: invoke with /bin/bash -p or execute the file directly" >&2
	exit 2
fi
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH LC_ALL=C LANG=C
unset BASH_ENV ENV CDPATH GLOBIGNORE CURL_HOME XDG_CONFIG_HOME
unset CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR TAR_OPTIONS GZIP POSIXLY_CORRECT
IFS=$' \t\n'
umask 077

readonly project_url=https://github.com/hardrails/steward
readonly max_manifest_bytes=4194304
readonly max_archive_bytes=268435456

version=${STEWARD_VERSION:-latest}
offline_dir=${STEWARD_OFFLINE_DIR:-}
install_dir=${STEWARD_INSTALL_DIR:-"${HOME:-}/.local/bin"}
dry_run=false

usage() {
	cat <<'EOF'
Install Steward's macOS operator and local-development tools.

Usage:
  /bin/bash -p install-macos.sh
  /bin/bash -p install-macos.sh --version v2.1.1 --install-dir ~/.local/bin
  /bin/bash -p install-macos.sh --offline-dir /path/to/release

Options:
  --version VERSION       Release tag; default is the latest GitHub release
  --offline-dir DIR       Directory containing checksums.txt and the Darwin archive
  --install-dir DIR       Binary destination; default is ~/.local/bin
  --dry-run               Resolve and verify the plan without installing
  -h, --help              Show this help

This installs steward, steward-control, stewardctl, and steward-mcp. Docker
Desktop is a development execution profile. Hardened production nodes continue
to use Linux with Docker and gVisor; `stewardctl agent doctor` reports the exact
profile active on this Mac.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--version) version=${2:-}; shift 2 ;;
		--offline-dir) offline_dir=${2:-}; shift 2 ;;
		--install-dir) install_dir=${2:-}; shift 2 ;;
		--dry-run) dry_run=true; shift ;;
		-h | --help) usage; exit 0 ;;
		*) echo "install-macos: unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

[[ $(uname -s) == Darwin ]] || { echo "install-macos: this installer supports macOS only" >&2; exit 1; }
case $(uname -m) in
	arm64) arch=arm64 ;;
	x86_64) arch=amd64 ;;
	*) echo "install-macos: supported architectures are Apple Silicon and Intel" >&2; exit 1 ;;
esac
[[ $install_dir == /* && $install_dir != / ]] || { echo "install-macos: install directory must be an absolute non-root path" >&2; exit 2; }

valid_version() {
	[[ $1 =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$ ]]
}

workspace=$(mktemp -d "${TMPDIR:-/tmp}/steward-macos.XXXXXX")
cleanup() { rm -rf "$workspace"; }
trap cleanup EXIT INT TERM HUP

if [[ -n $offline_dir ]]; then
	[[ $offline_dir == /* && -d $offline_dir && ! -L $offline_dir ]] || { echo "install-macos: offline directory must be an absolute real directory" >&2; exit 1; }
	[[ $version != latest ]] || {
		matches=("$offline_dir"/steward_v*_darwin_${arch}.tar.gz)
		[[ ${#matches[@]} == 1 && -f ${matches[0]} ]] || { echo "install-macos: offline directory must contain exactly one matching Darwin archive when version is latest" >&2; exit 1; }
		name=${matches[0]##*/}; version=${name#steward_}; version=${version%_darwin_${arch}.tar.gz}
	}
	valid_version "$version" || { echo "install-macos: invalid release version" >&2; exit 2; }
	archive_name="steward_${version}_darwin_${arch}.tar.gz"
	cp -p "$offline_dir/checksums.txt" "$workspace/checksums.txt"
	cp -p "$offline_dir/$archive_name" "$workspace/$archive_name"
else
	if [[ $version == latest ]]; then
		effective=$(curl -q --proto '=https' --tlsv1.2 --location --fail --silent --show-error --output /dev/null --write-out '%{url_effective}' --max-time 30 "$project_url/releases/latest")
		version=${effective##*/}
	fi
	valid_version "$version" || { echo "install-macos: latest release did not resolve to an installable semantic version" >&2; exit 1; }
	archive_name="steward_${version}_darwin_${arch}.tar.gz"
	base="$project_url/releases/download/$version"
	curl -q --proto '=https' --tlsv1.2 --location --fail --silent --show-error --max-time 180 --max-filesize "$max_manifest_bytes" --output "$workspace/checksums.txt" "$base/checksums.txt"
	curl -q --proto '=https' --tlsv1.2 --location --fail --silent --show-error --max-time 300 --max-filesize "$max_archive_bytes" --output "$workspace/$archive_name" "$base/$archive_name"
fi

[[ -f $workspace/checksums.txt && ! -L $workspace/checksums.txt && $(stat -f %z "$workspace/checksums.txt") -le $max_manifest_bytes ]] || { echo "install-macos: checksum manifest is missing or oversized" >&2; exit 1; }
[[ -f $workspace/$archive_name && ! -L $workspace/$archive_name && $(stat -f %z "$workspace/$archive_name") -le $max_archive_bytes ]] || { echo "install-macos: archive is missing or oversized" >&2; exit 1; }
expected=$(awk -v name="$archive_name" '$2 == name || $2 == "./" name { if (++count == 1) hash=$1 } END { if (count == 1) print hash }' "$workspace/checksums.txt")
[[ $expected =~ ^[0-9a-f]{64}$ ]] || { echo "install-macos: checksum manifest has no unique canonical entry for $archive_name" >&2; exit 1; }
actual=$(shasum -a 256 "$workspace/$archive_name" | awk '{print $1}')
[[ $actual == "$expected" ]] || { echo "install-macos: archive checksum mismatch" >&2; exit 1; }

inventory="$workspace/inventory"
tar -tzf "$workspace/$archive_name" >"$inventory"
expected_files=(steward steward-control steward-mcp stewardctl)
for file in "${expected_files[@]}"; do
	[[ $(grep -Fxc "$file" "$inventory") == 1 ]] || { echo "install-macos: archive inventory is missing or duplicates $file" >&2; exit 1; }
done
extract="$workspace/extract"
mkdir "$extract"
tar -xzf "$workspace/$archive_name" -C "$extract" steward steward-control steward-mcp stewardctl
for binary in steward steward-control stewardctl steward-mcp; do
	[[ -f $extract/$binary && ! -L $extract/$binary ]] || { echo "install-macos: $binary is not a regular extracted binary" >&2; exit 1; }
done

echo "Steward $version for macOS/$arch"
echo "Install directory: $install_dir"
if [[ $dry_run == true ]]; then
	echo "Archive verified; no files changed."
	exit 0
fi
mkdir -p "$install_dir"
[[ -d $install_dir && ! -L $install_dir ]] || { echo "install-macos: install destination must be a real directory" >&2; exit 1; }
for binary in steward steward-control stewardctl steward-mcp; do
	temporary="$install_dir/.${binary}.steward-install.$$"
	install -m 0755 "$extract/$binary" "$temporary"
	mv -f "$temporary" "$install_dir/$binary"
done
"$install_dir/stewardctl" version
echo "Add $install_dir to PATH if it is not already present, then run:"
echo "  stewardctl agent doctor"
