#!/usr/bin/env bash
# Install, configure, validate, and optionally start a Steward node.
set -Eeuo pipefail

readonly project_url=https://github.com/hardrails/steward
readonly release_url="$project_url/releases"

usage() {
	cat <<'EOF'
Install Steward on a supported Linux server.

Usage:
  sudo bash install-steward.sh                 # interactive guided install
  sudo bash install-steward.sh --non-interactive OPTIONS

Artifact source:
  --version VERSION             Release tag (default: latest)
  --offline-dir DIR             Directory containing checksums.txt and release assets
  --artifact FILE               Exact DEB, RPM, or Linux tar.gz to install
  --checksums FILE              SHA-256 manifest; --artifact defaults to checksums.txt beside it
  --package auto|deb|rpm|tar    Override host package selection

Node enrollment:
  --control-plane-url URL       HTTPS control-plane base URL
  --steward-credential FILE     Steward uplink credential JSON
  --executor-credential FILE    Executor uplink credential JSON
  --ca-file FILE                PEM CA bundle for the control plane
  --executor-token FILE         Host-local token (securely generated if omitted)
  --admission-policy FILE       Signed site policy (with both site-root flags)
  --site-root-public-key FILE   Base64 Ed25519 site-root public key
  --site-root-key-id ID         Signature key ID used by the policy
  --node-id ID                  Stable node ID (machine-derived if omitted)
  --allow-host-admin-intent     Let the host token select signed tenant intent
  --local-only                  Use loopback HTTP, CLI, and MCP without remote enrollment
  --reuse-configuration         Reuse and validate existing /etc/steward enrollment
  --stage-only                  Install files only; Docker daemon/runsc may be offline
  --no-start                    On a stopped node, configure/activate without a restart

gVisor:
  --install-gvisor              Install/register gVisor if Docker lacks runsc
  --gvisor-dir DIR              Offline runsc + shim + matching .sha512 files
  --gvisor-version VERSION      Official release path component (default: latest)

Automation and inspection:
  --non-interactive             Never prompt; enrollment flags are required
  --yes                         Accept the final interactive confirmation
  --dry-run                     Print the resolved plan without downloading or changing state
  -h, --help                    Show this help

Environment variables matching automation flags are also accepted: STEWARD_VERSION,
STEWARD_OFFLINE_DIR, STEWARD_ARTIFACT, STEWARD_CHECKSUMS,
STEWARD_CONTROL_PLANE_URL, STEWARD_CREDENTIAL_FILE,
STEWARD_EXECUTOR_CREDENTIAL_FILE, STEWARD_CA_FILE, STEWARD_EXECUTOR_TOKEN_FILE,
STEWARD_ADMISSION_POLICY_FILE, STEWARD_SITE_ROOT_PUBLIC_KEY_FILE,
STEWARD_SITE_ROOT_KEY_ID, STEWARD_NODE_ID, STEWARD_ALLOW_HOST_ADMIN_INTENT,
STEWARD_LOCAL_ONLY, STEWARD_INSTALL_GVISOR, STEWARD_GVISOR_DIR, and STEWARD_GVISOR_VERSION.

Supported node targets: Debian/Ubuntu (DEB), RHEL/Rocky/Alma/Fedora/Amazon Linux/
SUSE (RPM), and other systemd Linux distributions (tar), on amd64 or arm64.
Docker is a prerequisite. macOS and Windows are not Steward node targets.
EOF
}

version=${STEWARD_VERSION:-latest}
offline_dir=${STEWARD_OFFLINE_DIR:-}
artifact=${STEWARD_ARTIFACT:-}
checksums=${STEWARD_CHECKSUMS:-}
package_kind=auto
control_plane_url=${STEWARD_CONTROL_PLANE_URL:-}
steward_credential=${STEWARD_CREDENTIAL_FILE:-}
executor_credential=${STEWARD_EXECUTOR_CREDENTIAL_FILE:-}
ca_file=${STEWARD_CA_FILE:-}
executor_token=${STEWARD_EXECUTOR_TOKEN_FILE:-}
admission_policy=${STEWARD_ADMISSION_POLICY_FILE:-}
site_root=${STEWARD_SITE_ROOT_PUBLIC_KEY_FILE:-}
site_root_key_id=${STEWARD_SITE_ROOT_KEY_ID:-}
node_id=${STEWARD_NODE_ID:-}
allow_host_admin=${STEWARD_ALLOW_HOST_ADMIN_INTENT:-false}
gvisor_dir=${STEWARD_GVISOR_DIR:-}
gvisor_version=${STEWARD_GVISOR_VERSION:-latest}
install_gvisor=${STEWARD_INSTALL_GVISOR:-false}
non_interactive=false
stage_only=false
reuse_configuration=false
local_only=${STEWARD_LOCAL_ONLY:-false}
start_services=true
assume_yes=false
dry_run=false

valid_release_version() {
	local candidate=$1 core prerelease identifier
	[[ $candidate =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$ ]] || return 1
	core=${candidate#v}
	if [[ $core == *-* ]]; then
		prerelease=${core#*-}
		IFS=. read -r -a identifiers <<<"$prerelease"
		for identifier in "${identifiers[@]}"; do
			if [[ $identifier =~ ^[0-9]+$ && $identifier == 0[0-9]* ]]; then
				return 1
			fi
		done
	fi
	return 0
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--version) version=${2:-}; shift 2 ;;
		--offline-dir) offline_dir=${2:-}; shift 2 ;;
		--artifact) artifact=${2:-}; shift 2 ;;
		--checksums) checksums=${2:-}; shift 2 ;;
		--package) package_kind=${2:-}; shift 2 ;;
		--control-plane-url) control_plane_url=${2:-}; shift 2 ;;
		--steward-credential) steward_credential=${2:-}; shift 2 ;;
		--executor-credential) executor_credential=${2:-}; shift 2 ;;
		--ca-file) ca_file=${2:-}; shift 2 ;;
		--executor-token) executor_token=${2:-}; shift 2 ;;
		--admission-policy) admission_policy=${2:-}; shift 2 ;;
		--site-root-public-key) site_root=${2:-}; shift 2 ;;
		--site-root-key-id) site_root_key_id=${2:-}; shift 2 ;;
		--node-id) node_id=${2:-}; shift 2 ;;
		--allow-host-admin-intent) allow_host_admin=true; shift ;;
		--local-only) local_only=true; shift ;;
		--reuse-configuration) reuse_configuration=true; shift ;;
		--stage-only) stage_only=true; shift ;;
		--no-start) start_services=false; shift ;;
		--install-gvisor) install_gvisor=true; shift ;;
		--gvisor-dir) gvisor_dir=${2:-}; shift 2 ;;
		--gvisor-version) gvisor_version=${2:-}; shift 2 ;;
		--non-interactive) non_interactive=true; shift ;;
		--yes | -y) assume_yes=true; shift ;;
		--dry-run) dry_run=true; shift ;;
		-h | --help) usage; exit 0 ;;
		*) echo "install-steward: unknown option $1" >&2; usage >&2; exit 2 ;;
	esac
done

case "$package_kind" in auto | deb | rpm | tar) ;; *)
	echo "install-steward: --package must be auto, deb, rpm, or tar" >&2; exit 2 ;;
esac
case "$install_gvisor" in true | false) ;; *)
	echo "install-steward: STEWARD_INSTALL_GVISOR must be true or false" >&2; exit 2 ;;
esac
case "$local_only" in true | false) ;; *)
	echo "install-steward: STEWARD_LOCAL_ONLY must be true or false" >&2; exit 2 ;;
esac
case "$allow_host_admin" in true | false) ;; *)
	echo "install-steward: STEWARD_ALLOW_HOST_ADMIN_INTENT must be true or false" >&2; exit 2 ;;
esac
if [[ $gvisor_version != latest && ! $gvisor_version =~ ^[0-9]{8}(\.[0-9]+)?$ ]]; then
	echo "install-steward: --gvisor-version must be latest, YYYYMMDD, or YYYYMMDD.N" >&2
	exit 2
fi
if [[ -n $offline_dir && -n $artifact ]]; then
	echo "install-steward: choose --offline-dir or --artifact, not both" >&2
	exit 2
fi

machine=$(uname -m)
case "$machine" in
	x86_64 | amd64) goarch=amd64; gvisor_arch=x86_64 ;;
	aarch64 | arm64) goarch=arm64; gvisor_arch=aarch64 ;;
	*) echo "install-steward: unsupported architecture $machine" >&2; exit 2 ;;
esac

os_id=unknown
os_like=
if [[ -r /etc/os-release ]]; then
	# Values are distribution-owned data, used only for package selection.
	# shellcheck disable=SC1091
	source /etc/os-release
	os_id=${ID:-unknown}
	os_like=${ID_LIKE:-}
fi
if [[ $package_kind == auto ]]; then
	case " $os_id $os_like " in
		*" debian "* | *" ubuntu "*) package_kind=deb ;;
		*" rhel "* | *" fedora "* | *" centos "* | *" suse "*) package_kind=rpm ;;
		*) package_kind=tar ;;
	esac
fi
if [[ -n $artifact ]]; then
	case "$artifact" in
		*.deb) package_kind=deb ;;
		*.rpm) package_kind=rpm ;;
		*.tar.gz) package_kind=tar ;;
		*) echo "install-steward: artifact must end in .deb, .rpm, or .tar.gz" >&2; exit 2 ;;
	esac
	if [[ $version == latest ]]; then
		base=${artifact##*/}
		case "$package_kind" in
			deb | rpm) version=${base#steward-node_}; version=${version%_"$goarch".*} ;;
			tar) version=${base#steward_}; version=${version%_linux_"$goarch".tar.gz} ;;
		esac
	fi
fi

prompt() {
	local message=$1 default=${2:-} answer
	if [[ $non_interactive == true ]]; then
		return 1
	fi
	read -r -p "$message" answer </dev/tty
	printf '%s' "${answer:-$default}"
}
confirm() {
	local message=$1 default=${2:-yes} answer suffix=' [Y/n] '
	[[ $default == no ]] && suffix=' [y/N] '
	if [[ $assume_yes == true ]]; then return 0; fi
	if [[ $non_interactive == true ]]; then return 1; fi
	answer=$(prompt "$message$suffix" "$default")
	case "$answer" in y | Y | yes | YES | Yes) return 0 ;; *) return 1 ;; esac
}

if [[ $non_interactive == false && ! -r /dev/tty ]]; then
	echo "install-steward: no interactive terminal; pass --non-interactive" >&2
	exit 2
fi
if [[ $non_interactive == false ]]; then
	remote_inputs_supplied=false
	for value in "$control_plane_url" "$steward_credential" "$executor_credential" "$ca_file"; do
		[[ -z $value ]] || remote_inputs_supplied=true
	done
	echo "Steward guided node installation"
	echo "Detected: $os_id on $machine -> $package_kind package"
	version=$(prompt "Release version [latest]: " "$version")
	if [[ $stage_only == false ]]; then
		if [[ $remote_inputs_supplied == false && $local_only == false && \
			-f /etc/steward/uplink-credential.json && \
			-f /etc/steward/executor-uplink.json ]]; then
			if confirm "Reuse the existing Steward enrollment?" yes; then
				reuse_configuration=true
			fi
		fi
		if [[ $reuse_configuration == false ]]; then
			if [[ $remote_inputs_supplied == true ]]; then
			echo "Using the supplied remote-enrollment inputs."
			elif [[ $local_only == true ]]; then
				:
			elif confirm "Configure this as a local-only node (HTTP, CLI, and MCP)?" yes; then
				local_only=true
			elif ! confirm "Configure remote enrollment and activate this node now?" yes; then
				stage_only=true
			else
				control_plane_url=$(prompt "Control-plane HTTPS URL: " "$control_plane_url")
				steward_credential=$(prompt "Steward credential JSON path: " "$steward_credential")
				executor_credential=$(prompt "Executor credential JSON path: " "$executor_credential")
				ca_file=$(prompt "Control-plane CA PEM path: " "$ca_file")
				executor_token=$(prompt "Existing Executor token path [generate one]: " "$executor_token")
			fi
			if [[ $local_only == false && $stage_only == false && -z $admission_policy && -z $site_root && -z $site_root_key_id ]]; then
				admission_answer=$(prompt "Configure signed multi-tenant admission now? [y/N] " "no")
				case "$admission_answer" in
				y | Y | yes | YES | Yes)
					admission_policy=$(prompt "Signed site-policy DSSE path: " "$admission_policy")
					site_root=$(prompt "Site-root public key path: " "$site_root")
					site_root_key_id=$(prompt "Site-root key ID: " "$site_root_key_id")
					node_id=$(prompt "Stable node ID [derive from machine-id]: " "$node_id")
					;;
				esac
			fi
		fi
	fi
fi

remote_inputs_supplied=false
for value in "$control_plane_url" "$steward_credential" "$executor_credential" "$ca_file"; do
	[[ -z $value ]] || remote_inputs_supplied=true
done

if [[ $stage_only == true && $reuse_configuration == true ]]; then
	echo "install-steward: --stage-only and --reuse-configuration are mutually exclusive" >&2
	exit 2
fi
if [[ $local_only == true && $remote_inputs_supplied == true ]]; then
	echo "install-steward: --local-only cannot be combined with remote-enrollment inputs" >&2
	exit 2
fi
if [[ $reuse_configuration == true && $remote_inputs_supplied == true ]]; then
	echo "install-steward: --reuse-configuration cannot replace enrollment inputs in the same run" >&2
	exit 2
fi
if [[ $local_only == true && $reuse_configuration == true ]]; then
	echo "install-steward: --local-only and --reuse-configuration are mutually exclusive" >&2
	exit 2
fi
admission_required=0
for value in "$admission_policy" "$site_root" "$site_root_key_id"; do
	[[ -z $value ]] || ((admission_required += 1))
done
if (( admission_required != 0 && admission_required != 3 )); then
	echo "install-steward: signed admission requires --admission-policy, --site-root-public-key, and --site-root-key-id together" >&2
	exit 2
fi
if (( admission_required == 0 )) && { [[ -n $node_id ]] || [[ $allow_host_admin == true ]]; }; then
	echo "install-steward: --node-id and --allow-host-admin-intent require signed admission trust inputs" >&2
	exit 2
fi
if (( admission_required == 3 )); then
	[[ $site_root_key_id =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$ ]] || {
		echo "install-steward: invalid --site-root-key-id" >&2
		exit 2
	}
	if [[ -n $node_id && ! $node_id =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; then
		echo "install-steward: invalid --node-id" >&2
		exit 2
	fi
fi
if [[ $stage_only == true && $admission_required -ne 0 ]]; then
	echo "install-steward: --stage-only cannot configure signed admission; deliver trust after staging" >&2
	exit 2
fi
if [[ $stage_only == true && $remote_inputs_supplied == true ]]; then
	echo "install-steward: --stage-only cannot consume remote-enrollment inputs" >&2
	exit 2
fi
if [[ $reuse_configuration == true && $admission_required -ne 0 ]]; then
	echo "install-steward: --reuse-configuration cannot replace signed admission in the same run" >&2
	exit 2
fi
if [[ $stage_only == true && $install_gvisor == true ]]; then
	echo "install-steward: --stage-only and --install-gvisor are mutually exclusive" >&2
	exit 2
fi
if [[ $stage_only == false && $reuse_configuration == false && $local_only == false ]]; then
	for value in "$control_plane_url" "$steward_credential" "$executor_credential" "$ca_file"; do
		if [[ -z $value ]]; then
			echo "install-steward: full installation requires enrollment inputs (or --reuse-configuration)" >&2
			exit 2
		fi
	done
fi

if [[ $version != latest ]] && ! valid_release_version "$version"; then
	echo "install-steward: version must be latest or a vX.Y.Z release tag" >&2
	exit 2
fi

artifact_name_for() {
	case "$package_kind" in
		deb) printf 'steward-node_%s_%s.deb' "$version" "$goarch" ;;
		rpm) printf 'steward-node_%s_%s.rpm' "$version" "$goarch" ;;
		tar) printf 'steward_%s_linux_%s.tar.gz' "$version" "$goarch" ;;
	esac
}

if [[ $dry_run == true ]]; then
	if [[ $stage_only == true ]]; then
		enrollment_plan=staged-only
	elif [[ $reuse_configuration == true ]]; then
		enrollment_plan=reuse-existing
	elif [[ $local_only == true ]]; then
		enrollment_plan=local-only
	else
		enrollment_plan=provision-new
	fi
	echo "Install plan:"
	echo "  target:       $os_id/$goarch"
	echo "  package:      $package_kind"
	echo "  version:      $version"
	echo "  source:       ${artifact:-${offline_dir:-$release_url}}"
	echo "  enrollment:   $enrollment_plan"
	echo "  admission:    $([[ $admission_required -eq 3 ]] && printf 'signed' || printf 'unchanged')"
	echo "  service start: $start_services"
	echo "  gVisor install: $install_gvisor"
	exit 0
fi

if [[ ${EUID} -ne 0 ]]; then
	echo "install-steward: run as root (sudo bash install-steward.sh)" >&2
	exit 2
fi
if [[ $(uname -s) != Linux || ! -d /run/systemd/system ]]; then
	echo "install-steward: a systemd-based Linux host is required" >&2
	exit 2
fi
for command in docker systemctl getent useradd runuser; do
	command -v "$command" >/dev/null || {
		echo "install-steward: missing prerequisite $command" >&2
		exit 2
	}
done

# Fail before downloading or installing a package when enrollment material is
# not actually available. Dry-run intentionally exits above this point so CI
# and operators can inspect plans with placeholder paths.
if [[ $stage_only == false && $reuse_configuration == false ]]; then
	if [[ $local_only == false ]]; then
		for input in "$steward_credential" "$executor_credential" "$ca_file"; do
			if [[ ! -f $input || ! -r $input ]]; then
				echo "install-steward: enrollment input is not a readable regular file: $input" >&2
				exit 2
			fi
		done
	fi
	if [[ -n $executor_token && ( ! -f $executor_token || ! -r $executor_token ) ]]; then
		echo "install-steward: Executor token is not a readable regular file: $executor_token" >&2
		exit 2
	fi
	if (( admission_required == 3 )); then
		for input in "$admission_policy" "$site_root"; do
			if [[ ! -f $input || ! -r $input || -L $input ]]; then
				echo "install-steward: admission trust input must be a readable regular file, not a symlink: $input" >&2
				exit 2
			fi
		done
	fi
fi

has_runsc() {
	docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q '"runsc"'
}

if [[ $stage_only == false ]]; then
	docker info >/dev/null 2>&1 || {
		echo "install-steward: Docker is installed but the daemon is not reachable" >&2
		exit 2
	}
	if [[ $start_services == false ]] && \
		(systemctl is-active --quiet steward.service || \
			systemctl is-active --quiet steward-executor.service || \
			systemctl is-active --quiet steward-gateway.service); then
		echo "install-steward: --no-start requires all three Steward services to be stopped" >&2
		echo "  Use --stage-only to stage an upgrade without disrupting a running node." >&2
		exit 2
	fi
	if ! has_runsc && [[ $install_gvisor == false && $non_interactive == false ]]; then
		if confirm "Docker does not advertise runsc. Install and register official gVisor?" yes; then
			install_gvisor=true
		fi
	fi
	if ! has_runsc && [[ $install_gvisor != true ]]; then
		echo "install-steward: Docker runtime runsc is required; re-run with --install-gvisor" >&2
		exit 2
	fi
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/install-steward.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

fetch() {
	local url=$1 output=$2
	command -v curl >/dev/null || {
		echo "install-steward: curl is required for network installation; use --offline-dir instead" >&2
		exit 2
	}
	curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
		-o "$output" "$url"
}
hash_file() {
	if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null; then shasum -a 256 "$1" | awk '{print $1}'
	else echo "install-steward: sha256sum or shasum is required" >&2; exit 2
	fi
}
verify_sha256() {
	local file=$1 manifest=$2 base expected actual
	base=${file##*/}
	[[ -f $manifest ]] || { echo "install-steward: missing checksum manifest $manifest" >&2; exit 2; }
	expected=$(awk -v a="$base" '$2 == a || $2 == "./" a || $2 == "*" a { print $1 }' "$manifest")
	if [[ ! $expected =~ ^[0-9a-fA-F]{64}$ ]]; then
		echo "install-steward: manifest has no unique SHA-256 for $base" >&2
		exit 2
	fi
	actual=$(hash_file "$file")
	if [[ ${actual,,} != "${expected,,}" ]]; then
		echo "install-steward: SHA-256 mismatch for $base" >&2
		exit 1
	fi
	echo "install-steward: verified SHA-256 for $base"
}

install_deb() {
	local output="$work/dpkg-install.log" status deadline=$((SECONDS + 60))
	while true; do
		if STEWARD_EXPECTED_VERSION="$version" dpkg -i "$artifact" >"$output" 2>&1; then
			cat "$output"
			return 0
		else
			status=$?
		fi
		cat "$output" >&2
		if grep -q 'frontend lock was locked by another process' "$output" && \
			(( SECONDS < deadline )); then
			echo "install-steward: waiting for the operating system package manager" >&2
			sleep 2
			continue
		fi
		return "$status"
	done
}

install_gvisor_runtime() {
	local source_dir=$gvisor_dir runsc_path expected actual daemon_backup=
	if command -v runsc >/dev/null 2>&1; then
		runsc_path=$(command -v runsc)
		runsc_mode=$(stat -c '%a' "$runsc_path")
		if [[ ! -f $runsc_path || ! -x $runsc_path || $(stat -c '%u' "$runsc_path") -ne 0 ]] || \
			(( (8#$runsc_mode & 0022) != 0 )); then
			echo "install-steward: refusing non-root-owned or writable runsc at $runsc_path" >&2
			exit 2
		fi
	else
		if [[ -z $source_dir ]]; then
			if [[ -n $offline_dir ]]; then
				echo "install-steward: air-gapped gVisor install requires --gvisor-dir" >&2
				exit 2
			fi
			source_dir="$work/gvisor"
			mkdir -p "$source_dir"
			local base="https://storage.googleapis.com/gvisor/releases/release/${gvisor_version}/${gvisor_arch}"
			for name in runsc runsc.sha512 containerd-shim-runsc-v1 containerd-shim-runsc-v1.sha512; do
				fetch "$base/$name" "$source_dir/$name"
			done
		fi
		for name in runsc containerd-shim-runsc-v1; do
			[[ -f $source_dir/$name && -f $source_dir/$name.sha512 ]] || {
				echo "install-steward: gVisor directory is missing $name or $name.sha512" >&2; exit 2;
			}
			expected=$(awk 'NR == 1 { print $1 }' "$source_dir/$name.sha512")
			[[ $expected =~ ^[0-9a-fA-F]{128}$ ]] || {
				echo "install-steward: invalid SHA-512 manifest for $name" >&2; exit 2;
			}
			actual=$(sha512sum "$source_dir/$name" | awk '{print $1}')
			[[ ${actual,,} == "${expected,,}" ]] || {
				echo "install-steward: SHA-512 mismatch for $name" >&2; exit 1;
			}
		done
		install -o root -g root -m 0755 "$source_dir/runsc" /usr/local/bin/runsc
		install -o root -g root -m 0755 "$source_dir/containerd-shim-runsc-v1" \
			/usr/local/bin/containerd-shim-runsc-v1
		runsc_path=/usr/local/bin/runsc
	fi
	if [[ -e /etc/docker/daemon.json ]]; then
		daemon_backup="$work/daemon.json"
		cp -a /etc/docker/daemon.json "$daemon_backup"
	fi
	if ! "$runsc_path" install || ! systemctl reload docker.service; then
		if [[ -n $daemon_backup ]]; then cp -a "$daemon_backup" /etc/docker/daemon.json
		else rm -f /etc/docker/daemon.json
		fi
		systemctl reload docker.service >/dev/null 2>&1 || true
		echo "install-steward: gVisor registration failed; restored Docker configuration" >&2
		exit 1
	fi
	for _ in 1 2 3 4 5; do has_runsc && break; sleep 1; done
	has_runsc || { echo "install-steward: Docker still does not advertise runsc" >&2; exit 1; }
	echo "install-steward: Docker runtime runsc is ready"
}

if [[ -n $offline_dir ]]; then
	[[ -d $offline_dir ]] || { echo "install-steward: offline directory not found: $offline_dir" >&2; exit 2; }
	if [[ $version == latest ]]; then
		case "$package_kind" in
			deb) pattern="$offline_dir/steward-node_v*_${goarch}.deb" ;;
			rpm) pattern="$offline_dir/steward-node_v*_${goarch}.rpm" ;;
			tar) pattern="$offline_dir/steward_v*_linux_${goarch}.tar.gz" ;;
		esac
		mapfile -t candidates < <(compgen -G "$pattern" || true)
		if [[ ${#candidates[@]} -ne 1 ]]; then
			echo "install-steward: offline latest requires exactly one matching $package_kind artifact" >&2
			exit 2
		fi
		artifact=${candidates[0]}
		base=${artifact##*/}
		case "$package_kind" in
			deb | rpm) version=${base#steward-node_}; version=${version%_"$goarch".*} ;;
			tar) version=${base#steward_}; version=${version%_linux_"$goarch".tar.gz} ;;
		esac
	else
		artifact="$offline_dir/$(artifact_name_for)"
	fi
	checksums=${checksums:-$offline_dir/checksums.txt}
elif [[ -z $artifact ]]; then
	if [[ $version == latest ]]; then
		command -v curl >/dev/null || { echo "install-steward: curl is required to resolve latest" >&2; exit 2; }
		final=$(curl --fail --silent --show-error --location --head \
			--output /dev/null --write-out '%{url_effective}' "$release_url/latest")
		version=${final##*/}
	fi
	name=$(artifact_name_for)
	artifact="$work/$name"
	checksums="$work/checksums.txt"
	fetch "$release_url/download/$version/$name" "$artifact"
	fetch "$release_url/download/$version/checksums.txt" "$checksums"
	else
		checksums=${checksums:-"$(dirname "$artifact")/checksums.txt"}
fi

if ! valid_release_version "$version"; then
	echo "install-steward: resolved artifact version is not a valid release tag: $version" >&2
	exit 2
fi

[[ -f $artifact ]] || { echo "install-steward: artifact not found: $artifact" >&2; exit 2; }
verify_sha256 "$artifact" "$checksums"

echo "Install summary: $version, $package_kind, $goarch, source $artifact"
if ! confirm "Proceed with host installation?" yes && [[ $non_interactive == false ]]; then
	echo "install-steward: cancelled"
	exit 0
fi

if [[ $stage_only == false ]] && ! has_runsc; then install_gvisor_runtime; fi

case "$package_kind" in
	deb)
		command -v dpkg >/dev/null || { echo "install-steward: dpkg is required" >&2; exit 2; }
		install_deb
		;;
	rpm)
		command -v rpm >/dev/null || { echo "install-steward: rpm is required" >&2; exit 2; }
		STEWARD_EXPECTED_VERSION="$version" rpm -Uvh "$artifact"
		;;
	tar)
		archive_dir="$work/archive"
		mkdir -p "$archive_dir"
		if tar -tzf "$artifact" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
			echo "install-steward: archive contains an unsafe path" >&2
			exit 1
		fi
		tar -xzf "$artifact" -C "$archive_dir"
		STEWARD_EXPECTED_VERSION="$version" bash "$archive_dir/scripts/install-node.sh" \
			--expected-version "$version"
		;;
esac

installed_manifest="/opt/steward/releases/$version/release.json"
if [[ ! -f $installed_manifest || -L $installed_manifest ]]; then
	echo "install-steward: installed release is missing regular file $installed_manifest" >&2
	exit 1
fi
installed_version=$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' "$installed_manifest")
if [[ $installed_version != "$version" ]]; then
	echo "install-steward: installed manifest reports '${installed_version:-<invalid>}', expected '$version'" >&2
	exit 1
fi

if [[ $stage_only == true ]]; then
	echo "install-steward: $version is installed but not configured or started; upgrades remain staged"
	exit 0
fi

if [[ $reuse_configuration == true ]]; then
	/usr/local/libexec/steward/node-preflight
else
	if [[ $local_only == true ]]; then
		configure_args=(--local-only --no-start)
	else
		configure_args=(
			--control-plane-url "$control_plane_url"
			--steward-credential "$steward_credential"
			--executor-credential "$executor_credential"
			--ca-file "$ca_file"
			--no-start
		)
	fi
	if [[ -n $executor_token ]]; then
		configure_args+=(--executor-token "$executor_token")
	fi
	if (( admission_required == 3 )); then
		configure_args+=(
			--admission-policy "$admission_policy"
			--site-root-public-key "$site_root"
			--site-root-key-id "$site_root_key_id"
		)
		[[ -z $node_id ]] || configure_args+=(--node-id "$node_id")
		[[ $allow_host_admin == false ]] || configure_args+=(--allow-host-admin-intent)
	fi
	/usr/local/libexec/steward/configure-node "${configure_args[@]}"
fi

if [[ $start_services == true ]]; then
	"/opt/steward/releases/$version/integration/scripts/activate-node-release.sh" "$version" --restart
	systemctl enable --now steward-gateway.service steward.service steward-executor.service
	echo "install-steward: Steward $version is installed, configured, and running"
else
	"/opt/steward/releases/$version/integration/scripts/activate-node-release.sh" "$version"
	echo "install-steward: Steward $version is installed and active; service enablement was not changed"
fi
