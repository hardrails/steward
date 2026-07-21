#!/bin/bash -p
# Install, configure, validate, and optionally start a Steward node.
set -Eeuo pipefail
set +x
if ! shopt -qo privileged; then
	echo "install-steward: invoke this installer with /bin/bash -p or execute it directly so caller-controlled shell startup files and exported functions are ignored" >&2
	exit 2
fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C LANG=C
unset BASH_ENV ENV CDPATH GLOBIGNORE CURL_HOME XDG_CONFIG_HOME
unset CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR
unset TAR_OPTIONS GZIP POSIXLY_CORRECT TMPDIR
IFS=$' \t\n'
umask 077

readonly project_url=https://github.com/hardrails/steward
readonly release_url="$project_url/releases"
readonly max_manifest_bytes=4194304
readonly max_artifact_bytes=268435456
readonly max_gvisor_manifest_bytes=1048576
readonly max_gvisor_binary_bytes=268435456

usage() {
	cat <<'EOF'
Install Steward on a supported Linux server.

Usage:
  sudo /bin/bash -p install-steward.sh                 # interactive guided install
  sudo /bin/bash -p install-steward.sh --non-interactive OPTIONS

Artifact source:
  --version VERSION             Release tag (default: latest)
  --offline-dir DIR             Directory containing checksums.txt and release assets
  --artifact FILE               Exact DEB, RPM, or Linux tar.gz to install
  --checksums FILE              SHA-256 manifest; --artifact defaults to checksums.txt beside it
  --package auto|deb|rpm|tar    Override host package selection

Node enrollment:
  --control-plane-url URL       HTTPS control-plane base URL
  --steward-credential FILE     Optional supervisor uplink credential JSON.
                                Omit with bundled steward-control; the
                                supervisor remains loopback-only.
  --executor-credential FILE    Executor uplink credential JSON
  --ca-file FILE                PEM CA bundle for the control plane
  --executor-token FILE         Host-admin local token (securely generated if omitted)
  --admission-policy FILE       Signed site policy (with both site-root flags)
  --site-root-public-key FILE   Base64 Ed25519 site-root public key
  --site-root-key-id ID         Signature key ID used by the policy
  --node-id ID                  Stable node ID (machine-derived if omitted)
  --executor-evidence-config FILE
                                Evidence config emitted by enrollment exchange
  --executor-evidence-private-key FILE
                                Receipt private key used during enrollment
  --executor-evidence-public-key FILE
                                Matching receipt public key
  --allow-host-admin-intent     Let the host-admin token select signed tenant intent
  --allow-unquotaed-state-on-dedicated-host
                                Allow persistent Docker volumes only when the
                                signed policy contains exactly one tenant; no
                                hard byte or inode quota is enforced
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
STEWARD_SITE_ROOT_KEY_ID, STEWARD_NODE_ID, STEWARD_EXECUTOR_EVIDENCE_CONFIG_FILE,
STEWARD_EXECUTOR_EVIDENCE_PRIVATE_KEY_FILE, STEWARD_EXECUTOR_EVIDENCE_PUBLIC_KEY_FILE,
STEWARD_ALLOW_HOST_ADMIN_INTENT,
STEWARD_ALLOW_UNQUOTAED_STATE_ON_DEDICATED_HOST,
STEWARD_LOCAL_ONLY, STEWARD_INSTALL_GVISOR, STEWARD_GVISOR_DIR, and STEWARD_GVISOR_VERSION.

Supported node targets: Debian/Ubuntu (DEB), RHEL/Rocky/Alma/Fedora/Amazon Linux/
SUSE (RPM), and other systemd Linux distributions (tar), on amd64 or arm64.
Docker is a prerequisite. macOS and Windows are not Steward node targets.
Bundled steward-control enrollment requires a node-scoped Executor credential
and the three signed-admission trust inputs. It does not use a supervisor credential.
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
executor_evidence_config=${STEWARD_EXECUTOR_EVIDENCE_CONFIG_FILE:-}
receipt_private=${STEWARD_EXECUTOR_EVIDENCE_PRIVATE_KEY_FILE:-}
receipt_public=${STEWARD_EXECUTOR_EVIDENCE_PUBLIC_KEY_FILE:-}
allow_host_admin=${STEWARD_ALLOW_HOST_ADMIN_INTENT:-false}
allow_unquotaed_state=${STEWARD_ALLOW_UNQUOTAED_STATE_ON_DEDICATED_HOST:-false}
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
	(( ${#candidate} <= 128 )) || return 1
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

trusted_root_directory_chain() {
	local directory=$1 current metadata uid mode
	[[ -d $directory && ! -L $directory && $(readlink -e -- "$directory" 2>/dev/null) == "$directory" ]] || return 1
	current=$directory
	while :; do
		metadata=$(stat -c '%u:%a' -- "$current") || return 1
		uid=${metadata%%:*}
		mode=${metadata#*:}
		if [[ $uid != 0 ]] || (( (8#$mode & 022) != 0 )); then return 1; fi
		[[ $current == / ]] && break
		current=$(dirname -- "$current")
	done
}

trusted_local_file() {
	local source=$1 max_bytes=$2 metadata uid mode links size parent
	[[ $source == /* && -f $source && ! -L $source &&
		$(readlink -e -- "$source" 2>/dev/null) == "$source" ]] || return 1
	parent=$(dirname -- "$source")
	trusted_root_directory_chain "$parent" || return 1
	metadata=$(stat -c '%u:%a:%h:%s' -- "$source") || return 1
	IFS=: read -r uid mode links size <<<"$metadata"
	[[ $uid == 0 && $links == 1 ]] || return 1
	(( (8#$mode & 022) == 0 && size > 0 && size <= max_bytes ))
}

bounded_snapshot() {
	local source=$1 destination=$2 max_bytes=$3 timeout_seconds=$4
	local before after source_size output_blocks block_size=1048576 block_count
	[[ $max_bytes =~ ^[0-9]+$ && $timeout_seconds =~ ^[0-9]+$ ]] || return 1
	(( max_bytes > 0 && max_bytes % 1024 == 0 && timeout_seconds > 0 )) || return 1
	trusted_local_file "$source" "$max_bytes" || return 1
	before=$(stat -c '%d:%i:%s:%u:%g:%a:%h:%y:%z' -- "$source") || return 1
	source_size=$(stat -c '%s' -- "$source") || return 1
	(( source_size > 0 && source_size <= max_bytes )) || return 1
	output_blocks=$((max_bytes / 1024))
	block_count=$(((max_bytes + block_size - 1) / block_size + 1))
	rm -f -- "$destination"
	if ! (
		set -o noclobber
		exec >"$destination"
		ulimit -c 0
		ulimit -f "$output_blocks"
		exec timeout --signal=TERM --kill-after=5 "$timeout_seconds" \
			dd if="$source" bs="$block_size" count="$block_count" \
			iflag=nofollow,nonblock,fullblock status=none
	); then
		rm -f -- "$destination"
		return 1
	fi
	after=$(stat -c '%d:%i:%s:%u:%g:%a:%h:%y:%z' -- "$source") || {
		rm -f -- "$destination"
		return 1
	}
	if [[ $before != "$after" || ! -f $destination || -L $destination ||
		$(stat -c '%u:%g:%a:%h:%s' -- "$destination") != "0:0:600:1:$source_size" ]]; then
		rm -f -- "$destination"
		return 1
	fi
}

download() {
	local url=$1 output=$2 limit=$3 output_blocks size
	[[ $limit =~ ^[0-9]+$ ]] && (( limit > 0 && limit % 1024 == 0 )) || return 1
	output_blocks=$((limit / 1024))
	rm -f -- "$output"
	if ! (
		ulimit -c 0
		ulimit -f "$output_blocks"
		exec timeout --signal=TERM --kill-after=5 190 \
			curl -q --proto '=https' --tlsv1.2 --location --fail --silent --show-error \
			--retry 3 --retry-connrefused --connect-timeout 15 --max-time 180 \
			--max-filesize "$limit" --output "$output" "$url"
	); then
		rm -f -- "$output"
		return 1
	fi
	if [[ ! -f $output || -L $output ]]; then
		rm -f -- "$output"
		return 1
	fi
	size=$(stat -c '%s' -- "$output") || {
		rm -f -- "$output"
		return 1
	}
	if (( size <= 0 || size > limit )) ||
		[[ $(stat -c '%u:%g:%a:%h' -- "$output") != 0:0:600:1 ]]; then
		rm -f -- "$output"
		return 1
	fi
}

run_bounded_command() {
	local stdout=$1 stderr=$2 max_bytes=$3 file_limit_bytes=$4 timeout_seconds=$5 memory_kib=$6
	local output_blocks path size
	shift 6
	[[ $max_bytes =~ ^[0-9]+$ && $file_limit_bytes =~ ^[0-9]+$ &&
		$timeout_seconds =~ ^[0-9]+$ && $memory_kib =~ ^[0-9]+$ ]] || return 1
	(( max_bytes > 0 && file_limit_bytes >= max_bytes && file_limit_bytes % 1024 == 0 &&
		timeout_seconds > 0 && memory_kib > 0 )) || return 1
	output_blocks=$((file_limit_bytes / 1024))
	rm -f -- "$stdout" "$stderr"
	if ! (
		ulimit -c 0
		ulimit -f "$output_blocks"
		ulimit -v "$memory_kib"
		exec timeout --signal=TERM --kill-after=5 "$timeout_seconds" "$@"
	) >"$stdout" 2>"$stderr"; then
		rm -f -- "$stdout" "$stderr"
		return 1
	fi
	for path in "$stdout" "$stderr"; do
		if [[ ! -f $path || -L $path || $(stat -c '%u:%g:%a:%h' -- "$path") != 0:0:600:1 ]]; then
			rm -f -- "$stdout" "$stderr"
			return 1
		fi
		size=$(stat -c '%s' -- "$path") || {
			rm -f -- "$stdout" "$stderr"
			return 1
		}
		if (( size > max_bytes )); then
			rm -f -- "$stdout" "$stderr"
			return 1
		fi
	done
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
		--executor-evidence-config) executor_evidence_config=${2:-}; shift 2 ;;
		--executor-evidence-private-key) receipt_private=${2:-}; shift 2 ;;
		--executor-evidence-public-key) receipt_public=${2:-}; shift 2 ;;
		--allow-host-admin-intent) allow_host_admin=true; shift ;;
		--allow-unquotaed-state-on-dedicated-host) allow_unquotaed_state=true; shift ;;
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
case "$allow_unquotaed_state" in true | false) ;; *)
	echo "install-steward: STEWARD_ALLOW_UNQUOTAED_STATE_ON_DEDICATED_HOST must be true or false" >&2
	exit 2
	;;
esac
if (( ${#gvisor_version} > 64 )) ||
	[[ $gvisor_version != latest && ! $gvisor_version =~ ^[0-9]{8}(\.[0-9]+)?$ ]]; then
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
if [[ $package_kind == auto ]]; then
	# Never source os-release: images and host configuration are untrusted input,
	# and that file is shell-like text. Presence of the package manager is enough
	# to select a package format without evaluating host-controlled statements.
	if [[ -x /usr/bin/dpkg ]]; then
		os_id=debian-family
		package_kind=deb
	elif [[ -x /usr/bin/rpm || -x /bin/rpm ]]; then
		os_id=rpm-family
		package_kind=rpm
	else
		package_kind=tar
	fi
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
	for value in "$control_plane_url" "$steward_credential" "$executor_credential" "$ca_file" \
		"$executor_evidence_config" "$receipt_private" "$receipt_public"; do
		[[ -z $value ]] || remote_inputs_supplied=true
	done
	echo "Steward guided node installation"
	echo "Detected: $os_id on $machine -> $package_kind package"
	version=$(prompt "Release version [latest]: " "$version")
	if [[ $stage_only == false ]]; then
		if [[ $remote_inputs_supplied == false && $local_only == false && \
			-f /etc/steward/executor-uplink.json && \
			-f /etc/steward/control-plane-ca.pem ]]; then
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
				if confirm "Use bundled steward-control (signed Executor control; local supervisor)?" yes; then
					steward_credential=
					echo "The supervisor will listen only on loopback, keep durable local state, and reject process execution."
				else
					steward_credential=$(prompt "Generic supervisor uplink credential JSON path: " "$steward_credential")
				fi
				executor_credential=$(prompt "Executor credential JSON path: " "$executor_credential")
				ca_file=$(prompt "Control-plane CA PEM path: " "$ca_file")
				executor_token=$(prompt "Existing Executor token path [generate one]: " "$executor_token")
			fi
			if [[ $local_only == false && $stage_only == false && -z $admission_policy && -z $site_root && -z $site_root_key_id ]]; then
				if [[ -z $steward_credential ]]; then
					echo "Bundled steward-control requires signed admission and a node-scoped Executor credential."
					admission_policy=$(prompt "Signed site-policy DSSE path: " "$admission_policy")
					site_root=$(prompt "Site-root public key path: " "$site_root")
					site_root_key_id=$(prompt "Site-root key ID: " "$site_root_key_id")
					node_id=$(prompt "Stable node ID [derive from machine-id]: " "$node_id")
					executor_evidence_config=$(prompt "Executor evidence enrollment config path: " "$executor_evidence_config")
					receipt_private=$(prompt "Executor receipt private key path: " "$receipt_private")
					receipt_public=$(prompt "Executor receipt public key path: " "$receipt_public")
				else
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
fi

remote_inputs_supplied=false
for value in "$control_plane_url" "$steward_credential" "$executor_credential" "$ca_file" \
	"$executor_evidence_config" "$receipt_private" "$receipt_public"; do
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
executor_only_remote=false
if [[ $stage_only == false && $reuse_configuration == false && \
	$local_only == false && -z $steward_credential ]]; then
	executor_only_remote=true
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
if (( admission_required == 0 )) && [[ $allow_unquotaed_state == true ]]; then
	echo "install-steward: --allow-unquotaed-state-on-dedicated-host requires signed admission trust inputs" >&2
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
evidence_input_count=0
for value in "$executor_evidence_config" "$receipt_private" "$receipt_public"; do
	[[ -z $value ]] || ((evidence_input_count += 1))
done
if (( evidence_input_count != 0 && evidence_input_count != 3 )); then
	echo "install-steward: Executor evidence enrollment requires config, private key, and public key together" >&2
	exit 2
fi
if (( evidence_input_count == 3 && admission_required != 3 )); then
	echo "install-steward: Executor evidence enrollment requires signed-admission trust inputs" >&2
	exit 2
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
	for value in "$control_plane_url" "$executor_credential" "$ca_file"; do
		if [[ -z $value ]]; then
			echo "install-steward: remote installation requires --control-plane-url, --executor-credential, and --ca-file (or --reuse-configuration)" >&2
			exit 2
		fi
	done
fi
if [[ $executor_only_remote == true && $admission_required -ne 3 ]]; then
	echo "install-steward: bundled steward-control enrollment requires complete signed-admission inputs" >&2
	echo "  Pass --admission-policy, --site-root-public-key, and --site-root-key-id." >&2
	exit 2
fi
if [[ $executor_only_remote == true && $evidence_input_count -ne 3 ]]; then
	echo "install-steward: bundled steward-control enrollment requires the Executor evidence config and receipt key pair" >&2
	exit 2
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

find_deployed_control_plane_marker() {
	local marker
	for marker in "$@"; do
		if [[ -e $marker || -L $marker ]]; then
			printf '%s\n' "$marker"
			return 0
		fi
	done
	return 1
}

readonly host_role_runtime_dir=/run/steward-host-role
readonly host_role_lock_file=$host_role_runtime_dir/role.lock
readonly node_role_claim_dir=/var/lib/steward-node-installer
readonly node_role_claim_file=$node_role_claim_dir/claim

acquire_host_role_lock() {
	local metadata uid mode path_metadata fd_metadata process_id=${BASHPID:-$$}
	[[ -d /run && ! -L /run && $(readlink -e -- /run 2>/dev/null) == /run ]] || return 1
	metadata=$(stat -c '%u:%a' -- /run) || return 1
	uid=${metadata%%:*}; mode=${metadata#*:}
	[[ $uid == 0 ]] && (( (8#$mode & 022) == 0 )) || return 1
	if [[ ! -e $host_role_runtime_dir && ! -L $host_role_runtime_dir ]]; then
		install -d -o root -g root -m 0700 -- "$host_role_runtime_dir"
	fi
	[[ -d $host_role_runtime_dir && ! -L $host_role_runtime_dir &&
		$(readlink -e -- "$host_role_runtime_dir" 2>/dev/null) == "$host_role_runtime_dir" &&
		$(stat -c '%u:%g:%a' -- "$host_role_runtime_dir" 2>/dev/null) == 0:0:700 ]] || return 1
	if [[ ! -e $host_role_lock_file && ! -L $host_role_lock_file ]]; then
		(umask 077; set -o noclobber; : >"$host_role_lock_file") 2>/dev/null || true
	fi
	[[ -f $host_role_lock_file && ! -L $host_role_lock_file &&
		$(stat -c '%u:%g:%a:%h' -- "$host_role_lock_file" 2>/dev/null) == 0:0:600:1 ]] || return 1
	exec 6<>"$host_role_lock_file"
	path_metadata=$(stat -c '%d:%i:%u:%g:%a:%h' -- "$host_role_lock_file") || return 1
	fd_metadata=$(stat -Lc '%d:%i:%u:%g:%a:%h' -- "/proc/$process_id/fd/6") || return 1
	[[ $path_metadata == "$fd_metadata" && $path_metadata == *:0:0:600:1 ]] || return 1
	flock -w 60 6
}

create_node_role_claim() {
	trusted_root_directory_chain /var/lib || return 1
	if [[ ! -e $node_role_claim_dir && ! -L $node_role_claim_dir ]]; then
		install -d -o root -g root -m 0700 -- "$node_role_claim_dir"
	fi
	[[ -d $node_role_claim_dir && ! -L $node_role_claim_dir &&
		$(readlink -e -- "$node_role_claim_dir" 2>/dev/null) == "$node_role_claim_dir" &&
		$(stat -c '%u:%g:%a' -- "$node_role_claim_dir" 2>/dev/null) == 0:0:700 ]] || return 1
	if [[ ! -e $node_role_claim_file && ! -L $node_role_claim_file ]]; then
		(umask 077; set -o noclobber; printf 'steward.node-role-claim.v1\n' >"$node_role_claim_file") || return 1
	fi
	[[ -f $node_role_claim_file && ! -L $node_role_claim_file &&
		$(stat -c '%u:%g:%a:%h:%s' -- "$node_role_claim_file" 2>/dev/null) == 0:0:600:1:27 &&
		$(<"$node_role_claim_file") == steward.node-role-claim.v1 ]] || return 1
	sync -f "$node_role_claim_file"
	sync -f "$node_role_claim_dir"
}

if control_plane_marker=$(find_deployed_control_plane_marker \
	/opt/steward-control \
	/etc/steward-control \
	/var/lib/steward-control-installer \
	/etc/systemd/system/steward-control.service \
	/usr/local/libexec/steward-control); then
	echo "install-steward: refusing to install a node over the deployed Steward control plane marker $control_plane_marker" >&2
	echo "  Run Steward Control and Steward nodes on separate management hosts; both products own /usr/local/bin/steward-control." >&2
	exit 2
fi

if [[ $dry_run == true ]]; then
	if [[ $stage_only == true ]]; then
		enrollment_plan=staged-only
	elif [[ $reuse_configuration == true ]]; then
		enrollment_plan=reuse-existing
	elif [[ $local_only == true ]]; then
		enrollment_plan=local-only
	elif [[ $executor_only_remote == true ]]; then
		enrollment_plan=bundled-control-executor-only
	else
		enrollment_plan=generic-supervisor-and-executor
	fi
	echo "Install plan:"
	echo "  target:       $os_id/$goarch"
	echo "  package:      $package_kind"
	echo "  version:      $version"
	echo "  source:       ${artifact:-${offline_dir:-$release_url}}"
	echo "  enrollment:   $enrollment_plan"
	echo "  admission:    $([[ $admission_required -eq 3 ]] && printf 'signed' || printf 'unchanged')"
	echo "  evidence:     $([[ $evidence_input_count -eq 3 ]] && printf 'witnessed-uplink' || printf 'disabled')"
	echo "  state:        $([[ $allow_unquotaed_state == true ]] && printf 'dedicated-host-unquotaed' || printf 'disabled')"
	effective_service_start=$start_services
	[[ $stage_only == false ]] || effective_service_start=false
	echo "  service start: $effective_service_start"
	echo "  gVisor install: $install_gvisor"
	exit 0
fi

if [[ ${EUID} -ne 0 ]]; then
	echo "install-steward: run as root (sudo /bin/bash -p install-steward.sh)" >&2
	exit 2
fi
if [[ $(uname -s) != Linux || ! -d /run/systemd/system ]]; then
	echo "install-steward: a systemd-based Linux host is required" >&2
	exit 2
fi
for local_command_dir in /usr/local/sbin /usr/local/bin; do
	if [[ -d $local_command_dir ]] && trusted_root_directory_chain "$local_command_dir"; then
		PATH+=":$local_command_dir"
	fi
done
export PATH
for command in awk dd docker getent install readlink runuser stat sync systemctl timeout useradd; do
	command -v "$command" >/dev/null || {
		echo "install-steward: missing prerequisite $command" >&2
		exit 2
	}
done

work=$(mktemp -d /run/install-steward.XXXXXX)
if [[ ! -d $work || -L $work || $(readlink -e -- "$work" 2>/dev/null) != "$work" ||
	$(stat -c '%u:%g:%a' -- "$work") != 0:0:700 ]]; then
	echo "install-steward: could not create a trusted root-only work directory" >&2
	exit 1
fi
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

# Fail before downloading or installing a package when enrollment material is
# not actually available. Dry-run intentionally exits above this point so CI
# and operators can inspect plans with placeholder paths.
if [[ $stage_only == false && $reuse_configuration == false ]]; then
	if [[ $local_only == false ]]; then
		for input in "$executor_credential" "$ca_file"; do
			if [[ ! -f $input || ! -r $input ]]; then
				echo "install-steward: Executor enrollment input is not a readable regular file: $input" >&2
				exit 2
			fi
		done
		if [[ -n $steward_credential && ( ! -f $steward_credential || ! -r $steward_credential ) ]]; then
			echo "install-steward: supervisor credential is not a readable regular file: $steward_credential" >&2
			exit 2
		fi
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
	if (( evidence_input_count == 3 )); then
		for input in "$executor_evidence_config" "$receipt_private" "$receipt_public"; do
			if [[ ! -f $input || ! -r $input || -L $input ]]; then
				echo "install-steward: Executor evidence input must be a readable regular file, not a symlink: $input" >&2
				exit 2
			fi
		done
	fi
fi

bounded_docker_info() {
	local output=$1 format=$2
	run_bounded_command "$output" "$work/docker-info.stderr" \
		65536 65536 15 262144 \
		docker info --format "$format"
}

docker_daemon_reachable() {
	bounded_docker_info "$work/docker-version.stdout" '{{.ServerVersion}}'
}

has_runsc() {
	bounded_docker_info "$work/docker-runtimes.stdout" '{{json .Runtimes}}' &&
		grep -m 1 -Fq '"runsc"' "$work/docker-runtimes.stdout"
}

if [[ $stage_only == false ]]; then
	docker_daemon_reachable || {
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

fetch() {
	local url=$1 output=$2 limit=$3
	command -v curl >/dev/null || {
		echo "install-steward: curl is required for network installation; use --offline-dir instead" >&2
		exit 2
	}
	if ! download "$url" "$output" "$limit"; then
		echo "install-steward: bounded download failed for $url" >&2
		exit 1
	fi
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

extract_verified_node_archive() {
	local archive=$1 destination=$2 entry permissions owner size date time name
	local entry_count=0 metadata_count=0 total_size=0
	local saw_manifest=false saw_installer=false
	declare -A listed=() described=()
	if ! run_bounded_command "$work/archive.list" "$work/archive.list.stderr" \
		4194304 4194304 60 524288 \
		env -u TAR_OPTIONS -u GZIP -u POSIXLY_CORRECT tar -tzf "$archive" ||
		[[ -s $work/archive.list.stderr ]]; then
		echo "install-steward: archive inventory failed, emitted warnings, or exceeded its resource bounds" >&2
		return 1
	fi
	while IFS= read -r entry; do
		((entry_count += 1))
		if (( entry_count > 4096 || ${#entry} == 0 || ${#entry} > 1024 )) ||
			[[ ! $entry =~ ^[A-Za-z0-9._/+:-]+$ || $entry == /* || $entry == ./* ||
			$entry == *//* || $entry == ../* || $entry == */../* || $entry == */.. ||
			$entry == */./* || $entry == */. || ${listed[$entry]+present} == present ]]; then
			echo "install-steward: archive inventory contains an unsafe or duplicate path" >&2
			return 1
		fi
		listed[$entry]=1
		[[ $entry == release.json ]] && saw_manifest=true
		[[ $entry == scripts/install-node.sh ]] && saw_installer=true
	done <"$work/archive.list"
	if (( entry_count == 0 )) || [[ $saw_manifest != true || $saw_installer != true ]]; then
		echo "install-steward: archive inventory is incomplete" >&2
		return 1
	fi
	if ! run_bounded_command "$work/archive.verbose" "$work/archive.verbose.stderr" \
		4194304 4194304 60 524288 \
		env -u TAR_OPTIONS -u GZIP -u POSIXLY_CORRECT tar --numeric-owner -tvzf "$archive" ||
		[[ -s $work/archive.verbose.stderr ]]; then
		echo "install-steward: archive metadata failed, emitted warnings, or exceeded its resource bounds" >&2
		return 1
	fi
	while read -r permissions owner size date time name; do
		: "$owner" "$date" "$time"
		((metadata_count += 1))
		if [[ -z $name ]]; then
			echo "install-steward: archive metadata contains an empty path" >&2
			return 1
		fi
		if [[ ${listed[$name]+present} != present || ${described[$name]+present} == present ||
			! $size =~ ^[0-9]+$ ]]; then
			echo "install-steward: archive metadata does not match its inventory" >&2
			return 1
		fi
		described[$name]=1
		case "$permissions" in
			-*)
				(( size <= max_artifact_bytes )) || {
					echo "install-steward: archive member exceeds the per-file size bound" >&2
					return 1
				}
				((total_size += size))
				(( total_size <= 1073741824 )) || {
					echo "install-steward: archive exceeds the expanded-size bound" >&2
					return 1
				}
				;;
			d*) (( size == 0 )) || {
				echo "install-steward: archive directory has invalid metadata" >&2
				return 1
			} ;;
			*)
				echo "install-steward: archive contains a link or special entry" >&2
				return 1
				;;
		esac
	done <"$work/archive.verbose"
	if (( metadata_count != entry_count )); then
		echo "install-steward: archive metadata count does not match its inventory" >&2
		return 1
	fi
	if ! run_bounded_command "$work/archive.extract.stdout" "$work/archive.extract.stderr" \
		1048576 "$max_artifact_bytes" 180 524288 \
		env -u TAR_OPTIONS -u GZIP -u POSIXLY_CORRECT tar --extract --gzip \
		--file "$archive" --directory "$destination" --no-same-owner \
		--no-same-permissions --delay-directory-restore ||
		[[ -s $work/archive.extract.stdout || -s $work/archive.extract.stderr ]]; then
		echo "install-steward: archive extraction failed, emitted output, or exceeded its resource bounds" >&2
		return 1
	fi
	[[ -f $destination/release.json && ! -L $destination/release.json &&
		-f $destination/scripts/install-node.sh && ! -L $destination/scripts/install-node.sh ]]
}

install_deb() {
	local output="$work/dpkg-install.log" status deadline=$((SECONDS + 60))
	while true; do
		if STEWARD_EXPECTED_VERSION="$version" STEWARD_NODE_ID="$node_id" dpkg -i "$artifact" >"$output" 2>&1; then
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
	local source_dir=$gvisor_dir safe_source_dir runsc_path expected actual name limit resolved
	local daemon_file=/etc/docker/daemon.json daemon_work="$work/daemon.json"
	local daemon_original="$work/daemon.original.json"
	local daemon_pending=/etc/docker/.daemon.json.steward-install daemon_existed=false
	local daemon_metadata daemon_gid=0 daemon_mode=644 daemon_size
	if command -v runsc >/dev/null 2>&1; then
		runsc_path=$(command -v runsc)
		runsc_mode=$(stat -c '%a' "$runsc_path")
		if [[ ! -f $runsc_path || ! -x $runsc_path || $(stat -c '%u' "$runsc_path") -ne 0 ]] || \
			(( (8#$runsc_mode & 0022) != 0 )); then
			echo "install-steward: refusing non-root-owned or writable runsc at $runsc_path" >&2
			exit 2
		fi
	else
		command -v sha512sum >/dev/null 2>&1 || {
			echo "install-steward: sha512sum is required to install gVisor" >&2
			exit 2
		}
		safe_source_dir="$work/gvisor-input"
		install -d -m 0700 "$safe_source_dir"
		if [[ -z $source_dir ]]; then
			if [[ -n $offline_dir ]]; then
				echo "install-steward: air-gapped gVisor install requires --gvisor-dir" >&2
				exit 2
			fi
			local base="https://storage.googleapis.com/gvisor/releases/release/${gvisor_version}/${gvisor_arch}"
			for name in runsc runsc.sha512 containerd-shim-runsc-v1 containerd-shim-runsc-v1.sha512; do
				case "$name" in *.sha512) limit=$max_gvisor_manifest_bytes ;; *) limit=$max_gvisor_binary_bytes ;; esac
				fetch "$base/$name" "$safe_source_dir/$name" "$limit"
			done
		else
			if [[ ! -d $source_dir || -L $source_dir ]]; then
				echo "install-steward: gVisor source must be a real directory" >&2
				exit 2
			fi
			source_dir=$(readlink -e -- "$source_dir")
			if ! trusted_root_directory_chain "$source_dir"; then
				echo "install-steward: gVisor source and every ancestor must be root-owned and not group- or world-writable" >&2
				exit 2
			fi
			for name in runsc runsc.sha512 containerd-shim-runsc-v1 containerd-shim-runsc-v1.sha512; do
				case "$name" in *.sha512) limit=$max_gvisor_manifest_bytes ;; *) limit=$max_gvisor_binary_bytes ;; esac
				if ! resolved=$(resolve_local_file "$source_dir/$name") ||
					! bounded_snapshot "$resolved" "$safe_source_dir/$name" "$limit" 120; then
					echo "install-steward: gVisor input $name must be a bounded, root-owned, one-link regular file under the trusted source path" >&2
					exit 1
				fi
			done
		fi
		source_dir=$safe_source_dir
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
	trusted_root_directory_chain /etc || {
		echo "install-steward: /etc must be a trusted root-owned directory chain" >&2
		exit 2
	}
	if [[ ! -e /etc/docker && ! -L /etc/docker ]]; then
		install -d -o root -g root -m 0755 /etc/docker
	fi
	trusted_root_directory_chain /etc/docker || {
		echo "install-steward: refusing an unsafe /etc/docker directory" >&2
		exit 2
	}
	if [[ -e $daemon_file || -L $daemon_file ]]; then
		trusted_local_file "$daemon_file" 1048576 || {
			echo "install-steward: Docker daemon configuration must be a bounded, root-owned, one-link regular file" >&2
			exit 2
		}
		daemon_metadata=$(stat -c '%g:%a' -- "$daemon_file")
		daemon_gid=${daemon_metadata%%:*}
		daemon_mode=${daemon_metadata#*:}
		bounded_snapshot "$daemon_file" "$daemon_original" 1048576 10 || {
			echo "install-steward: could not safely snapshot Docker daemon configuration" >&2
			exit 1
		}
		install -o root -g root -m 0600 "$daemon_original" "$daemon_work"
		daemon_existed=true
	else
		printf '{}\n' >"$daemon_work"
		chmod 0600 "$daemon_work"
	fi
	if [[ -e $daemon_work~ || -L $daemon_work~ ]]; then
		echo "install-steward: refusing stale gVisor configuration work state" >&2
		exit 2
	fi
	if ! timeout --signal=TERM --kill-after=5 30 "$runsc_path" install --config_file "$daemon_work"; then
		echo "install-steward: gVisor registration did not produce a Docker configuration" >&2
		exit 1
	fi
	rm -f -- "$daemon_work~"
	if [[ ! -f $daemon_work || -L $daemon_work ||
		$(stat -c '%u:%h' -- "$daemon_work" 2>/dev/null) != 0:1 ]]; then
		echo "install-steward: gVisor produced unsafe Docker configuration output" >&2
		exit 1
	fi
	daemon_size=$(stat -c %s -- "$daemon_work")
	(( daemon_size > 0 && daemon_size <= 1048576 )) || {
		echo "install-steward: gVisor Docker configuration exceeds its size bound" >&2
		exit 1
	}
	if [[ -e $daemon_pending || -L $daemon_pending ]]; then
		[[ -f $daemon_pending && ! -L $daemon_pending &&
			$(stat -c '%u:%h' -- "$daemon_pending" 2>/dev/null) == 0:1 ]] || {
			echo "install-steward: refusing unsafe pending Docker configuration" >&2
			exit 2
		}
		rm -f -- "$daemon_pending"
	fi
	install -o root -g "$daemon_gid" -m "$daemon_mode" "$daemon_work" "$daemon_pending"
	sync -f "$daemon_pending"
	mv -T -- "$daemon_pending" "$daemon_file"
	sync -f /etc/docker
	if ! timeout --signal=TERM --kill-after=5 30 systemctl reload docker.service; then
		if [[ $daemon_existed == true ]]; then
			install -o root -g "$daemon_gid" -m "$daemon_mode" "$daemon_original" "$daemon_pending"
			mv -T -- "$daemon_pending" "$daemon_file"
		else
			rm -f -- "$daemon_file"
		fi
		sync -f /etc/docker
		timeout --signal=TERM --kill-after=5 30 systemctl reload docker.service >/dev/null 2>&1 || true
		echo "install-steward: gVisor registration failed; restored Docker configuration" >&2
		exit 1
	fi
	for _ in 1 2 3 4 5; do has_runsc && break; sleep 1; done
	has_runsc || { echo "install-steward: Docker still does not advertise runsc" >&2; exit 1; }
	echo "install-steward: Docker runtime runsc is ready"
}

resolve_local_file() {
	local source=$1
	[[ -f $source && ! -L $source ]] || return 1
	readlink -e -- "$source"
}

if [[ -n $offline_dir ]]; then
	if [[ ! -d $offline_dir || -L $offline_dir ]]; then
		echo "install-steward: offline directory must be a real directory" >&2
		exit 2
	fi
	offline_dir=$(readlink -e -- "$offline_dir")
	if ! trusted_root_directory_chain "$offline_dir"; then
		echo "install-steward: offline directory and every ancestor must be root-owned and not group- or world-writable" >&2
		exit 2
	fi
fi

manifest_source=
if [[ -n $checksums ]]; then
	manifest_source=$checksums
elif [[ -n $artifact ]]; then
	manifest_source="$(dirname -- "$artifact")/checksums.txt"
elif [[ -n $offline_dir ]]; then
	manifest_source="$offline_dir/checksums.txt"
else
	checksums="$work/checksums.txt"
	if [[ $version == latest ]]; then
		fetch "$release_url/latest/download/checksums.txt" "$checksums" "$max_manifest_bytes"
	else
		fetch "$release_url/download/$version/checksums.txt" "$checksums" "$max_manifest_bytes"
	fi
fi
if [[ -n $manifest_source ]]; then
	if ! manifest_source=$(resolve_local_file "$manifest_source") ||
		! bounded_snapshot "$manifest_source" "$work/checksums.txt" "$max_manifest_bytes" 30; then
		echo "install-steward: checksums must be a bounded, root-owned, one-link regular file under a trusted root-owned path" >&2
		exit 1
	fi
	checksums="$work/checksums.txt"
fi

if [[ $version == latest ]]; then
	match_count=0
	matched_version=
	while read -r _ listed _; do
		listed=${listed#\*}
		listed=${listed#./}
		candidate=
		case "$package_kind" in
			deb | rpm)
				if [[ $listed =~ ^steward-node_(v[^_]+)_${goarch}\.${package_kind}$ ]]; then
					candidate=${BASH_REMATCH[1]}
				fi
				;;
			tar)
				if [[ $listed =~ ^steward_(v[^_]+)_linux_${goarch}\.tar\.gz$ ]]; then
					candidate=${BASH_REMATCH[1]}
				fi
				;;
		esac
		if [[ -n $candidate ]] && valid_release_version "$candidate"; then
			((match_count += 1))
			matched_version=$candidate
		fi
	done <"$checksums"
	if (( match_count != 1 )); then
		echo "install-steward: checksums must name exactly one linux/$goarch $package_kind artifact for latest" >&2
		exit 1
	fi
	version=$matched_version
fi
if ! valid_release_version "$version"; then
	echo "install-steward: resolved artifact version is not a valid release tag: $version" >&2
	exit 2
fi

name=$(artifact_name_for)
if [[ -n $artifact ]]; then
	if [[ ${artifact##*/} != "$name" ]]; then
		echo "install-steward: local artifact must be named $name" >&2
		exit 2
	fi
	if ! artifact_source=$(resolve_local_file "$artifact") ||
		! bounded_snapshot "$artifact_source" "$work/$name" "$max_artifact_bytes" 120; then
		echo "install-steward: artifact must be a bounded, root-owned, one-link regular file under a trusted root-owned path" >&2
		exit 1
	fi
	artifact="$work/$name"
elif [[ -n $offline_dir ]]; then
	artifact_source="$offline_dir/$name"
	if ! artifact_source=$(resolve_local_file "$artifact_source") ||
		! bounded_snapshot "$artifact_source" "$work/$name" "$max_artifact_bytes" 120; then
		echo "install-steward: offline artifact must be a bounded, root-owned, one-link regular file under the trusted offline path" >&2
		exit 1
	fi
	artifact="$work/$name"
else
	artifact="$work/$name"
	fetch "$release_url/download/$version/$name" "$artifact" "$max_artifact_bytes"
fi

verify_sha256 "$artifact" "$checksums"

echo "Install summary: $version, $package_kind, $goarch, source $artifact"
if ! confirm "Proceed with host installation?" yes && [[ $non_interactive == false ]]; then
	echo "install-steward: cancelled"
	exit 0
fi

acquire_host_role_lock || {
	echo "install-steward: could not acquire the shared host-role lock" >&2
	exit 1
}
if control_plane_marker=$(find_deployed_control_plane_marker \
	/opt/steward-control \
	/etc/steward-control \
	/var/lib/steward-control-installer \
	/etc/systemd/system/steward-control.service \
	/usr/local/libexec/steward-control); then
	echo "install-steward: refusing to install a node over the deployed Steward control plane marker $control_plane_marker" >&2
	exit 2
fi
create_node_role_claim || {
	echo "install-steward: could not create the durable node-role reservation" >&2
	exit 1
}
flock -u 6
exec 6>&-

if [[ $stage_only == false ]] && ! has_runsc; then install_gvisor_runtime; fi

case "$package_kind" in
	deb)
		command -v dpkg >/dev/null || { echo "install-steward: dpkg is required" >&2; exit 2; }
		install_deb
		;;
	rpm)
		command -v rpm >/dev/null || { echo "install-steward: rpm is required" >&2; exit 2; }
		STEWARD_EXPECTED_VERSION="$version" STEWARD_NODE_ID="$node_id" rpm -Uvh "$artifact"
		;;
	tar)
		for command in env tar; do
			command -v "$command" >/dev/null || {
				echo "install-steward: $command is required for a tar archive installation" >&2
				exit 2
			}
		done
		archive_dir="$work/archive"
		install -d -m 0700 "$archive_dir"
		if ! extract_verified_node_archive "$artifact" "$archive_dir"; then exit 1; fi
		STEWARD_EXPECTED_VERSION="$version" STEWARD_NODE_ID="$node_id" /bin/bash -p "$archive_dir/scripts/install-node.sh" \
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
			--executor-credential "$executor_credential"
			--ca-file "$ca_file"
			--no-start
		)
		if [[ -n $steward_credential ]]; then
			configure_args+=(--steward-credential "$steward_credential")
		fi
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
		[[ $allow_unquotaed_state == false ]] ||
			configure_args+=(--allow-unquotaed-state-on-dedicated-host)
	fi
	if (( evidence_input_count == 3 )); then
		configure_args+=(
			--executor-evidence-config "$executor_evidence_config"
			--executor-evidence-private-key "$receipt_private"
			--executor-evidence-public-key "$receipt_public"
		)
	fi
	/usr/local/libexec/steward/configure-node "${configure_args[@]}"
fi

echo "install-steward: local Executor roles use /etc/steward/executor-observer-token, /etc/steward/executor-operator-token, and /etc/steward/executor-token"

if [[ $start_services == true ]]; then
	"/opt/steward/releases/$version/integration/scripts/activate-node-release.sh" "$version" --restart
	systemctl enable --now steward-gateway.service steward.service steward-executor.service
	echo "install-steward: Steward $version is installed, configured, and running"
else
	"/opt/steward/releases/$version/integration/scripts/activate-node-release.sh" "$version"
	echo "install-steward: Steward $version is installed and active; service enablement was not changed"
fi
