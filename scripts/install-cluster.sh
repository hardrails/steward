#!/bin/bash -p
# Install Steward's pinned RKE2 cluster substrate on one clean Linux server.
set -Eeuo pipefail
set +x
if ! shopt -qo privileged; then
	echo "install-cluster: invoke this installer with /bin/bash -p or execute it directly so caller-controlled shell startup files and exported functions are ignored" >&2
	exit 2
fi
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
export PATH LC_ALL=C LANG=C
unset BASH_ENV ENV CDPATH GLOBIGNORE CURL_HOME XDG_CONFIG_HOME
unset CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
unset TAR_OPTIONS GZIP POSIXLY_CORRECT TMPDIR
IFS=$' \t\n'
umask 077

readonly max_bundle_bytes=268435456
readonly max_images_bytes=2147483648
readonly max_token_bytes=4096
readonly substrate_root=/opt/steward/substrates/rke2
readonly cluster_state_root=/var/lib/steward-cluster
readonly cluster_config=/etc/rancher/rke2/config.yaml
readonly canonical_join_token=/etc/rancher/rke2/steward-join-token
readonly baseline_manifest=/var/lib/rancher/rke2/server/manifests/steward-baseline.yaml
readonly containerd_template=/var/lib/rancher/rke2/agent/etc/containerd/config-v3.toml.tmpl

usage() {
	cat <<'EOF'
Install or inspect Steward's pinned Linux cluster substrate.

Usage:
  sudo /bin/bash -p install-cluster.sh init [options]
  sudo /bin/bash -p install-cluster.sh join-worker --server URL --token-file FILE [options]
  sudo /bin/bash -p install-cluster.sh join-server --server URL --token-file FILE [options]
  sudo /bin/bash -p install-cluster.sh token create --out FILE [--ttl 15m]
  sudo /bin/bash -p install-cluster.sh doctor

Cluster options:
  --cluster NAME         Lowercase cluster identity (default: steward)
  --node NAME            Lowercase node identity (default: host name)
  --server URL           Existing server registration origin on port 9345
  --token-file FILE      Owner-only RKE2 bootstrap token for a joining node
  --offline-dir DIR      Root-staged pinned RKE2 bundle and image archive
  --stewardctl FILE      Dry-run-only path to a checkout-built stewardctl
  --no-start             Install and configure without starting the service
  --dry-run              Validate and print the exact plan without host changes

Token options:
  --out FILE             New owner-only token output; must not already exist
  --ttl DURATION         Worker bootstrap lifetime from 1m through 1h (default: 15m)

RKE2 is an internal cluster substrate and part of the trusted computing base for
this profile. Cluster installation does not move existing Steward agents away
from the qualified Docker and gVisor Executor.
EOF
}

die() {
	echo "install-cluster: $*" >&2
	exit 2
}

trusted_root_directory_chain() {
	local current=$1 metadata uid mode
	[[ $current == /* && -d $current && ! -L $current &&
		$(readlink -e -- "$current" 2>/dev/null) == "$current" ]] || return 1
	while :; do
		metadata=$(stat -c '%u:%a' -- "$current") || return 1
		uid=${metadata%%:*}
		mode=${metadata#*:}
		[[ $uid == 0 ]] && (( (8#$mode & 022) == 0 )) || return 1
		[[ $current == / ]] && return 0
		current=$(dirname -- "$current")
	done
}

operation=${1:-}
[[ -n $operation ]] || {
	usage >&2
	exit 2
}
shift

cluster=steward
node=
server=
token_source=
offline_dir=
start=true
dry_run=false
token_output=
token_ttl=15m
dry_run_ctl=

if [[ $operation == token ]]; then
	[[ ${1:-} == create ]] || die "token requires create"
	shift
fi

while (($#)); do
	case "$1" in
	--cluster)
		(($# >= 2)) || die "--cluster requires a value"
		cluster=$2
		shift 2
		;;
	--node)
		(($# >= 2)) || die "--node requires a value"
		node=$2
		shift 2
		;;
	--server)
		(($# >= 2)) || die "--server requires a value"
		server=$2
		shift 2
		;;
	--token-file)
		(($# >= 2)) || die "--token-file requires a value"
		token_source=$2
		shift 2
		;;
	--offline-dir)
		(($# >= 2)) || die "--offline-dir requires a value"
		offline_dir=$2
		shift 2
		;;
	--stewardctl)
		(($# >= 2)) || die "--stewardctl requires a value"
		dry_run_ctl=$2
		shift 2
		;;
	--out)
		(($# >= 2)) || die "--out requires a value"
		token_output=$2
		shift 2
		;;
	--ttl)
		(($# >= 2)) || die "--ttl requires a value"
		token_ttl=$2
		shift 2
		;;
	--no-start)
		start=false
		shift
		;;
	--dry-run)
		dry_run=true
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		die "unknown option '$1'; run with --help"
		;;
	esac
done

case "$operation" in
init | join-server | join-worker | token | doctor) ;;
*) die "operation must be init, join-server, join-worker, token create, or doctor" ;;
esac

find_stewardctl() {
	local candidate metadata
	for candidate in /opt/steward/current/stewardctl /usr/local/bin/stewardctl /usr/bin/stewardctl; do
		[[ -x $candidate && -f $candidate && ! -L $candidate ]] || continue
		metadata=$(stat -c '%u:%a:%h' -- "$candidate" 2>/dev/null) || continue
		if [[ $metadata == 0:*:1 && ${metadata#*:} != 777:1 ]]; then
			printf '%s\n' "$candidate"
			return 0
		fi
	done
	return 1
}

if [[ $dry_run == true ]]; then
	if [[ -n $dry_run_ctl ]]; then
		[[ $dry_run_ctl == /* && -x $dry_run_ctl && -f $dry_run_ctl && ! -L $dry_run_ctl ]] ||
			die "--stewardctl must name an absolute regular executable"
		ctl=$dry_run_ctl
	else
		ctl=$(command -v stewardctl 2>/dev/null || true)
		[[ -n $ctl && -x $ctl ]] || die "stewardctl is required for --dry-run"
	fi
else
	[[ -z $dry_run_ctl ]] || die "--stewardctl is accepted only with --dry-run"
	[[ $EUID -eq 0 ]] || die "run as root"
	[[ $(uname -s) == Linux ]] || die "cluster nodes require Linux"
	ctl=$(find_stewardctl) || die "install a Steward release before installing the cluster substrate"
fi

case "$(uname -m)" in
x86_64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "supported cluster architectures are amd64 and arm64" ;;
esac

if [[ -z $node ]]; then
	node=$(hostname -s | tr '[:upper:]' '[:lower:]')
fi

if [[ $operation == token ]]; then
	[[ $dry_run == false ]] || die "token creation does not support --dry-run"
	[[ $token_output == /* && $token_output != / && $token_output != *$'\n'* ]] ||
		die "--out must be a clean absolute path"
	[[ $(dirname -- "$token_output") != "$token_output" ]] || die "--out is invalid"
	trusted_root_directory_chain "$(dirname -- "$token_output")" ||
		die "token output parent must be root-owned and not writable by group or other users"
	[[ ! -e $token_output && ! -L $token_output ]] || die "token output already exists"
	if [[ ! $token_ttl =~ ^([1-9][0-9]?)([mh])$ ]]; then
		die "token lifetime must be 1m through 60m or exactly 1h"
	fi
	token_amount=${BASH_REMATCH[1]}
	token_unit=${BASH_REMATCH[2]}
	if [[ $token_unit == h && $token_amount != 1 ]] || [[ $token_unit == m && $token_amount -gt 60 ]]; then
		die "token lifetime must not exceed 1h"
	fi
	[[ -x /usr/local/bin/rke2 ]] || die "RKE2 is not installed"
	systemctl is-active --quiet rke2-server.service || die "RKE2 server is not active"
	token_tmp=$(mktemp "$(dirname -- "$token_output")/.steward-rke2-token.XXXXXX")
	# shellcheck disable=SC2329 # Invoked by the EXIT trap.
	cleanup_token() { rm -f -- "${token_tmp:-}"; }
	trap cleanup_token EXIT HUP INT TERM
	ulimit -c 0
	if ! timeout --signal=TERM --kill-after=5 30 /usr/local/bin/rke2 token create \
		--ttl "$token_ttl" --description "Steward worker bootstrap" >"$token_tmp"; then
		die "RKE2 did not create a worker bootstrap token"
	fi
	[[ -f $token_tmp && ! -L $token_tmp ]] || die "RKE2 token output is not a regular file"
	token_size=$(stat -c '%s' -- "$token_tmp")
	((token_size > 20 && token_size <= max_token_bytes)) || die "RKE2 token output size is invalid"
	[[ $(wc -l <"$token_tmp") -eq 1 ]] || die "RKE2 token output contains more than one line"
	grep -Eq '^[A-Za-z0-9:._-]+$' "$token_tmp" || die "RKE2 token output format is invalid"
	chmod 0600 "$token_tmp"
	mv -T -- "$token_tmp" "$token_output"
	token_tmp=
	echo "install-cluster: wrote a $token_ttl worker token to $token_output"
	echo "install-cluster: remove the transferred copy after the worker joins"
	exit 0
fi

if [[ $operation == doctor ]]; then
	[[ -f $cluster_state_root/installed && ! -L $cluster_state_root/installed ]] ||
		die "cluster installation record is missing"
	service=$(sed -n 's/^service=//p' "$cluster_state_root/installed")
	[[ $service == rke2-server || $service == rke2-agent ]] || die "cluster installation record is invalid"
	systemctl is-active --quiet "$service.service" || die "$service is not active; inspect journalctl -u $service"
	timeout --signal=TERM --kill-after=5 30 /usr/local/bin/rke2 kubectl get node "$node" >/dev/null ||
		die "Kubernetes does not report this node ready"
	if [[ $service == rke2-server ]]; then
		timeout --signal=TERM --kill-after=5 30 /usr/local/bin/rke2 secrets-encrypt status >/dev/null ||
			die "Kubernetes secret encryption status is unavailable"
		timeout --signal=TERM --kill-after=5 30 /usr/local/bin/rke2 kubectl get runtimeclass runsc >/dev/null ||
			die "runsc RuntimeClass is unavailable"
		timeout --signal=TERM --kill-after=5 30 /usr/local/bin/rke2 kubectl get namespace steward-agents >/dev/null ||
			die "steward-agents namespace is unavailable"
	fi
	echo "install-cluster: $service is healthy on $node"
	exit 0
fi

plan_args=(cluster plan "$operation" -cluster "$cluster" -node "$node" -arch "$arch")
if [[ $operation != init ]]; then
	[[ -n $server && -n $token_source ]] || die "$operation requires --server and --token-file"
	plan_args+=(-server "$server" -token-file "$canonical_join_token")
elif [[ -n $server || -n $token_source ]]; then
	die "init does not accept --server or --token-file"
fi
[[ -z $offline_dir ]] || plan_args+=(-air-gap)
[[ $start == true ]] || plan_args+=(-no-start)

if [[ $dry_run == true ]]; then
	exec "$ctl" "${plan_args[@]}"
fi

command -v systemctl >/dev/null || die "systemd is required"
command -v tar >/dev/null || die "tar is required"
command -v sha256sum >/dev/null || die "sha256sum is required"
command -v timeout >/dev/null || die "timeout is required"
command -v flock >/dev/null || die "flock is required"
[[ -x /usr/local/bin/runsc && -f /usr/local/bin/runsc && ! -L /usr/local/bin/runsc ]] ||
	die "gVisor runsc must be installed as /usr/local/bin/runsc"
[[ -x /usr/local/bin/containerd-shim-runsc-v1 && -f /usr/local/bin/containerd-shim-runsc-v1 &&
	! -L /usr/local/bin/containerd-shim-runsc-v1 ]] ||
	die "gVisor containerd-shim-runsc-v1 must be installed as a regular executable"
if systemctl is-active --quiet firewalld.service; then
	die "active firewalld conflicts with RKE2's default Canal network; apply a reviewed Calico firewall design or disable firewalld explicitly"
fi

install -d -o root -g root -m 0700 /run/steward-cluster
exec 9>/run/steward-cluster/install.lock
flock -w 60 9 || die "another cluster operation holds the install lock"

if [[ -f $cluster_state_root/installed && ! -L $cluster_state_root/installed ]]; then
	record_version=$(sed -n 's/^version=//p' "$cluster_state_root/installed")
	record_operation=$(sed -n 's/^operation=//p' "$cluster_state_root/installed")
	record_node=$(sed -n 's/^node=//p' "$cluster_state_root/installed")
	record_cluster=$(sed -n 's/^cluster=//p' "$cluster_state_root/installed")
	if [[ $record_version != v* || $record_operation != "$operation" ||
		$record_node != "$node" || $record_cluster != "$cluster" ]]; then
		die "installed cluster identity differs; remove or recover the existing cluster before changing role or identity"
	fi
fi

config_tmp=$(mktemp /run/steward-cluster/config.XXXXXX)
baseline_tmp=$(mktemp /run/steward-cluster/baseline.XXXXXX)
work=$(mktemp -d /run/steward-cluster/work.XXXXXX)
cleanup() {
	rm -f -- "${config_tmp:-}" "${baseline_tmp:-}"
	rm -rf -- "${work:-}"
}
trap cleanup EXIT HUP INT TERM
"$ctl" "${plan_args[@]}" -output config >"$config_tmp"
if [[ $operation != join-worker ]]; then
	"$ctl" cluster baseline >"$baseline_tmp"
fi
[[ -s $config_tmp && $(stat -c '%s' "$config_tmp") -le 16384 ]] ||
	die "rendered RKE2 configuration is missing or oversized"
config_sha=$(sha256sum "$config_tmp" | awk '{print $1}')

IFS=$'\t' read -r bundle_name bundle_url bundle_size bundle_sha < <(
	"$ctl" cluster artifact bundle -arch "$arch"
)
[[ -n $bundle_name && -n $bundle_url && $bundle_size =~ ^[0-9]+$ && $bundle_sha =~ ^[0-9a-f]{64}$ ]] ||
	die "stewardctl returned invalid RKE2 bundle metadata"
if [[ -n $offline_dir ]]; then
	IFS=$'\t' read -r images_name _ images_size images_sha < <(
		"$ctl" cluster artifact images -arch "$arch"
	)
	[[ -n $images_name && $images_size =~ ^[0-9]+$ && $images_sha =~ ^[0-9a-f]{64}$ ]] ||
		die "stewardctl returned invalid RKE2 image metadata"
fi

verify_file() {
	local path=$1 size=$2 digest=$3 actual_size actual_digest
	[[ -f $path && ! -L $path ]] || return 1
	actual_size=$(stat -c '%s' -- "$path") || return 1
	[[ $actual_size == "$size" ]] || return 1
	actual_digest=$(sha256sum "$path" | awk '{print $1}') || return 1
	[[ $actual_digest == "$digest" ]]
}

copy_offline() {
	local source=$1 destination=$2 limit=$3
	[[ $source == /* && -f $source && ! -L $source ]] ||
		die "offline artifact must be a root-staged absolute regular file: $source"
	local metadata
	metadata=$(stat -c '%u:%a:%h:%s' -- "$source")
	IFS=: read -r source_uid source_mode source_links source_size <<<"$metadata"
	[[ $source_uid == 0 && $source_links == 1 ]] || die "offline artifact must be root-owned with one link"
	(( (8#$source_mode & 022) == 0 && source_size > 0 && source_size <= limit )) ||
		die "offline artifact permissions or size are unsafe"
	timeout --signal=TERM --kill-after=5 180 dd if="$source" of="$destination" \
		bs=1048576 iflag=nofollow,fullblock status=none
}

download_locked() {
	local url=$1 destination=$2 size=$3 limit=$4
	((size > 0 && size <= limit)) || die "pinned artifact size exceeds the installer bound"
	ulimit -c 0
	ulimit -f $(((limit + 1023) / 1024))
	timeout --signal=TERM --kill-after=5 600 curl -q --proto '=https' --tlsv1.2 \
		--location --fail --silent --show-error --retry 3 --retry-connrefused \
		--connect-timeout 15 --max-time 590 --max-filesize "$limit" \
		--output "$destination" "$url" || die "download failed for pinned RKE2 artifact"
}

bundle="$work/$bundle_name"
if [[ -n $offline_dir ]]; then
	[[ $offline_dir == /* && -d $offline_dir && ! -L $offline_dir ]] ||
		die "--offline-dir must be a root-staged absolute directory"
	copy_offline "$offline_dir/$bundle_name" "$bundle" "$max_bundle_bytes"
else
	command -v curl >/dev/null || die "curl is required for a connected install"
	download_locked "$bundle_url" "$bundle" "$bundle_size" "$max_bundle_bytes"
fi
verify_file "$bundle" "$bundle_size" "$bundle_sha" ||
	die "RKE2 bundle size or SHA-256 differs from Steward's lock"

archive_list="$work/archive.list"
archive_verbose="$work/archive.verbose"
timeout --signal=TERM --kill-after=5 30 tar -tzf "$bundle" >"$archive_list" ||
	die "RKE2 bundle inventory could not be read"
timeout --signal=TERM --kill-after=5 30 tar -tvzf "$bundle" >"$archive_verbose" ||
	die "RKE2 bundle types could not be read"
	[[ $(wc -l <"$archive_list") -eq 15 ]] || die "RKE2 bundle inventory has an unexpected entry count"
expected_inventory='bin/
bin/rke2
bin/rke2-killall.sh
bin/rke2-uninstall.sh
lib/
lib/systemd/
lib/systemd/system/
lib/systemd/system/rke2-agent.env
lib/systemd/system/rke2-agent.service
lib/systemd/system/rke2-server.env
lib/systemd/system/rke2-server.service
share/
share/rke2/
share/rke2/LICENSE.txt
share/rke2/rke2-cis-sysctl.conf'
if [[ $(sort -u "$archive_list") != "$expected_inventory" ]]; then
	die "RKE2 bundle contains an unexpected path"
fi
if awk 'substr($1,1,1) !~ /^[d-]$/ { bad=1 } END { exit bad ? 0 : 1 }' "$archive_verbose"; then
	die "RKE2 bundle contains a link or special file"
fi
extract="$work/extract"
install -d -m 0700 "$extract"
timeout --signal=TERM --kill-after=5 120 tar --no-same-owner --no-same-permissions \
	-xzf "$bundle" -C "$extract" || die "RKE2 bundle extraction failed"
[[ -x $extract/bin/rke2 && -f $extract/bin/rke2 && ! -L $extract/bin/rke2 ]] ||
	die "RKE2 bundle did not produce its exact binary"
extracted_size=$(find "$extract" -type f -printf '%s\n' | awk '{ total += $1 } END { print total + 0 }')
((extracted_size > 0 && extracted_size <= max_bundle_bytes)) ||
	die "RKE2 extracted payload exceeds its bound"
version=$("$extract/bin/rke2" --version | awk 'NR==1 {print $3}')
lock_version=$("$ctl" cluster plan init -cluster "$cluster" -node "$node" -arch "$arch" -output json |
	sed -n 's/^[[:space:]]*"version": "\([^"]*\)",*$/\1/p')
[[ -n $lock_version && $version == "$lock_version" ]] ||
	die "RKE2 binary version '$version' differs from Steward's lock '$lock_version'"

if [[ -n $offline_dir ]]; then
	images="$work/$images_name"
	copy_offline "$offline_dir/$images_name" "$images" "$max_images_bytes"
	verify_file "$images" "$images_size" "$images_sha" ||
		die "RKE2 air-gap image archive size or SHA-256 differs from Steward's lock"
fi

if [[ -e /etc/kubernetes || -L /etc/kubernetes ]] && [[ ! -f $cluster_state_root/installed ]]; then
	die "existing Kubernetes configuration is not owned by this installer"
fi
if [[ -e /var/lib/rancher/rke2 || -L /var/lib/rancher/rke2 ]] &&
	[[ ! -f $cluster_state_root/installed ]]; then
	die "existing RKE2 state is not owned by this installer"
fi
if [[ -f $cluster_config ]]; then
	[[ $(sha256sum "$cluster_config" | awk '{print $1}') == "$config_sha" ]] ||
		die "RKE2 configuration drift detected; restore the reviewed configuration before retrying"
elif [[ -e $cluster_config || -L $cluster_config ]]; then
	die "RKE2 configuration path is unsafe"
fi

if [[ $operation != init ]]; then
	[[ $token_source == /* && -f $token_source && ! -L $token_source ]] ||
		die "join token must be an absolute regular file"
	token_metadata=$(stat -c '%u:%a:%h:%s' -- "$token_source")
	IFS=: read -r token_uid token_mode token_links token_size <<<"$token_metadata"
	[[ $token_uid == 0 && $token_mode == 600 && $token_links == 1 ]] ||
		die "join token must be root-owned, mode 0600, with one link"
	((token_size > 20 && token_size <= max_token_bytes)) || die "join token size is invalid"
fi

target="$substrate_root/$lock_version"
if [[ -e $target && ! -d $target ]] || [[ -L $target ]]; then
	die "RKE2 version target is unsafe"
fi
if [[ ! -d $target ]]; then
	staged="$substrate_root/.${lock_version}.pending.$$"
	install -d -o root -g root -m 0755 "$staged"
	cp -a "$extract/." "$staged/"
	printf 'version=%s\nbundle_sha256=%s\n' "$lock_version" "$bundle_sha" >"$staged/steward-lock"
	chown -R root:root "$staged"
	chmod 0644 "$staged/steward-lock"
	mv -T "$staged" "$target"
else
	if ! grep -Fxq "version=$lock_version" "$target/steward-lock" 2>/dev/null ||
		! grep -Fxq "bundle_sha256=$bundle_sha" "$target/steward-lock" 2>/dev/null; then
		die "existing RKE2 version directory is not the locked payload"
	fi
fi

install -d -o root -g root -m 0755 "$substrate_root"
if [[ ! -e $substrate_root/current && ! -L $substrate_root/current ]]; then
	ln -s "$lock_version" "$substrate_root/current"
elif [[ $(readlink -- "$substrate_root/current") != "$lock_version" ]]; then
	die "another RKE2 version is selected; use the reviewed upgrade procedure"
fi
for pair in \
	"/usr/local/bin/rke2:$substrate_root/current/bin/rke2" \
	"/usr/local/bin/rke2-killall.sh:$substrate_root/current/bin/rke2-killall.sh" \
	"/usr/local/bin/rke2-uninstall.sh:$substrate_root/current/bin/rke2-uninstall.sh" \
	"/usr/local/lib/systemd/system/rke2-server.service:$substrate_root/current/lib/systemd/system/rke2-server.service" \
	"/usr/local/lib/systemd/system/rke2-server.env:$substrate_root/current/lib/systemd/system/rke2-server.env" \
	"/usr/local/lib/systemd/system/rke2-agent.service:$substrate_root/current/lib/systemd/system/rke2-agent.service" \
	"/usr/local/lib/systemd/system/rke2-agent.env:$substrate_root/current/lib/systemd/system/rke2-agent.env"; do
	destination=${pair%%:*}
	source=${pair#*:}
	install -d -o root -g root -m 0755 "$(dirname -- "$destination")"
	if [[ ! -e $destination && ! -L $destination ]]; then
		ln -s "$source" "$destination"
	elif [[ ! -L $destination || $(readlink -- "$destination") != "$source" ]]; then
		die "refusing to replace unmanaged path $destination"
	fi
done

install -d -o root -g root -m 0700 /etc/rancher/rke2
if [[ ! -f $cluster_config ]]; then
	install -o root -g root -m 0600 "$config_tmp" "$cluster_config"
fi
if [[ $operation != init && ! -f $canonical_join_token ]]; then
	install -o root -g root -m 0600 "$token_source" "$canonical_join_token"
elif [[ $operation != init ]] && ! cmp -s "$token_source" "$canonical_join_token"; then
	die "installed join token differs from the supplied token"
fi
if [[ $operation != join-worker ]]; then
	install -d -o root -g root -m 0755 "$(dirname -- "$baseline_manifest")"
	if [[ ! -f $baseline_manifest ]]; then
		install -o root -g root -m 0644 "$baseline_tmp" "$baseline_manifest"
	elif ! cmp -s "$baseline_tmp" "$baseline_manifest"; then
		die "cluster baseline drift detected"
	fi
fi

install -d -o root -g root -m 0755 "$(dirname -- "$containerd_template")"
if [[ ! -f $containerd_template ]]; then
	cat >"$containerd_template" <<'EOF'
{{ template "base" . }}
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
EOF
	chown root:root "$containerd_template"
	chmod 0644 "$containerd_template"
elif ! grep -Fxq '  runtime_type = "io.containerd.runsc.v1"' "$containerd_template"; then
	die "containerd runtime configuration drift detected"
fi

install -o root -g root -m 0644 "$target/share/rke2/rke2-cis-sysctl.conf" /etc/sysctl.d/90-rke2-cis.conf
if [[ $operation != join-worker ]] && ! id etcd >/dev/null 2>&1; then
	useradd --system --no-create-home --home-dir /var/lib/rancher/rke2/server/db \
		--shell /usr/sbin/nologin etcd
fi
if [[ -n $offline_dir ]]; then
	install -d -o root -g root -m 0755 /var/lib/rancher/rke2/agent/images
	if [[ ! -f /var/lib/rancher/rke2/agent/images/$images_name ]]; then
		install -o root -g root -m 0644 "$images" "/var/lib/rancher/rke2/agent/images/$images_name"
	elif ! verify_file "/var/lib/rancher/rke2/agent/images/$images_name" "$images_size" "$images_sha"; then
		die "installed air-gap image archive drift detected"
	fi
fi

service=rke2-server
[[ $operation != join-worker ]] || service=rke2-agent
install -d -o root -g root -m 0700 "$cluster_state_root"
record_tmp="$cluster_state_root/.installed.pending.$$"
printf 'version=%s\noperation=%s\nservice=%s\ncluster=%s\nnode=%s\nconfig_sha256=%s\n' \
	"$lock_version" "$operation" "$service" "$cluster" "$node" "$config_sha" >"$record_tmp"
chmod 0600 "$record_tmp"
systemctl daemon-reload
if [[ $start == true ]]; then
	sysctl --system >/dev/null
	systemctl enable "$service.service" >/dev/null
	systemctl start "$service.service"
	active_deadline=$((SECONDS + 300))
	until systemctl is-active --quiet "$service.service"; do
		((SECONDS < active_deadline)) ||
			die "$service did not become active within five minutes; inspect journalctl -u $service"
		sleep 2
	done
fi
mv -T "$record_tmp" "$cluster_state_root/installed"
record_tmp=

echo "install-cluster: installed $lock_version as $service on $node"
if [[ $start == true ]]; then
	echo "install-cluster: run '$0 doctor' after Kubernetes reports the node ready"
else
	echo "install-cluster: configuration is staged; start $service.service when ready"
fi
