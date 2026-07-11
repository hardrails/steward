#!/usr/bin/env bash
# Provision node trust material, validate it, and optionally start Steward.
set -Eeuo pipefail

usage() {
	cat <<'EOF'
Usage: configure-node.sh OPTIONS

Required:
  --control-plane-url URL       HTTPS control-plane base URL
  --steward-credential FILE     Steward uplink credential JSON
  --executor-credential FILE    Executor uplink credential JSON
  --ca-file FILE                PEM CA bundle for the control plane

Optional:
  --executor-token FILE         Existing host-local bearer token; generated if omitted
  --no-start                    Validate and configure, but leave services stopped
  -h, --help                    Show this help

The operation is transactional through preflight: invalid input restores the
previous files under /etc/steward. Existing Executor fence state is never reset.
EOF
}

control_plane_url=
steward_credential=
executor_credential=
ca_file=
executor_token=
start_services=true
while [[ $# -gt 0 ]]; do
	case "$1" in
		--control-plane-url) control_plane_url=${2:-}; shift 2 ;;
		--steward-credential) steward_credential=${2:-}; shift 2 ;;
		--executor-credential) executor_credential=${2:-}; shift 2 ;;
		--ca-file) ca_file=${2:-}; shift 2 ;;
		--executor-token) executor_token=${2:-}; shift 2 ;;
		--no-start) start_services=false; shift ;;
		-h | --help) usage; exit 0 ;;
		*) echo "configure-node: unknown option $1" >&2; usage >&2; exit 2 ;;
	esac
done

if [[ ${EUID} -ne 0 ]]; then
	echo "configure-node: run as root" >&2
	exit 2
fi
if [[ $(uname -s) != Linux ]]; then
	echo "configure-node: Linux is required" >&2
	exit 2
fi
if [[ $control_plane_url != https://* ]]; then
	echo "configure-node: --control-plane-url must use HTTPS" >&2
	exit 2
fi
case "$control_plane_url" in
	*[[:space:]]* | *\"* | *\\*)
		echo "configure-node: control-plane URL contains an unsafe character" >&2
		exit 2
		;;
esac
for input in "$steward_credential" "$executor_credential" "$ca_file"; do
	if [[ -z $input || ! -f $input || ! -r $input ]]; then
		echo "configure-node: required input is not a readable regular file: ${input:-<unset>}" >&2
		exit 2
	fi
done
if [[ -n $executor_token && ( ! -f $executor_token || ! -r $executor_token ) ]]; then
	echo "configure-node: Executor token is not a readable regular file: $executor_token" >&2
	exit 2
fi
for identity in steward steward-executor; do
	id "$identity" >/dev/null 2>&1 || {
		echo "configure-node: missing service identity $identity; install Steward first" >&2
		exit 2
	}
done
for path in /etc/steward/steward.json /etc/steward/executor.env \
	/usr/local/bin/steward-executor /usr/local/libexec/steward/node-preflight; do
	if [[ ! -e $path ]]; then
		echo "configure-node: missing installed path $path; install Steward first" >&2
		exit 2
	fi
done

install -d -o root -g root -m 0755 /etc/steward
backup_dir=$(mktemp -d /etc/steward/.configure-backup.XXXXXX)
targets=(
	/etc/steward/steward.json
	/etc/steward/executor.env
	/etc/steward/uplink-credential.json
	/etc/steward/executor-uplink.json
	/etc/steward/executor-token
	/etc/steward/control-plane-ca.pem
)
for target in "${targets[@]}"; do
	name=${target##*/}
	if [[ -e $target || -L $target ]]; then
		cp -a -- "$target" "$backup_dir/$name"
	else
		: >"$backup_dir/$name.absent"
	fi
done

committed=false
steward_tmp=
executor_tmp=
token_tmp=
atomic_tmp=
fence=/var/lib/steward-executor/uplink-state.json
fence_created=false
rollback() {
	status=$?
	trap - ERR INT TERM
	if [[ $committed != true ]]; then
		for target in "${targets[@]}"; do
			name=${target##*/}
			if [[ -e $backup_dir/$name || -L $backup_dir/$name ]]; then
				rm -f -- "$target"
				cp -a -- "$backup_dir/$name" "$target"
			else
				rm -f -- "$target"
			fi
		done
		if [[ $fence_created == true ]]; then
			rm -f -- "$fence"
		fi
		echo "configure-node: preflight failed; restored previous configuration" >&2
	fi
	rm -f -- "${steward_tmp:-}" "${executor_tmp:-}" "${token_tmp:-}" "${atomic_tmp:-}"
	rm -rf -- "$backup_dir"
	exit "$status"
}
trap rollback ERR INT TERM

steward_tmp=$(mktemp /etc/steward/.steward.json.XXXXXX)
awk -v url="$control_plane_url" -v ca="/etc/steward/control-plane-ca.pem" '
	/^[[:space:]]*"uplink_url"[[:space:]]*:/ {
		comma = ($0 ~ /,[[:space:]]*$/) ? "," : ""
		printf "  \"uplink_url\": \"%s\"%s\n", url, comma
		found_url = 1
		next
	}
	/^[[:space:]]*"uplink_tls_ca_file"[[:space:]]*:/ {
		comma = ($0 ~ /,[[:space:]]*$/) ? "," : ""
		printf "  \"uplink_tls_ca_file\": \"%s\"%s\n", ca, comma
		found_ca = 1
		next
	}
	{ print }
	END { if (!found_url || !found_ca) exit 3 }
' /etc/steward/steward.json >"$steward_tmp"
chown root:steward "$steward_tmp"
chmod 0640 "$steward_tmp"
mv -f "$steward_tmp" /etc/steward/steward.json
steward_tmp=

executor_tmp=$(mktemp /etc/steward/.executor.env.XXXXXX)
awk -v url="$control_plane_url" -v ca="/etc/steward/control-plane-ca.pem" '
	/^EXECUTOR_UPLINK_URL=/ {
		print "EXECUTOR_UPLINK_URL=" url
		found_url = 1
		next
	}
	/^EXECUTOR_UPLINK_TLS_CA_FILE=/ {
		print "EXECUTOR_UPLINK_TLS_CA_FILE=" ca
		found_ca = 1
		next
	}
	{ print }
	END { if (!found_url || !found_ca) exit 3 }
' /etc/steward/executor.env >"$executor_tmp"
chown root:root "$executor_tmp"
chmod 0600 "$executor_tmp"
mv -f "$executor_tmp" /etc/steward/executor.env
executor_tmp=

install_atomic() {
	local source=$1 target=$2 owner=$3 group=$4 mode=$5
	atomic_tmp=$(mktemp "/etc/steward/.${target##*/}.XXXXXX")
	install -o "$owner" -g "$group" -m "$mode" "$source" "$atomic_tmp"
	mv -f "$atomic_tmp" "$target"
	atomic_tmp=
}
install_atomic "$steward_credential" /etc/steward/uplink-credential.json \
	steward steward 0600
install_atomic "$executor_credential" /etc/steward/executor-uplink.json \
	steward-executor steward-executor 0600
install_atomic "$ca_file" /etc/steward/control-plane-ca.pem root root 0644
if [[ -n $executor_token ]]; then
	install_atomic "$executor_token" /etc/steward/executor-token \
		steward-executor steward-executor 0600
elif [[ ! -e /etc/steward/executor-token ]]; then
	token_tmp=$(mktemp /etc/steward/.executor-token.XXXXXX)
	od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"$token_tmp"
	printf '\n' >>"$token_tmp"
	chown steward-executor:steward-executor "$token_tmp"
	chmod 0600 "$token_tmp"
	mv -f "$token_tmp" /etc/steward/executor-token
	token_tmp=
fi

if [[ ! -e $fence ]]; then
	fence_created=true
	runuser -u steward-executor -- /usr/local/bin/steward-executor \
		-initialize-uplink-state -uplink-state-file "$fence"
fi
/usr/local/libexec/steward/node-preflight

committed=true
trap - ERR INT TERM
rm -rf -- "$backup_dir"
if [[ $start_services == true ]]; then
	systemctl enable --now steward.service steward-executor.service
	echo "configure-node: Steward is configured, validated, enabled, and running"
else
	echo "configure-node: Steward is configured and validated; service state was not changed"
fi
