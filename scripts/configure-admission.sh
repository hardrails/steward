#!/usr/bin/env bash
# Transactionally install signed-admission trust and generate node-local evidence identity.
set -Eeuo pipefail

usage() {
	cat <<'EOF'
Usage: configure-admission.sh --policy FILE --site-root-public-key FILE --site-root-key-id ID [OPTIONS]

Required:
  --policy FILE                  Site-root-signed site policy DSSE envelope
  --site-root-public-key FILE    Base64 Ed25519 site-root public key
  --site-root-key-id ID          Signature key ID used by the policy

Optional:
  --node-id ID                   Stable node identity (derived from /etc/machine-id by default)
  --allow-host-admin-intent      Allow the host-local token to select signed tenant intent
  --no-restart                   Validate and commit without restarting an active Executor
  -h, --help                     Show this help

The receipt private key is generated on the node and never accepted as input.
The public key is written to /etc/steward/node-receipts.public for enrollment/audit.
EOF
}

policy=
site_root=
site_root_key_id=
node_id=
allow_host_admin=false
restart=true
while [[ $# -gt 0 ]]; do
	case "$1" in
		--policy) policy=${2:-}; shift 2 ;;
		--site-root-public-key) site_root=${2:-}; shift 2 ;;
		--site-root-key-id) site_root_key_id=${2:-}; shift 2 ;;
		--node-id) node_id=${2:-}; shift 2 ;;
		--allow-host-admin-intent) allow_host_admin=true; shift ;;
		--no-restart) restart=false; shift ;;
		-h | --help) usage; exit 0 ;;
		*) echo "configure-admission: unknown option $1" >&2; usage >&2; exit 2 ;;
	esac
done

[[ ${EUID} -eq 0 ]] || { echo "configure-admission: run as root" >&2; exit 2; }
[[ $(uname -s) == Linux ]] || { echo "configure-admission: Linux is required" >&2; exit 2; }
for input in "$policy" "$site_root"; do
	[[ -n $input && -f $input && -r $input && ! -L $input ]] || {
		echo "configure-admission: trust input must be a readable regular file: ${input:-<unset>}" >&2
		exit 2
	}
done
[[ $site_root_key_id =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$ ]] || {
	echo "configure-admission: invalid --site-root-key-id" >&2; exit 2;
}
if [[ -z $node_id ]]; then
	[[ -r /etc/machine-id ]] || { echo "configure-admission: --node-id is required without /etc/machine-id" >&2; exit 2; }
	machine_id=$(tr -d '\n' </etc/machine-id)
	[[ $machine_id =~ ^[a-f0-9]{32}$ ]] || { echo "configure-admission: /etc/machine-id is invalid" >&2; exit 2; }
	node_id="steward-$machine_id"
fi
[[ $node_id =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]] || { echo "configure-admission: invalid node ID" >&2; exit 2; }
for path in /usr/local/bin/stewardctl /usr/local/bin/steward-executor \
	/usr/local/libexec/steward/node-preflight /usr/local/libexec/steward/build-relay-image \
	/etc/steward/executor.env; do
	[[ -e $path ]] || { echo "configure-admission: Steward node is missing $path" >&2; exit 2; }
done
if [[ -e /etc/steward/node-receipts.private.pem && ! -e /etc/steward/node-receipts.public ]] || \
	[[ ! -e /etc/steward/node-receipts.private.pem && -e /etc/steward/node-receipts.public ]]; then
	echo "configure-admission: receipt private/public key files must both exist or both be absent" >&2
	exit 2
fi

# Authenticate and semantically validate the policy before changing host state.
/usr/local/bin/stewardctl policy verify -in "$policy" -public-key "$site_root" \
	-key-id "$site_root_key_id" >/dev/null

targets=(
	/etc/steward/executor.env
	/etc/steward/site-policy.dsse.json
	/etc/steward/site-root.public
	/etc/steward/node-receipts.private.pem
	/etc/steward/node-receipts.public
	/etc/steward/executor-gateway.env
)
backup=$(mktemp -d /etc/steward/.admission-backup.XXXXXX)
for target in "${targets[@]}"; do
	name=${target##*/}
	if [[ -e $target || -L $target ]]; then cp -a -- "$target" "$backup/$name"; else : >"$backup/$name.absent"; fi
done
fence=/var/lib/steward-executor/admission-fences.bin
fence_created=false
was_active=false
systemctl is-active --quiet steward-executor.service && was_active=true
committed=false
tmp_private=
tmp_public=
tmp_env=
rollback() {
	status=$?
	trap - ERR INT TERM
	if [[ $committed != true ]]; then
		for target in "${targets[@]}"; do
			name=${target##*/}
			rm -f -- "$target"
			[[ -e $backup/$name || -L $backup/$name ]] && cp -a -- "$backup/$name" "$target"
		done
		[[ $fence_created == false ]] || rm -f -- "$fence"
		if [[ $was_active == true ]]; then systemctl restart steward-executor.service >/dev/null 2>&1 || true; fi
		echo "configure-admission: failed; restored previous trust configuration" >&2
	fi
	rm -f -- "${tmp_private:-}" "${tmp_public:-}" "${tmp_env:-}"
	rm -rf -- "$backup"
	exit "$status"
}
trap rollback ERR INT TERM

install -o root -g steward-executor -m 0640 "$policy" /etc/steward/site-policy.dsse.json
install -o root -g root -m 0644 "$site_root" /etc/steward/site-root.public
if [[ ! -e /etc/steward/node-receipts.private.pem ]]; then
	tmp_private=$(mktemp /etc/steward/.node-receipts.private.XXXXXX)
	tmp_public=$(mktemp /etc/steward/.node-receipts.public.XXXXXX)
	rm -f "$tmp_private" "$tmp_public"
	/usr/local/bin/stewardctl keygen -private-out "$tmp_private" -public-out "$tmp_public" >/dev/null
	chown steward-executor:steward-executor "$tmp_private"
	chmod 0600 "$tmp_private"
	chown root:root "$tmp_public"
	chmod 0644 "$tmp_public"
	mv -f "$tmp_private" /etc/steward/node-receipts.private.pem
	tmp_private=
	mv -f "$tmp_public" /etc/steward/node-receipts.public
	tmp_public=
fi

tmp_env=$(mktemp /etc/steward/.executor.env.XXXXXX)
awk '!/^EXECUTOR_ADMISSION_(POLICY_FILE|SITE_ROOT_PUBLIC_KEY_FILE|SITE_ROOT_KEY_ID|NODE_ID|EVIDENCE_KEY_FILE|HOST_ADMIN_ARG)=/' \
	/etc/steward/executor.env >"$tmp_env"
{
	printf 'EXECUTOR_ADMISSION_POLICY_FILE=/etc/steward/site-policy.dsse.json\n'
	printf 'EXECUTOR_ADMISSION_SITE_ROOT_PUBLIC_KEY_FILE=/etc/steward/site-root.public\n'
	printf 'EXECUTOR_ADMISSION_SITE_ROOT_KEY_ID=%s\n' "$site_root_key_id"
	printf 'EXECUTOR_ADMISSION_NODE_ID=%s\n' "$node_id"
	printf 'EXECUTOR_ADMISSION_EVIDENCE_KEY_FILE=/etc/steward/node-receipts.private.pem\n'
	if [[ $allow_host_admin == true ]]; then
		printf 'EXECUTOR_ADMISSION_HOST_ADMIN_ARG=-admission-allow-host-admin-intent\n'
	else
		printf 'EXECUTOR_ADMISSION_HOST_ADMIN_ARG=\n'
	fi
} >>"$tmp_env"
chown root:root "$tmp_env"
chmod 0600 "$tmp_env"
mv -f "$tmp_env" /etc/steward/executor.env
tmp_env=

gateway_line=$(grep -v '^[[:space:]]*#' /etc/steward/executor-gateway.env 2>/dev/null | grep -v '^[[:space:]]*$' || true)
if [[ -z $gateway_line || $gateway_line == EXECUTOR_GATEWAY_ARGS= ]]; then
	/usr/local/libexec/steward/build-relay-image --configure
fi
if [[ ! -e $fence ]]; then
	fence_created=true
	runuser -u steward-executor -- /usr/local/bin/steward-executor -initialize-admission-fence -admission-fence-file "$fence"
fi
/usr/local/libexec/steward/node-preflight
if [[ $restart == true && $was_active == true ]]; then systemctl restart steward-executor.service; fi

committed=true
trap - ERR INT TERM
rm -rf -- "$backup"
echo "configure-admission: signed admission ready for node $node_id"
echo "configure-admission: retain /etc/steward/node-receipts.public outside the node for receipt verification"
