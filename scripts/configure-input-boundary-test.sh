#!/usr/bin/env bash
# Exercise the hostile-file boundary shared independently by node and admission configuration.
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $(uname -s) != Linux ]]; then
	if command -v docker >/dev/null 2>&1 && docker image inspect ubuntu:24.04 >/dev/null 2>&1; then
		exec docker run --rm -v "$root:/src:ro" ubuntu:24.04 \
			/bin/bash /src/scripts/configure-input-boundary-test.sh --linux
	fi
	echo "configure-input-boundary-test: Linux or a local ubuntu:24.04 image is required" >&2
	exit 1
fi
if [[ ${EUID} -ne 0 ]]; then
	if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
		exec sudo -n /bin/bash "$0" --linux
	fi
	if [[ ${STEWARD_REQUIRE_ROOT_SMOKE:-0} == 1 ]]; then
		echo "configure-input-boundary-test: passwordless root is required" >&2
		exit 1
	fi
	echo "configure-input-boundary-test: skipped hostile ownership checks without passwordless root"
	exit 0
fi

umask 077
work=$(mktemp -d /run/steward-configure-input-test.XXXXXX)
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

extract_boundary() {
	local source=$1 destination=$2
	awk '
		/^# BEGIN TRUSTED_INPUT_BOUNDARY$/ { copying=1; next }
		/^# END TRUSTED_INPUT_BOUNDARY$/ { exit }
		copying { print }
	' "$source" >"$destination"
	grep -Fq 'trusted_input_snapshot() {' "$destination"
}

extract_function() {
	local source=$1 name=$2 destination=$3
	awk -v signature="$name() {" '
		$0 == signature { copying=1 }
		copying { print }
		copying && $0 == "}" { exit }
	' "$source" >>"$destination"
	grep -Fq "$name() {" "$destination"
}

exercise_common_boundary() (
	set -Eeuo pipefail
	local source=$1 kind=$2
	local helper=$work/$kind-boundary.sh
	local suite=$work/$kind
	extract_boundary "$source" "$helper"
	# shellcheck source=/dev/null
	source "$helper"
	mkdir -m 0700 "$suite" "$suite/safe" "$suite/unsafe-parent" "$suite/nonroot-parent"
	chmod 0770 "$suite/unsafe-parent"

	printf 'trusted\n' >"$suite/safe/valid"
	chmod 0600 "$suite/safe/valid"
	ln -s "$suite/safe/valid" "$suite/safe/source-symlink"
	mkfifo -m 0600 "$suite/safe/source-fifo"
	cp "$suite/safe/valid" "$suite/safe/hardlink-source"
	ln "$suite/safe/hardlink-source" "$suite/safe/hardlink-peer"
	cp "$suite/safe/valid" "$suite/safe/nonroot"
	chown 65534:65534 "$suite/safe/nonroot"
	cp "$suite/safe/valid" "$suite/safe/writable"
	chmod 0620 "$suite/safe/writable"
	cp "$suite/safe/valid" "$suite/safe/group-readable-secret"
	chmod 0640 "$suite/safe/group-readable-secret"
	cp "$suite/safe/valid" "$suite/unsafe-parent/input"
	cp "$suite/safe/valid" "$suite/nonroot-parent/input"
	chown 65534:65534 "$suite/nonroot-parent"
	ln -s "$suite/safe" "$suite/ancestor-symlink"

	input_stage_prefix=/run/steward-boundary-$kind.
	input_stage=
	create_trusted_input_stage
	[[ $(stat -c '%u:%g:%a' "$input_stage") == 0:0:700 ]]

	expect_reject() {
		local label=$1 candidate=$2 owner_only=${3:-false}
		if trusted_input_snapshot "$candidate" "$input_stage/rejected" "$label" 4096 "$owner_only" \
			>"$suite/reject.out" 2>"$suite/reject.err"; then
			echo "configure-input-boundary-test: $kind accepted hostile $label" >&2
			exit 1
		fi
		grep -Fq 'copy the input to a protected root-owned directory and retry' "$suite/reject.err"
		[[ ! -e $input_stage/rejected ]]
	}

	expect_reject symlink "$suite/safe/source-symlink"
	expect_reject FIFO "$suite/safe/source-fifo"
	expect_reject hardlink "$suite/safe/hardlink-source"
	expect_reject unsafe-parent "$suite/unsafe-parent/input"
	expect_reject nonroot-parent "$suite/nonroot-parent/input"
	expect_reject nonroot "$suite/safe/nonroot"
	expect_reject writable "$suite/safe/writable"
	expect_reject owner-only "$suite/safe/group-readable-secret" true
	expect_reject relative safe/valid
	expect_reject dotdot "$suite/safe/../safe/valid"
	expect_reject symlink-ancestor "$suite/ancestor-symlink/valid"

	trusted_input_snapshot "$suite/safe/group-readable-secret" \
		"$input_stage/public-snapshot" public-input 4096 false
	[[ $(stat -c '%u:%g:%a:%h' "$input_stage/public-snapshot") == 0:0:600:1 ]]
	cmp "$suite/safe/group-readable-secret" "$input_stage/public-snapshot"

	local marker=$suite/cleanup-stage status staged
	set +e
	(
		input_stage_prefix=/run/steward-boundary-cleanup-$kind.
		# shellcheck disable=SC2030 # Deliberately tests EXIT cleanup in an isolated process.
		input_stage=
		trap cleanup_trusted_input_stage EXIT
		create_trusted_input_stage
		printf '%s\n' "$input_stage" >"$marker"
		exit 37
	)
	status=$?
	set -e
	[[ $status -eq 37 ]]
	staged=$(<"$marker")
	[[ ! -e $staged ]]
	# shellcheck disable=SC2031 # The outer stage predates and survives the cleanup subprocess.
	rm -rf -- "$input_stage"
)

set_node_sources() {
	local fixture=$1
	# shellcheck disable=SC2034 # These globals are consumed by the extracted production function.
	local_only=false
	steward_credential=$fixture/steward.json
	executor_credential=$fixture/executor.json
	ca_file=$fixture/ca.pem
	executor_token=$fixture/token
	# shellcheck disable=SC2034 # Consumed by the extracted production function.
	admission_required=3
	admission_policy=$fixture/policy.json
	site_root=$fixture/site-root.public
	executor_evidence_config=$fixture/evidence.env
	receipt_private=$fixture/receipts.private.pem
	receipt_public=$fixture/receipts.public
	# shellcheck disable=SC2034 # Consumed by the extracted production function.
	evidence_input_count=3
}

exercise_node_staging() (
	set -Eeuo pipefail
	local helper=$work/node-stage-boundary.sh fixture=$work/node-stage
	extract_boundary "$root/scripts/configure-node.sh" "$helper"
	# shellcheck source=/dev/null
	source "$helper"
	mkdir -m 0700 "$fixture"
	for name in steward.json executor.json token evidence.env receipts.private.pem; do
		printf '%s:trusted\n' "$name" >"$fixture/$name"
		chmod 0600 "$fixture/$name"
	done
	for name in ca.pem policy.json site-root.public receipts.public; do
		printf '%s:trusted\n' "$name" >"$fixture/$name"
		chmod 0644 "$fixture/$name"
	done

	input_stage_prefix=/run/steward-node-stage-test.
	input_stage=
	create_trusted_input_stage
	set_node_sources "$fixture"
	stage_node_input_sources
	[[ $steward_credential == "$input_stage/steward-credential.json" ]]
	[[ $executor_credential == "$input_stage/executor-credential.json" ]]
	[[ $ca_file == "$input_stage/control-plane-ca.pem" ]]
	[[ $executor_token == "$input_stage/executor-token" ]]
	[[ $admission_policy == "$input_stage/site-policy.dsse.json" ]]
	[[ $site_root == "$input_stage/site-root.public" ]]
	[[ $executor_evidence_config == "$input_stage/executor-evidence.env" ]]
	[[ $receipt_private == "$input_stage/node-receipts.private.pem" ]]
	[[ $receipt_public == "$input_stage/node-receipts.public" ]]
	printf 'attacker\n' >"$fixture/steward.json"
	printf 'attacker\n' >"$fixture/executor.json"
	printf 'attacker\n' >"$fixture/ca.pem"
	printf 'attacker\n' >"$fixture/token"
	printf 'attacker\n' >"$fixture/policy.json"
	printf 'attacker\n' >"$fixture/site-root.public"
	printf 'attacker\n' >"$fixture/evidence.env"
	printf 'attacker\n' >"$fixture/receipts.private.pem"
	printf 'attacker\n' >"$fixture/receipts.public"
	for snapshot in "$steward_credential" "$executor_credential" "$ca_file" \
		"$executor_token" "$admission_policy" "$site_root" "$executor_evidence_config" \
		"$receipt_private" "$receipt_public"; do
		if grep -Fq attacker "$snapshot"; then
			echo "configure-input-boundary-test: configure-node snapshot followed a mutated source" >&2
			exit 1
		fi
	done
	rm -rf -- "$input_stage"

	truncate -s 65536 "$fixture/steward.json"
	truncate -s 65536 "$fixture/executor.json"
	truncate -s 1048576 "$fixture/ca.pem"
	truncate -s 4096 "$fixture/token"
	truncate -s 1048576 "$fixture/policy.json"
	truncate -s 4096 "$fixture/site-root.public"
	truncate -s 4096 "$fixture/evidence.env"
	truncate -s 16384 "$fixture/receipts.private.pem"
	truncate -s 4096 "$fixture/receipts.public"
	input_stage=
	create_trusted_input_stage
	set_node_sources "$fixture"
	stage_node_input_sources
	[[ $(stat -c %s "$steward_credential") -eq 65536 ]]
	[[ $(stat -c %s "$executor_credential") -eq 65536 ]]
	[[ $(stat -c %s "$ca_file") -eq 1048576 ]]
	[[ $(stat -c %s "$executor_token") -eq 4096 ]]
	[[ $(stat -c %s "$admission_policy") -eq 1048576 ]]
	[[ $(stat -c %s "$site_root") -eq 4096 ]]
	[[ $(stat -c %s "$executor_evidence_config") -eq 4096 ]]
	[[ $(stat -c %s "$receipt_private") -eq 16384 ]]
	[[ $(stat -c %s "$receipt_public") -eq 4096 ]]
	rm -rf -- "$input_stage"

	local target cap status
	while IFS=: read -r target cap; do
		for name in steward.json executor.json token evidence.env receipts.private.pem; do chmod 0600 "$fixture/$name"; done
		for name in ca.pem policy.json site-root.public receipts.public; do chmod 0644 "$fixture/$name"; done
		for name in steward.json executor.json ca.pem token policy.json site-root.public evidence.env receipts.private.pem receipts.public; do
			truncate -s 1 "$fixture/$name"
		done
		truncate -s "$((cap + 1))" "$fixture/$target"
		input_stage=
		create_trusted_input_stage
		set_node_sources "$fixture"
		set +e
		stage_node_input_sources >"$fixture/$target.out" 2>"$fixture/$target.err"
		status=$?
		set -e
		if [[ $status -eq 0 ]]; then
			echo "configure-input-boundary-test: configure-node accepted oversized $target" >&2
			exit 1
		fi
		grep -Fq "exceeds the $cap-byte limit" "$fixture/$target.err"
		rm -rf -- "$input_stage"
	done <<'EOF'
steward.json:65536
executor.json:65536
ca.pem:1048576
token:4096
policy.json:1048576
site-root.public:4096
evidence.env:4096
receipts.private.pem:16384
receipts.public:4096
EOF
)

exercise_admission_staging() (
	set -Eeuo pipefail
	local helper=$work/admission-stage-boundary.sh fixture=$work/admission-stage status
	extract_boundary "$root/scripts/configure-admission.sh" "$helper"
	# shellcheck source=/dev/null
	source "$helper"
	mkdir -m 0700 "$fixture"
	printf 'trusted-policy\n' >"$fixture/policy.json"
	printf 'trusted-root\n' >"$fixture/site-root.public"
	printf 'trusted-private\n' >"$fixture/receipts.private.pem"
	printf 'trusted-public\n' >"$fixture/receipts.public"
	chmod 0644 "$fixture/policy.json" "$fixture/site-root.public" "$fixture/receipts.public"
	chmod 0600 "$fixture/receipts.private.pem"
	policy=$fixture/policy.json
	site_root=$fixture/site-root.public
	receipt_private=$fixture/receipts.private.pem
	receipt_public=$fixture/receipts.public
	# shellcheck disable=SC2034 # Consumed by the extracted production function.
	input_stage_prefix=/run/steward-admission-stage-test.
	input_stage=
	create_trusted_input_stage
	stage_admission_input_sources
	[[ $policy == "$input_stage/site-policy.dsse.json" ]]
	[[ $site_root == "$input_stage/site-root.public" ]]
	[[ $receipt_private == "$input_stage/node-receipts.private.pem" ]]
	[[ $receipt_public == "$input_stage/node-receipts.public" ]]
	printf 'attacker-policy\n' >"$fixture/policy.json"
	printf 'attacker-root\n' >"$fixture/site-root.public"
	printf 'attacker-private\n' >"$fixture/receipts.private.pem"
	printf 'attacker-public\n' >"$fixture/receipts.public"
	[[ $(<"$policy") == trusted-policy ]]
	[[ $(<"$site_root") == trusted-root ]]
	[[ $(<"$receipt_private") == trusted-private ]]
	[[ $(<"$receipt_public") == trusted-public ]]
	rm -rf -- "$input_stage"

	truncate -s 1048577 "$fixture/policy.json"
	truncate -s 1 "$fixture/site-root.public"
	policy=$fixture/policy.json site_root=$fixture/site-root.public input_stage=
	receipt_private=$fixture/receipts.private.pem receipt_public=$fixture/receipts.public
	create_trusted_input_stage
	set +e
	stage_admission_input_sources >"$fixture/policy.out" 2>"$fixture/policy.err"
	status=$?
	set -e
	[[ $status -ne 0 ]]
	grep -Fq 'exceeds the 1048576-byte limit' "$fixture/policy.err"
	rm -rf -- "$input_stage"

	truncate -s 1 "$fixture/policy.json"
	truncate -s 4097 "$fixture/site-root.public"
	policy=$fixture/policy.json site_root=$fixture/site-root.public input_stage=
	receipt_private=$fixture/receipts.private.pem receipt_public=$fixture/receipts.public
	create_trusted_input_stage
	set +e
	stage_admission_input_sources >"$fixture/root.out" 2>"$fixture/root.err"
	status=$?
	set -e
	[[ $status -ne 0 ]]
	grep -Fq 'exceeds the 4096-byte limit' "$fixture/root.err"
	rm -rf -- "$input_stage"
)

exercise_receipt_pair_presence() (
	set -Eeuo pipefail
	local helper=$work/receipt-key-pair-state.sh fixture=$work/receipt-key-pair
	awk '
		$0 == "receipt_key_pair_state() {" { copying=1 }
		copying { print }
		copying && $0 == "}" { exit }
	' "$root/scripts/configure-admission.sh" >"$helper"
	# shellcheck source=/dev/null
	source "$helper"
	mkdir -m 0700 "$fixture"
	private=$fixture/private.pem
	public=$fixture/public
	[[ $(receipt_key_pair_state "$private" "$public") == absent ]]
	: >"$private"
	if receipt_key_pair_state "$private" "$public" >/dev/null; then
		echo "configure-input-boundary-test: private-only receipt identity was accepted" >&2
		exit 1
	fi
	: >"$public"
	[[ $(receipt_key_pair_state "$private" "$public") == present ]]
	rm -f "$private" "$public"
	ln -s "$fixture/missing-private" "$private"
	if receipt_key_pair_state "$private" "$public" >/dev/null; then
		echo "configure-input-boundary-test: broken private-only receipt identity was accepted" >&2
		exit 1
	fi
	ln -s "$fixture/missing-public" "$public"
	[[ $(receipt_key_pair_state "$private" "$public") == present ]]
)

exercise_evidence_config_parser() (
	set -Eeuo pipefail
	local helper=$work/evidence-config-parser.sh fixture=$work/evidence-config.env
	: >"$helper"
	extract_function "$root/scripts/configure-node.sh" evidence_config_error "$helper"
	extract_function "$root/scripts/configure-node.sh" parse_executor_evidence_config "$helper"
	# shellcheck source=/dev/null
	source "$helper"
	public_key="$(printf 'A%.0s' {1..43})="
	cat >"$fixture" <<EOF
STEWARD_EXECUTOR_EVIDENCE_CONFIG_VERSION=1
STEWARD_EXECUTOR_EVIDENCE_CONTROLLER_INSTANCE_ID=control-a
STEWARD_EXECUTOR_EVIDENCE_NODE_ID=node-a
STEWARD_EXECUTOR_EVIDENCE_RECEIPT_EPOCH=1
STEWARD_EXECUTOR_EVIDENCE_PUBLIC_KEY_BASE64=$public_key
EOF
	executor_evidence_config=$fixture
	evidence_controller_instance_id=
	evidence_node_id=
	evidence_public_key=
	parse_executor_evidence_config
	[[ $evidence_controller_instance_id == control-a ]]
	[[ $evidence_node_id == node-a ]]
	[[ $evidence_public_key == "$public_key" ]]

	printf 'UNKNOWN=value\n' >>"$fixture"
	if (set -e; parse_executor_evidence_config) >/dev/null 2>&1; then
		echo "configure-input-boundary-test: unknown evidence config setting was accepted" >&2
		exit 1
	fi
	sed -i '/^UNKNOWN=/d; s#^STEWARD_EXECUTOR_EVIDENCE_CONTROLLER_INSTANCE_ID=.*#STEWARD_EXECUTOR_EVIDENCE_CONTROLLER_INSTANCE_ID=bad/controller#' "$fixture"
	if (set -e; parse_executor_evidence_config) >/dev/null 2>&1; then
		echo "configure-input-boundary-test: invalid controller identity was accepted" >&2
		exit 1
	fi
	sed -i 's#^STEWARD_EXECUTOR_EVIDENCE_CONTROLLER_INSTANCE_ID=.*#STEWARD_EXECUTOR_EVIDENCE_CONTROLLER_INSTANCE_ID=control-a#' "$fixture"
	printf '\0' >>"$fixture"
	if (set -e; parse_executor_evidence_config) >/dev/null 2>&1; then
		echo "configure-input-boundary-test: non-text evidence config was accepted" >&2
		exit 1
	fi
)

exercise_common_boundary "$root/scripts/configure-node.sh" node
exercise_common_boundary "$root/scripts/configure-admission.sh" admission
exercise_node_staging
exercise_admission_staging
exercise_receipt_pair_presence
exercise_evidence_config_parser

node_stage_line=$(grep -n '^stage_node_input_sources$' "$root/scripts/configure-node.sh" | cut -d: -f1)
node_mutation_line=$(grep -n '^install -d -o root -g root -m 0755 /etc/steward$' \
	"$root/scripts/configure-node.sh" | cut -d: -f1)
admission_stage_line=$(grep -n '^stage_admission_input_sources$' \
	"$root/scripts/configure-admission.sh" | cut -d: -f1)
admission_verify_line=$(grep -n '^/usr/local/bin/stewardctl policy verify ' \
	"$root/scripts/configure-admission.sh" | cut -d: -f1)
(( node_stage_line < node_mutation_line ))
(( admission_stage_line < admission_verify_line ))

echo "configure-input-boundary-test: hostile paths, bounded snapshots, cleanup, and snapshot authority passed"
