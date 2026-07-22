#!/usr/bin/env bash
# Hermetic regression checks for node-doctor.sh. No Docker or systemd is used.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
doctor=$root/scripts/node-doctor.sh
work=$(mktemp -d)
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$work/bin" "$work/state"

mkdir -p "$work/hostile"
cat >"$work/hostile/bash" <<'EOF'
#!/bin/sh
touch "$HOSTILE_BASH_MARKER"
exit 97
EOF
cat >"$work/hostile/bash-env" <<'EOF'
touch "$HOSTILE_BASH_MARKER"
EOF
chmod 0755 "$work/hostile/bash"
set +e
HOSTILE_BASH_MARKER=$work/hostile/marker BASH_ENV=$work/hostile/bash-env \
	PATH="$work/hostile:/usr/bin:/bin" "$doctor" --help >"$work/hostile/help" 2>&1
hostile_status=$?
set -e
[[ $hostile_status == 0 && ! -e $work/hostile/marker ]]
grep -q '^Usage: node-doctor.sh' "$work/hostile/help"

cat >"$work/bin/timeout" <<'EOF'
#!/usr/bin/env bash
set -u
while (( $# > 0 )); do
	case "$1" in
	--signal=*|--kill-after=*) shift ;;
	*) break ;;
	esac
done
(( $# >= 2 )) || exit 2
shift
exec "$@"
EOF

cat >"$work/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -u
[[ ${1:-} == --config && ${3:-} == --host && ${4:-} == unix://* ]] || exit 93
[[ ${4:-} == "unix://${EXPECTED_DOCKER_SOCKET:-/var/run/docker.sock}" ]] || exit 94
[[ -z ${DOCKER_API_VERSION+x} ]] || exit 95
shift 4
case "${1:-}" in
info)
	if [[ ${2:-} == --format ]]; then
		if [[ ${FAKE_DOCKER_FLOOD:-0} == 1 ]]; then
			for ((index = 0; index < 10000; index++)); do printf 'untrusted-runtime-output'; done
			exit 0
		fi
		printf '{"runc":{},"runsc":{}}\n'
	fi
	exit 0
	;;
version)
	printf '%s\n' "${FAKE_DOCKER_VERSION:-28.3.1}"
	exit 0
	;;
*) exit 2 ;;
esac
EOF

cat >"$work/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -u
case "${1:-}" in
is-active)
	[[ ${3:-} != "${FAKE_INACTIVE_UNIT:-none}" ]]
	;;
is-failed)
	exit 1
	;;
*) exit 2 ;;
esac
EOF

cat >"$work/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -u
[[ ${1:-} == --disable ]] || exit 92
previous=
for argument in "$@"; do
	if [[ $previous == --header && $argument == @* ]]; then
		IFS= read -r header <"${argument#@}"
		[[ $header == 'Authorization: Bearer doctor-super-secret' ]] || exit 91
	fi
	previous=$argument
done
printf '%s\n' "$*" >>"$FAKE_CURL_LOG"
if [[ -n ${FAKE_CURL_FAIL_MATCH:-} && "$*" == *"$FAKE_CURL_FAIL_MATCH"* ]]; then
	exit 1
fi
if [[ -n ${FAKE_CURL_REDIRECT_MATCH:-} && "$*" == *"$FAKE_CURL_REDIRECT_MATCH"* ]]; then
	printf 302
else
	printf 200
fi
EOF

cat >"$work/bin/stat" <<'EOF'
#!/usr/bin/env bash
set -u
format=
path=
while (( $# > 0 )); do
	case "$1" in
	-Lc) format=${2:-}; shift 2 ;;
	--) shift; path=${1:-}; shift ;;
	*) path=$1; shift ;;
	esac
done
case "$format" in
'%u:%a:%s:%d:%i:%Y:%Z') printf '0:600:128:1:2:100:100\n' ;;
'%u:%g:%a:%s:%d:%i:%Y:%Z') printf '0:0:600:20:1:2:100:100\n' ;;
'%u:%a:%s') printf '0:600:24\n' ;;
'%s')
	case "$path" in
	*admission-fences.bin) printf '419430\n' ;;
	*operation-journal.bin) printf '1677721\n' ;;
	*evidence.bin) printf '6710886\n' ;;
	*uplink-state.json) printf '104857\n' ;;
	*uplink-delivery-state.json) printf '838860\n' ;;
	*) printf '%s\n' "${FAKE_CONNECTOR_SIZE:-6710886}" ;;
	esac
	;;
*) exit 2 ;;
esac
EOF

cat >"$work/bin/df" <<'EOF'
#!/usr/bin/env bash
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
printf '/dev/fake 1000000 500000 500000 50%% /fake\n'
EOF

cat >"$work/bin/node-preflight" <<'EOF'
#!/usr/bin/env bash
set -u
for name in STEWARD_BIN STEWARD_EXECUTOR_BIN STEWARD_GATEWAY_BIN STEWARD_CONFIG_FILE \
	STEWARD_GATEWAY_CONFIG_FILE STEWARD_CONNECTOR_RECEIPT_PRIVATE_KEY_FILE STEWARD_UNIT_DIR; do
	[[ -z ${!name+x} ]] || exit 96
done
[[ ${DOCKER_HOST:-} == unix://* && ${DOCKER_CONFIG:-} == /tmp/steward-node-doctor.*/* ]]
[[ ${STEWARD_EXECUTOR_ENV_FILE:-} == /* ]]
EOF

cat >"$work/bin/stewardctl" <<'EOF'
#!/usr/bin/env bash
set -u
printf '%s\n' "$*" >>"$FAKE_STEWARDCTL_LOG"
[[ ${1:-} == task ]] || exit 2
case "${2:-}" in
submit)
	[[ ${FAKE_SUBMIT_FAIL:-0} != 1 ]]
	;;
wait)
	[[ ${FAKE_WAIT_FAIL:-0} != 1 ]] || exit 1
	result=
	shift 2
	while (( $# > 0 )); do
		if [[ $1 == -result-out ]]; then result=${2:-}; shift 2; else shift; fi
	done
	[[ -n $result ]] || exit 2
	printf 'actual-agent-work-secret' >"$result"
	chmod 0600 "$result"
	;;
*) exit 2 ;;
esac
EOF
chmod 0755 "$work/bin/"*

token=$work/state/executor-token
operator_token=$work/state/executor-operator-token
observer_token=$work/state/executor-observer-token
printf 'doctor-super-secret\n' >"$token"
printf 'doctor-operator-secret\n' >"$operator_token"
printf 'doctor-observer-secret\n' >"$observer_token"
chmod 0600 "$token" "$operator_token" "$observer_token"
fence=$work/state/admission-fences.bin
journal=$work/state/operation-journal.bin
evidence=$work/state/evidence.bin
uplink=$work/state/uplink-state.json
uplink_delivery=$work/state/uplink-delivery-state.json
connector=$work/state/connector\"receipts.ndjson
: >"$fence"
: >"$journal"
: >"$evidence"
: >"$uplink"
: >"$uplink_delivery"
: >"$connector"
chmod 0600 "$fence" "$journal" "$evidence" "$uplink" "$uplink_delivery" "$connector"
executor_env=$work/state/executor.env
docker_socket=$work/state/docker.sock
printf 'EXECUTOR_DOCKER_SOCKET=%s\nEXECUTOR_TOKEN_FILE=%s\nEXECUTOR_OPERATOR_TOKEN_FILE=%s\nEXECUTOR_OBSERVER_TOKEN_FILE=%s\nEXECUTOR_UPLINK_STATE_FILE=%s\nEXECUTOR_UPLINK_DELIVERY_STATE_FILE=%s\nEXECUTOR_NODE_BOOT_IDENTITY_SHA256=\n' \
	"$docker_socket" "$token" "$operator_token" "$observer_token" "$uplink" "$uplink_delivery" >"$executor_env"
chmod 0600 "$executor_env"
: >"$work/curl.log"
: >"$work/stewardctl.log"

common_env=(
	"STEWARD_DOCTOR_TIMEOUT_BIN=$work/bin/timeout"
	"STEWARD_DOCTOR_MKTEMP_BIN=/usr/bin/mktemp"
	"STEWARD_DOCTOR_DOCKER_BIN=$work/bin/docker"
	"STEWARD_DOCTOR_SYSTEMCTL_BIN=$work/bin/systemctl"
	"STEWARD_DOCTOR_CURL_BIN=$work/bin/curl"
	"STEWARD_DOCTOR_STAT_BIN=$work/bin/stat"
	"STEWARD_DOCTOR_DF_BIN=$work/bin/df"
	"STEWARD_NODE_PREFLIGHT=$work/bin/node-preflight"
	"STEWARD_CTL_BIN=$work/bin/stewardctl"
	"STEWARD_DOCTOR_EXECUTOR_TOKEN_FILE=$token"
	"STEWARD_DOCTOR_EXECUTOR_ENV_FILE=$executor_env"
	"STEWARD_DOCTOR_GATEWAY_CONTROL_SOCKET=$work/state/control.sock"
	"STEWARD_DOCTOR_ADMISSION_FENCE_FILE=$fence"
	"STEWARD_DOCTOR_OPERATION_JOURNAL_FILE=$journal"
	"STEWARD_DOCTOR_EVIDENCE_FILE=$evidence"
	"STEWARD_DOCTOR_UPLINK_STATE_FILE=$uplink"
	"STEWARD_DOCTOR_UPLINK_DELIVERY_STATE_FILE=$uplink_delivery"
	"STEWARD_DOCTOR_CONNECTOR_RECEIPT_FILE=$connector"
	"FAKE_CURL_LOG=$work/curl.log"
	"FAKE_STEWARDCTL_LOG=$work/stewardctl.log"
	"EXPECTED_DOCKER_SOCKET=$docker_socket"
)

run_doctor() {
	local argument_count=${#doctor_arguments[@]}
	# These files instrument one invocation. Reset them so the fake commands do
	# not turn prior test output into a side effect that exceeds capture_bounded's
	# process file-size limit on Linux.
	: >"$work/curl.log"
	: >"$work/stewardctl.log"
	if (( argument_count == 0 )); then
		# The child shell, not this test process, expands the positional parameters.
		# shellcheck disable=SC2016
		env "${common_env[@]}" "$@" /bin/bash -c '
			source "$1"
			require_platform() {
				add_check platform.root pass "running as root"
				add_check platform.linux pass "running on Linux"
				return 0
			}
			shift
			main "$@"
		' doctor-test "$doctor"
		return
	fi
	# The child shell, not this test process, expands the positional parameters.
	# shellcheck disable=SC2016
	env "${common_env[@]}" "$@" /bin/bash -c '
		source "$1"
		require_platform() {
			add_check platform.root pass "running as root"
			add_check platform.linux pass "running on Linux"
			return 0
		}
		shift
		main "$@"
	' doctor-test "$doctor" "${doctor_arguments[@]}"
}

doctor_arguments=(--json)
json=$(run_doctor)
[[ $json == '{"schema":"steward.node-doctor.v1","overall":"pass"'* ]]
[[ $json == *'"canary":{"requested":false,"status":"skipped"}'* ]]
[[ $json == *'connector\"receipts.ndjson'* ]]
[[ $json == *'"id":"identity.executor_operator_token","status":"pass"'* ]]
[[ $json == *'"id":"identity.executor_observer_token","status":"pass"'* ]]
[[ $json != *doctor-super-secret* && $json != *actual-agent-work-secret* ]]
[[ $(printf '%s\n' "$json" | wc -l | tr -d ' ') == 1 ]]

doctor_arguments=(--json)
clean_preflight=$(run_doctor STEWARD_BIN=/tmp/untrusted-steward \
	STEWARD_EXECUTOR_BIN=/tmp/untrusted-executor STEWARD_CONFIG_FILE=/tmp/untrusted-config)
[[ $clean_preflight == *'"id":"preflight","status":"pass"'* ]]

doctor_arguments=(--json)
canonical=$(run_doctor STEWARD_DOCTOR_STORE_WARN_PERCENT=080 STEWARD_DOCTOR_STORE_FAIL_PERCENT=095 \
	STEWARD_DOCTOR_FS_WARN_FREE_PERCENT=015 STEWARD_DOCTOR_FS_FAIL_FREE_PERCENT=005)
[[ $canonical == *'"thresholds":{"durable_store_warn_percent":80,"durable_store_fail_percent":95,"filesystem_warn_free_percent":15,"filesystem_fail_free_percent":5}'* ]]

doctor_arguments=()
human=$(run_doctor)
[[ $human == *'Steward node doctor'* && $human == *'Overall: PASS'* ]]
[[ $human != *doctor-super-secret* && $human != *actual-agent-work-secret* ]]

doctor_arguments=(--json)
set +e
failed=$(run_doctor FAKE_DOCKER_VERSION=27.5.0)
failed_status=$?
set -e
[[ $failed_status == 1 && $failed == *'"overall":"fail"'* && $failed == *'"id":"docker.version","status":"fail"'* ]]

doctor_arguments=(--json)
set +e
redirected=$(run_doctor FAKE_CURL_REDIRECT_MATCH=/v1/readiness)
redirected_status=$?
set -e
[[ $redirected_status == 1 && $redirected == *'"id":"readiness.supervisor","status":"fail"'* ]]

doctor_arguments=(--json)
set +e
capacity=$(run_doctor FAKE_CONNECTOR_SIZE=65000000)
capacity_status=$?
set -e
[[ $capacity_status == 1 && $capacity == *'"id":"store.connector_receipts","status":"fail"'* ]]

doctor_arguments=(--json)
set +e
bounded=$(run_doctor FAKE_DOCKER_FLOOD=1 2>"$work/bounded.stderr")
bounded_status=$?
set -e
[[ $bounded_status == 1 && $bounded == *'"id":"docker.runsc","status":"fail"'* ]]
[[ ${#bounded} -le 65536 ]]
[[ ! -s $work/bounded.stderr ]]

executor_env_contents=$(<"$executor_env")
for ((index = 0; index < 2000; index++)); do printf 'UNTRUSTED_%04d=%01024d\n' "$index" 0; done >"$executor_env"
doctor_arguments=(--json)
set +e
large_environment=$(run_doctor)
large_environment_status=$?
set -e
[[ $large_environment_status == 1 && $large_environment == *'"id":"docker.target","status":"fail"'* ]]
printf '%s\n' "$executor_env_contents" >"$executor_env"

token_contents=$(<"$token")
for ((index = 0; index < 5000; index++)); do printf x; done >"$token"
doctor_arguments=(--json)
set +e
large_token=$(run_doctor)
large_token_status=$?
set -e
[[ $large_token_status == 1 && $large_token == *'"id":"readiness.executor_token","status":"fail"'* ]]
printf '%s\n' "$token_contents" >"$token"

bundle=$work/state/canary.bundle.json
result=$work/state/canary-result.json
gateway_token=$work/state/gateway-token
printf 'signed-bundle-placeholder\n' >"$bundle"
printf 'gateway-secret\n' >"$gateway_token"
chmod 0600 "$bundle" "$gateway_token"
doctor_arguments=(--json --canary-bundle "$bundle" --canary-result "$result" --canary-token-file "$gateway_token")
canary=$(run_doctor FAKE_SUBMIT_FAIL=1)
[[ $canary == *'"overall":"warn"'* && $canary == *'"canary":{"requested":true,"status":"pass"}'* ]]
[[ $canary == *'"id":"canary.submit","status":"warn"'* && $canary == *'"id":"canary.work","status":"pass"'* ]]
[[ -s $result && ! -L $result ]]
[[ $canary != *doctor-super-secret* && $canary != *actual-agent-work-secret* && $canary != *gateway-secret* ]]
grep -q '^task submit ' "$work/stewardctl.log"
grep -q '^task wait ' "$work/stewardctl.log"
grep -q '127.0.0.1:8080/v1/healthz' "$work/curl.log"
grep -q '127.0.0.1:8080/v1/readiness' "$work/curl.log"
grep -q '127.0.0.1:8090/v1/healthz' "$work/curl.log"
grep -q '127.0.0.1:8090/v1/readiness' "$work/curl.log"
grep -q -- '--unix-socket' "$work/curl.log"

doctor_arguments=(--unknown)
set +e
run_doctor >/dev/null 2>&1
usage_status=$?
set -e
[[ $usage_status == 2 ]]

printf 'node-doctor-test: human, JSON, failure, canary, and usage paths passed\n'
