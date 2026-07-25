#!/usr/bin/env bash
# Real Linux Docker/gVisor proof for signed admission and receipts.
set -euo pipefail

: "${V1_IMAGE:?set V1_IMAGE to an already-local repository@sha256 reference}"
[[ ${STEWARD_ACCEPT_DISPOSABLE_HOST_RISK:-} == YES ]] || {
	echo 'set STEWARD_ACCEPT_DISPOSABLE_HOST_RISK=YES after confirming this is a disposable acceptance host' >&2
	exit 2
}
case "$V1_IMAGE" in
	*@sha256:????????????????????????????????????????????????????????????????) ;;
	*) echo 'V1_IMAGE must be an immutable repository@sha256 reference' >&2; exit 2 ;;
esac
if ! docker info --format '{{json .Runtimes}}' | grep -q '"runsc"'; then
	echo 'Docker runtime runsc is required' >&2
	exit 2
fi
command -v python3 >/dev/null || {
	echo 'python3 is required' >&2
	exit 2
}
executor_addr=${STEWARD_ACCEPTANCE_EXECUTOR_ADDR:-127.0.0.1:8090}
if [[ ! $executor_addr =~ ^127\.0\.0\.1:([0-9]{1,5})$ ]] ||
	(( 10#${BASH_REMATCH[1]:-0} < 1 || 10#${BASH_REMATCH[1]:-0} > 65535 )); then
	echo 'STEWARD_ACCEPTANCE_EXECUTOR_ADDR must be a 127.0.0.1 TCP address' >&2
	exit 2
fi
executor_url=http://$executor_addr

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
executor_bin=${EXECUTOR_BIN:-$work/steward-executor}
ctl_bin=${STEWARDCTL_BIN:-$work/stewardctl}
runtime_ref=
keep_failed=${STEWARD_SIGNED_ADMISSION_KEEP_FAILED:-NO}
[[ $keep_failed == YES || $keep_failed == NO ]] || {
	echo 'STEWARD_SIGNED_ADMISSION_KEEP_FAILED must be YES or NO' >&2
	exit 2
}
run_id=${STEWARD_ACCEPTANCE_RUN_ID:-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')}
[[ $run_id =~ ^[a-f0-9]{16}$ ]] || { echo 'STEWARD_ACCEPTANCE_RUN_ID must be 16 lowercase hexadecimal characters' >&2; exit 2; }
tenant_id="acceptance-$run_id"
instance_id="agent-$run_id"
lineage_id="lineage-$run_id"
node_id="node-$run_id"

cleanup() {
	local status=$?
	trap - EXIT
	if [[ -n ${runtime_ref:-} && -n ${token:-} ]]; then
		curl -sS -X DELETE "$executor_url/v1/workloads/$runtime_ref" \
			-H "Authorization: Bearer $token" >/dev/null || true
	fi
	if [[ -n ${executor_pid:-} ]]; then kill "$executor_pid" 2>/dev/null || true; fi
	if (( status != 0 )) && [[ $keep_failed == YES ]]; then
		echo "signed-admission-acceptance: retained owner-only diagnostics at $work" >&2
	else
		rm -rf "$work"
	fi
	exit "$status"
}
trap cleanup EXIT

if [[ ! -x $executor_bin ]]; then
	(cd "$root" && go build -o "$executor_bin" ./cmd/steward-executor)
fi
if [[ ! -x $ctl_bin ]]; then
	(cd "$root" && go build -o "$ctl_bin" ./cmd/stewardctl)
fi

"$ctl_bin" keygen -key-id site-root -private-out "$work/site.private" -public-out "$work/site.public" >/dev/null
"$ctl_bin" keygen -key-id publisher -private-out "$work/publisher.private" -public-out "$work/publisher.public" >/dev/null
"$ctl_bin" keygen -key-id receipts -private-out "$work/receipts.private" -public-out "$work/receipts.public" >/dev/null

publisher_public=$(tr -d '\n' <"$work/publisher.public")
manifest_digest=${V1_IMAGE##*@}
repository=${V1_IMAGE%@*}
config_digest=$(docker image inspect --format '{{.Id}}' "$V1_IMAGE")
architecture=$(docker image inspect --format '{{.Architecture}}' "$V1_IMAGE")
variant=$(docker image inspect --format '{{.Variant}}' "$V1_IMAGE")
[[ $variant != '<no value>' ]] || variant=
platform="\"os\":\"linux\",\"architecture\":\"$architecture\""
[[ -z $variant ]] || platform+=",\"variant\":\"$variant\""

printf '%s\n' "{
  \"schema_version\":\"steward.admission.v1\",
  \"policy_id\":\"acceptance-site\",
  \"policy_epoch\":1,
  \"publishers\":[{
    \"key_id\":\"publisher\",\"public_key\":\"$publisher_public\",\"revoked\":false,
    \"allowed_profiles\":[{\"id\":\"generic-v1\",\"version\":\"v1\"}],
    \"allowed_repositories\":[\"$repository\"],
    \"allowed_manifest_digests\":[\"$manifest_digest\"],
    \"resource_ceiling\":{\"memory_bytes\":67108864,\"cpu_millis\":100,\"pids\":32}
  }],
  \"tenants\":[{
    \"tenant_id\":\"$tenant_id\",\"publisher_key_ids\":[\"publisher\"],
    \"resource_ceiling\":{\"memory_bytes\":67108864,\"cpu_millis\":100,\"pids\":32}
  }]
}" >"$work/policy.json"
"$ctl_bin" policy sign -in "$work/policy.json" -out "$work/policy.dsse.json" \
	-key "$work/site.private" -key-id site-root >/dev/null

printf '%s\n' "{
  \"schema_version\":\"steward.admission.v1\",\"capsule_id\":\"acceptance-capsule\",
  \"publisher_key_id\":\"publisher\",
  \"profile\":{\"id\":\"generic-v1\",\"version\":\"v1\"},
  \"image\":{
    \"repository\":\"$repository\",\"manifest_digest\":\"$manifest_digest\",
    \"config_digest\":\"$config_digest\",\"platform\":{$platform}
  },
  \"command\":[\"sleep\",\"300\"],
  \"resources\":{\"memory_bytes\":67108864,\"cpu_millis\":100,\"pids\":32},
  \"capabilities\":{\"state\":false,\"inference\":false,\"service\":false},
  \"state\":{\"schema_version\":\"v1\",\"path\":\"/state\"},\"service\":{}
}" >"$work/capsule.json"
capsule_digest=$("$ctl_bin" capsule sign -in "$work/capsule.json" -out "$work/capsule.dsse.json" \
	-key "$work/publisher.private" -key-id publisher)

token=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
printf '%s\n' "$token" >"$work/token"
chmod 0600 "$work/token" "$work/receipts.private"

"$executor_bin" -initialize-admission-fence -admission-fence-file "$work/fences.bin" >/dev/null

"$executor_bin" -addr "$executor_addr" -token-file "$work/token" -docker-socket /var/run/docker.sock \
	-admission-policy-file "$work/policy.dsse.json" \
	-admission-site-root-public-key-file "$work/site.public" \
	-admission-site-root-key-id site-root -admission-node-id "$node_id" \
	-admission-allow-host-admin-intent \
	-admission-fence-file "$work/fences.bin" -admission-journal-file "$work/journal.bin" \
	-admission-evidence-file "$work/evidence.bin" -admission-evidence-key-file "$work/receipts.private" \
	-max-workloads 2 -max-workloads-per-tenant 1 >"$work/executor.log" 2>&1 &
executor_pid=$!
for _ in $(seq 1 30); do
	if ! kill -0 "$executor_pid" 2>/dev/null; then
		echo 'Executor exited during startup' >&2
		exit 1
	fi
	if curl -fsS -H "Authorization: Bearer $token" "$executor_url/v1/readiness" >/dev/null 2>&1; then break; fi
	sleep 1
done
curl -fsS -H "Authorization: Bearer $token" "$executor_url/v1/readiness" >/dev/null

capsule_base64=$(base64 -w0 "$work/capsule.dsse.json")
printf '%s\n' "{
  \"capsule_dsse_base64\":\"$capsule_base64\",
  \"intent\":{
    \"tenant_id\":\"$tenant_id\",\"node_id\":\"$node_id\",\"instance_id\":\"$instance_id\",
    \"lineage_id\":\"$lineage_id\",\"generation\":1,\"capsule_digest\":\"$capsule_digest\",
    \"resources\":{\"memory_bytes\":67108864,\"cpu_millis\":100,\"pids\":32},
    \"capabilities\":{\"state\":false,\"inference\":false,\"service\":false},
    \"state_disposition\":\"none\"
  }
}" >"$work/request.json"

response=$(curl -fsS -X POST "$executor_url/v1/admissions" \
	-H 'Content-Type: application/json' -H "Authorization: Bearer $token" \
	--data-binary @"$work/request.json")
runtime_ref=$(sed -n 's/.*"runtime_ref":"\([^"]*\)".*/\1/p' <<<"$response")
test -n "$runtime_ref"
test "$(docker inspect --format '{{.HostConfig.Runtime}}' "$runtime_ref")" = runsc
test "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$runtime_ref")" = none
test "$(docker inspect --format '{{.HostConfig.IpcMode}}' "$runtime_ref")" = private
test "$(docker inspect --format '{{.HostConfig.CgroupnsMode}}' "$runtime_ref")" = private
test -z "$(docker inspect --format '{{.HostConfig.PidMode}}' "$runtime_ref")"
test -z "$(docker inspect --format '{{.HostConfig.UTSMode}}' "$runtime_ref")"
test "$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$runtime_ref")" = no
test "$(docker inspect --format '{{.Config.User}}' "$runtime_ref")" = 65532:65532
curl -fsS -X POST "$executor_url/v1/workloads/$runtime_ref/start" \
	-H "Authorization: Bearer $token" >/dev/null
curl -fsS -X POST "$executor_url/v1/workloads/$runtime_ref/stop" \
	-H "Authorization: Bearer $token" >/dev/null
curl -fsS -X DELETE "$executor_url/v1/workloads/$runtime_ref" \
	-H "Authorization: Bearer $token" >/dev/null
"$ctl_bin" evidence verify -in "$work/evidence.bin" -public-key "$work/receipts.public" \
	-node-id "$node_id" -epoch 1 -expected-sequence 9 >/dev/null
"$ctl_bin" evidence export -in "$work/evidence.bin" -public-key "$work/receipts.public" \
	-node-id "$node_id" -epoch 1 >"$work/evidence.ndjson"
python3 -I - "$work/evidence.ndjson" <<'PY'
import json
import pathlib
import sys

records = [
    json.loads(line)
    for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
    if line
]
events = [record for record in records if isinstance(record.get("sequence"), int)]
expected = [
    ("admission_allow", "allowed"),
    ("journal_prepare", "allowed"),
    ("journal_commit", "committed"),
    ("journal_prepare", "allowed"),
    ("lifecycle_start", "committed"),
    ("journal_prepare", "allowed"),
    ("lifecycle_stop", "committed"),
    ("journal_prepare", "allowed"),
    ("lifecycle_destroy", "committed"),
]
observed = [(record.get("event"), record.get("outcome")) for record in events]
if [record.get("sequence") for record in events] != list(range(1, 10)) or observed != expected:
    raise SystemExit("signed-admission-acceptance: evidence lifecycle is incomplete or out of order")
PY

# A tombstone prevents replaying the consumed generation after destroy.
status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$executor_url/v1/admissions" \
	-H 'Content-Type: application/json' -H "Authorization: Bearer $token" \
	--data-binary @"$work/request.json")
test "$status" = 409

# Equal-generation tampering cannot adopt a different signed artifact or identity.
status=$(sed "s/\"tenant_id\":\"$tenant_id\"/\"tenant_id\":\"unauthorized-$run_id\"/" "$work/request.json" | \
	curl -sS -o /dev/null -w '%{http_code}' -X POST "$executor_url/v1/admissions" \
		-H 'Content-Type: application/json' -H "Authorization: Bearer $token" --data-binary @-)
test "$status" = 403

echo 'Signed admission acceptance passed: local trust, fences, journal, gVisor, and offline receipts verified.'
