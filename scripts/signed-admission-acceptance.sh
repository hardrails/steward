#!/usr/bin/env bash
# Real Linux Docker/gVisor proof for v1.2 signed admission and receipts.
set -euo pipefail

: "${V1_IMAGE:?set V1_IMAGE to an already-local repository@sha256 reference}"
case "$V1_IMAGE" in
	*@sha256:????????????????????????????????????????????????????????????????) ;;
	*) echo 'V1_IMAGE must be an immutable repository@sha256 reference' >&2; exit 2 ;;
esac
if ! docker info --format '{{json .Runtimes}}' | grep -q '"runsc"'; then
	echo 'Docker runtime runsc is required' >&2
	exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
executor_bin=${EXECUTOR_BIN:-$work/steward-executor}
ctl_bin=${STEWARDCTL_BIN:-$work/stewardctl}
runtime_ref=

cleanup() {
	if [[ -n ${runtime_ref:-} && -n ${token:-} ]]; then
		curl -sS -X DELETE "http://127.0.0.1:8090/v1/workloads/$runtime_ref" \
			-H "Authorization: Bearer $token" >/dev/null || true
	fi
	if [[ -n ${executor_pid:-} ]]; then kill "$executor_pid" 2>/dev/null || true; fi
	rm -rf "$work"
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
    \"tenant_id\":\"tenant-a\",\"publisher_key_ids\":[\"publisher\"],
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
    \"config_digest\":\"$config_digest\",\"platform\":{\"os\":\"linux\",\"architecture\":\"amd64\"}
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

"$executor_bin" -token-file "$work/token" -docker-socket /var/run/docker.sock \
	-admission-policy-file "$work/policy.dsse.json" \
	-admission-site-root-public-key-file "$work/site.public" \
	-admission-site-root-key-id site-root -admission-node-id node-a \
	-admission-allow-host-admin-intent \
	-admission-fence-file "$work/fences.bin" -admission-journal-file "$work/journal.bin" \
	-admission-evidence-file "$work/evidence.bin" -admission-evidence-key-file "$work/receipts.private" \
	-max-workloads 2 -max-workloads-per-tenant 1 >"$work/executor.log" 2>&1 &
executor_pid=$!
for _ in $(seq 1 30); do
	if curl -fsS http://127.0.0.1:8090/v1/healthz >/dev/null 2>&1; then break; fi
	sleep 1
done
curl -fsS http://127.0.0.1:8090/v1/healthz >/dev/null

capsule_base64=$(base64 -w0 "$work/capsule.dsse.json")
printf '%s\n' "{
  \"capsule_dsse_base64\":\"$capsule_base64\",
  \"intent\":{
    \"tenant_id\":\"tenant-a\",\"node_id\":\"node-a\",\"instance_id\":\"agent-1\",
    \"lineage_id\":\"lineage-1\",\"generation\":1,\"capsule_digest\":\"$capsule_digest\",
    \"resources\":{\"memory_bytes\":67108864,\"cpu_millis\":100,\"pids\":32},
    \"capabilities\":{\"state\":false,\"inference\":false,\"service\":false},
    \"state_disposition\":\"none\"
  }
}" >"$work/request.json"

response=$(curl -fsS -X POST http://127.0.0.1:8090/v1/admissions \
	-H 'Content-Type: application/json' -H "Authorization: Bearer $token" \
	--data-binary @"$work/request.json")
runtime_ref=$(sed -n 's/.*"runtime_ref":"\([^"]*\)".*/\1/p' <<<"$response")
test -n "$runtime_ref"
test "$(docker inspect --format '{{.HostConfig.Runtime}}' "$runtime_ref")" = runsc
test "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$runtime_ref")" = none
test "$(docker inspect --format '{{.Config.User}}' "$runtime_ref")" = 65532:65532
curl -fsS -X POST "http://127.0.0.1:8090/v1/workloads/$runtime_ref/start" \
	-H "Authorization: Bearer $token" >/dev/null
curl -fsS -X POST "http://127.0.0.1:8090/v1/workloads/$runtime_ref/stop" \
	-H "Authorization: Bearer $token" >/dev/null
curl -fsS -X DELETE "http://127.0.0.1:8090/v1/workloads/$runtime_ref" \
	-H "Authorization: Bearer $token" >/dev/null
"$ctl_bin" evidence verify -in "$work/evidence.bin" -public-key "$work/receipts.public" \
	-node-id node-a -epoch 1 | grep -q 'sequence=8'

# A tombstone prevents replaying the consumed generation after destroy.
status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8090/v1/admissions \
	-H 'Content-Type: application/json' -H "Authorization: Bearer $token" \
	--data-binary @"$work/request.json")
test "$status" = 409

# Equal-generation tampering cannot adopt a different signed artifact or identity.
status=$(sed 's/"tenant_id":"tenant-a"/"tenant_id":"tenant-b"/' "$work/request.json" | \
	curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8090/v1/admissions \
		-H 'Content-Type: application/json' -H "Authorization: Bearer $token" --data-binary @-)
test "$status" = 403

echo 'Signed admission acceptance passed: local trust, fences, journal, gVisor, and offline receipts verified.'
