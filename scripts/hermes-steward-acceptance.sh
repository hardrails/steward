#!/usr/bin/env bash
# Signed-admission proof that Hermes executes the bundled workspace skill through Steward.
set -euo pipefail
umask 077

: "${HERMES_ARCHIVE:?set HERMES_ARCHIVE to a builder-produced Hermes adapter .tar}"
[[ ${STEWARD_ACCEPT_DISPOSABLE_HOST_RISK:-} == YES ]] || {
	echo "hermes-steward-acceptance: set STEWARD_ACCEPT_DISPOSABLE_HOST_RISK=YES only on a disposable host" >&2
	exit 2
}
for command in base64 curl docker go python3; do
	command -v "$command" >/dev/null 2>&1 || { echo "hermes-steward-acceptance: $command is required" >&2; exit 2; }
done
docker info --format '{{json .Runtimes}}' | grep -q '"runsc"' || {
	echo "hermes-steward-acceptance: Docker runtime runsc is required" >&2
	exit 2
}
[[ -f $HERMES_ARCHIVE && ! -L $HERMES_ARCHIVE ]] || {
	echo "hermes-steward-acceptance: HERMES_ARCHIVE must be a regular file" >&2
	exit 2
}

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
work=$(mktemp -d /tmp/steward-hermes-integration.XXXXXX)
executor_bin=${EXECUTOR_BIN:-$work/steward-executor}
gateway_bin=${GATEWAY_BIN:-$work/steward-gateway}
relay_bin=${RELAY_BIN:-$work/steward-relay}
ctl_bin=${STEWARDCTL_BIN:-$work/stewardctl}
run_id=${STEWARD_ACCEPTANCE_RUN_ID:-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')}
[[ $run_id =~ ^[a-f0-9]{16}$ ]] || { echo "hermes-steward-acceptance: invalid STEWARD_ACCEPTANCE_RUN_ID" >&2; exit 2; }
tenant_id=hermes-$run_id
instance_id=agent-$run_id
lineage_id=lineage-$run_id
node_id=node-$run_id
repository=local/hermes-agent
runtime_ref=
state_volume=
imported_runtime_digest=
debug_keep=${HERMES_DEBUG_KEEP_FAILED_WORK:-NO}
[[ $debug_keep == YES || $debug_keep == NO ]] || { echo "hermes-steward-acceptance: HERMES_DEBUG_KEEP_FAILED_WORK must be YES or NO" >&2; exit 2; }

cleanup() {
	local status=$?
	if [[ -n ${runtime_ref:-} && -n ${token:-} ]]; then
		curl -sS -X DELETE "http://127.0.0.1:8090/v1/workloads/$runtime_ref" -H "Authorization: Bearer $token" >/dev/null 2>&1 || true
	fi
	[[ -n ${executor_pid:-} ]] && kill "$executor_pid" 2>/dev/null || true
	[[ -n ${gateway_pid:-} ]] && kill "$gateway_pid" 2>/dev/null || true
	[[ -n ${model_pid:-} ]] && kill "$model_pid" 2>/dev/null || true
	docker ps -aq --filter label=io.hardrails.relay.managed=true \
		--filter "label=io.hardrails.tenant=$tenant_id" \
		--filter "label=io.hardrails.instance=$instance_id" | xargs -r docker rm -f >/dev/null 2>&1 || true
	docker network ls -q --filter label=io.hardrails.network.managed=true \
		--filter "label=io.hardrails.tenant=$tenant_id" \
		--filter "label=io.hardrails.instance=$instance_id" | xargs -r docker network rm >/dev/null 2>&1 || true
	[[ -n ${state_volume:-} ]] && docker volume rm "$state_volume" >/dev/null 2>&1 || true
	[[ -n ${relay_tag:-} ]] && docker image rm "$relay_tag" >/dev/null 2>&1 || true
	[[ -n ${imported_runtime_digest:-} ]] && docker image rm "$imported_runtime_digest" >/dev/null 2>&1 || true
	if [[ $status -eq 0 || $debug_keep == NO ]]; then
		rm -rf "$work"
	else
		echo "hermes-steward-acceptance: preserved diagnostics at $work" >&2
	fi
	exit "$status"
}
trap cleanup EXIT

for entry in executor:steward-executor gateway:steward-gateway relay:steward-relay ctl:stewardctl; do
	variable=${entry%%:*}_bin
	package=${entry#*:}
	path=${!variable}
	[[ -x $path ]] || (cd "$root" && go build -o "$path" "./cmd/$package")
done

image_json=$($ctl_bin image inspect -archive "$HERMES_ARCHIVE")
mapfile -t image_values < <(python3 -c '
import json,sys
p=json.load(sys.stdin)
print(p["manifest_digest"])
print(p["config_digest"])
print(p["platform"]["os"])
print(p["platform"]["architecture"])
print(p["platform"].get("variant", ""))
' <<<"$image_json")
(( ${#image_values[@]} == 5 )) || { echo "hermes-steward-acceptance: incomplete archive identity" >&2; exit 1; }
manifest_digest=${image_values[0]}
config_digest=${image_values[1]}
image_os=${image_values[2]}
image_arch=${image_values[3]}
image_variant=${image_values[4]}
[[ $image_os == linux && $manifest_digest =~ ^sha256:[a-f0-9]{64}$ && $config_digest =~ ^sha256:[a-f0-9]{64}$ ]] || {
	echo "hermes-steward-acceptance: invalid archive identity" >&2
	exit 1
}

install -m 0755 "$relay_bin" "$work/steward-relay"
printf '%s\n' 'FROM scratch' 'COPY steward-relay /steward-relay' 'USER 65532:65532' 'ENTRYPOINT ["/steward-relay"]' >"$work/Relayfile"
relay_tag=steward-hermes-relay-acceptance:$run_id
docker build --network=none --pull=false --provenance=false -q -f "$work/Relayfile" -t "$relay_tag" "$work" >/dev/null
relay_image=$(docker image inspect --format '{{.Id}}' "$relay_tag")

python3 - "$root/adapters/hermes-agent/fixture_model.py" <<'PY' >"$work/model.log" 2>&1 &
import http.server
import importlib.util
import sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("fixture_model", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
http.server.ThreadingHTTPServer(("127.0.0.1", 18080), module.Handler).serve_forever()
PY
model_pid=$!
for _ in $(seq 1 30); do
	curl -fsS http://127.0.0.1:18080/v1/models >/dev/null 2>&1 && break
	kill -0 "$model_pid" 2>/dev/null || { echo "hermes-steward-acceptance: model fixture exited" >&2; exit 1; }
	sleep 1
done
curl -fsS http://127.0.0.1:18080/v1/models >/dev/null

printf '%s\n' service-secret >"$work/service-token"
gid=$(id -g nobody 2>/dev/null || getent group nogroup | cut -d: -f3)
mkdir -p "$work/gateway" "$work/grants"
printf '%s\n' "{
  \"version\":1,
  \"control_socket\":\"$work/gateway/control.sock\",
  \"service_address\":\"127.0.0.1:18091\",
  \"service_token_file\":\"$work/service-token\",
  \"state_file\":\"$work/gateway-state.json\",
  \"grant_root\":\"$work/grants\",
  \"executor_gid\":$gid,
  \"relay_gid\":$gid,
  \"routes\":[{\"id\":\"local-openai\",\"base_url\":\"http://127.0.0.1:18080/v1\",\"max_concurrent\":2}]
}" >"$work/gateway.json"
"$gateway_bin" -config "$work/gateway.json" >"$work/gateway.log" 2>&1 &
gateway_pid=$!
for _ in $(seq 1 30); do [[ -S $work/gateway/control.sock ]] && break; sleep 1; done
[[ -S $work/gateway/control.sock ]] || { echo "hermes-steward-acceptance: Gateway did not become ready" >&2; exit 1; }

"$ctl_bin" keygen -key-id site-root -private-out "$work/site.private" -public-out "$work/site.public" >/dev/null
"$ctl_bin" keygen -key-id publisher -private-out "$work/publisher.private" -public-out "$work/publisher.public" >/dev/null
"$ctl_bin" keygen -key-id receipts -private-out "$work/receipts.private" -public-out "$work/receipts.public" >/dev/null
publisher_public=$(tr -d '\n' <"$work/publisher.public")
platform="\"os\":\"$image_os\",\"architecture\":\"$image_arch\""
[[ -z $image_variant ]] || platform+=",\"variant\":\"$image_variant\""
printf '%s\n' "{
  \"schema_version\":\"steward.admission.v1\",\"policy_id\":\"hermes-acceptance\",\"policy_epoch\":1,
  \"publishers\":[{\"key_id\":\"publisher\",\"public_key\":\"$publisher_public\",\"revoked\":false,
    \"allowed_profiles\":[{\"id\":\"hermes-v1\",\"version\":\"v1\"}],
    \"allowed_repositories\":[\"$repository\"],\"allowed_manifest_digests\":[\"$manifest_digest\"],
    \"resource_ceiling\":{\"memory_bytes\":1073741824,\"cpu_millis\":1000,\"pids\":128}}],
  \"tenants\":[{\"tenant_id\":\"$tenant_id\",\"publisher_key_ids\":[\"publisher\"],
    \"resource_ceiling\":{\"memory_bytes\":1073741824,\"cpu_millis\":1000,\"pids\":128},
    \"inference_route_ids\":[\"local-openai\"],\"inference_model_aliases\":[\"steward-fixture-model\"],
    \"service_ids\":[\"hermes-api\"]}]
}" >"$work/policy.json"
"$ctl_bin" policy sign -in "$work/policy.json" -out "$work/policy.dsse.json" -key "$work/site.private" -key-id site-root >/dev/null
printf '%s\n' "{
  \"schema_version\":\"steward.admission.v1\",\"capsule_id\":\"hermes-workspace-audit\",\"publisher_key_id\":\"publisher\",
  \"profile\":{\"id\":\"hermes-v1\",\"version\":\"v1\"},
  \"image\":{\"repository\":\"$repository\",\"manifest_digest\":\"$manifest_digest\",\"config_digest\":\"$config_digest\",\"platform\":{$platform}},
  \"command\":[\"serve\"],\"resources\":{\"memory_bytes\":1073741824,\"cpu_millis\":1000,\"pids\":128},
  \"capabilities\":{\"state\":true,\"inference\":true,\"service\":true,\"egress\":false},
  \"state\":{\"schema_version\":\"v1\",\"path\":\"/opt/data\"},\"service\":{\"id\":\"hermes-api\",\"port\":8766}
}" >"$work/capsule.json"
capsule_digest=$("$ctl_bin" capsule sign -in "$work/capsule.json" -out "$work/capsule.dsse.json" -key "$work/publisher.private" -key-id publisher)
capsule_base64=$(base64 <"$work/capsule.dsse.json" | tr -d '\n')

import_result=$("$ctl_bin" image import -archive "$HERMES_ARCHIVE" -capsule "$work/capsule.dsse.json" \
	-policy "$work/policy.dsse.json" -site-root-public-key "$work/site.public" -site-root-key-id site-root)
python3 -c 'import json,sys; p=json.load(sys.stdin); assert p["image"]["manifest_digest"]==sys.argv[1] and p["image"]["config_digest"]==sys.argv[2]' \
	"$manifest_digest" "$config_digest" <<<"$import_result"
imported_runtime_digest=$manifest_digest

token=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
printf '%s\n' "$token" >"$work/token"
"$executor_bin" -initialize-admission-fence -admission-fence-file "$work/fences.bin" >/dev/null
"$executor_bin" -token-file "$work/token" -admission-policy-file "$work/policy.dsse.json" \
	-admission-site-root-public-key-file "$work/site.public" -admission-site-root-key-id site-root \
	-admission-node-id "$node_id" -admission-allow-host-admin-intent -admission-fence-file "$work/fences.bin" \
	-admission-journal-file "$work/journal.bin" -admission-evidence-file "$work/evidence.bin" \
	-admission-evidence-key-file "$work/receipts.private" -allow-unquotaed-state-on-dedicated-host \
	-gateway-control-socket "$work/gateway/control.sock" -gateway-grant-root "$work/grants" \
	-relay-image "$relay_image" -relay-gid "$gid" >"$work/executor.log" 2>&1 &
executor_pid=$!
for _ in $(seq 1 30); do
	kill -0 "$executor_pid" 2>/dev/null || { echo "hermes-steward-acceptance: Executor exited" >&2; exit 1; }
	curl -fsS -H "Authorization: Bearer $token" http://127.0.0.1:8090/v1/readiness >/dev/null 2>&1 && break
	sleep 1
done
curl -fsS -H "Authorization: Bearer $token" http://127.0.0.1:8090/v1/readiness >/dev/null

admit() {
	local generation=$1 disposition=$2
	printf '%s\n' "{\"capsule_dsse_base64\":\"$capsule_base64\",\"intent\":{\"tenant_id\":\"$tenant_id\",\"node_id\":\"$node_id\",\"instance_id\":\"$instance_id\",\"lineage_id\":\"$lineage_id\",\"generation\":$generation,\"capsule_digest\":\"$capsule_digest\",\"resources\":{\"memory_bytes\":1073741824,\"cpu_millis\":1000,\"pids\":128},\"capabilities\":{\"state\":true,\"inference\":true,\"service\":true,\"egress\":false},\"state_disposition\":\"$disposition\",\"inference_route_id\":\"local-openai\",\"model_alias\":\"steward-fixture-model\",\"service_id\":\"hermes-api\"}}" | \
		curl -fsS -X POST http://127.0.0.1:8090/v1/admissions -H 'Content-Type: application/json' -H "Authorization: Bearer $token" --data-binary @-
}

extract_admission() {
	python3 -c 'import json,sys; p=json.load(sys.stdin); print(p["runtime_ref"]); print(p["grant_id"])'
}

run_workspace_audit() {
	local grant=$1 response run_ref terminal status expected
	expected=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["manifest_digest"])' \
		"$root/adapters/hermes-agent/fixtures/skill/workspace-fixture-contract.json")
	response=$(curl -fsS -X POST "http://127.0.0.1:18091/v1/services/$grant/v1/runs" \
		-H 'Authorization: Bearer service-secret' -H 'Content-Type: application/json' \
		--data-binary '{"input":"STEWARD_WORKSPACE_AUDIT","session_id":"steward-integration"}')
	run_ref=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["run_id"])' <<<"$response")
	[[ $run_ref =~ ^run_[a-f0-9]{32}$ ]] || return 1
	status=
	for _ in $(seq 1 180); do
		terminal=$(curl -fsS -H 'Authorization: Bearer service-secret' \
			"http://127.0.0.1:18091/v1/services/$grant/v1/runs/$run_ref")
		status=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' <<<"$terminal")
		[[ $status == completed ]] && break
		[[ $status == failed || $status == cancelled ]] && return 1
		sleep 1
	done
	[[ $status == completed ]] || return 1
	python3 -c 'import json,sys; p=json.load(sys.stdin); assert isinstance(p.get("output"),str) and sys.argv[1] in p["output"]' \
		"$expected" <<<"$terminal"
}

mapfile -t admission < <(admit 1 new | extract_admission)
runtime_ref=${admission[0]}
grant_id=${admission[1]}
curl -fsS -X POST "http://127.0.0.1:8090/v1/workloads/$runtime_ref/start" -H "Authorization: Bearer $token" >/dev/null
[[ $(docker inspect --format '{{.HostConfig.Runtime}}' "$runtime_ref") == runsc ]]
[[ $(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$runtime_ref") == true ]]
state_volume=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/opt/data"}}{{.Name}}{{end}}{{end}}' "$runtime_ref")
[[ -n $state_volume ]]
docker exec -u 65532:65532 "$runtime_ref" sh -c 'mkdir -p /opt/data/workspace/nested && printf "alpha\n" > /opt/data/workspace/alpha.txt && printf "beta\n" > /opt/data/workspace/nested/beta.txt'
curl -fsS -H 'Authorization: Bearer service-secret' "http://127.0.0.1:18091/v1/services/$grant_id/health" | grep -q '"status":"ok"'
run_workspace_audit "$grant_id"
curl -fsS -X DELETE "http://127.0.0.1:8090/v1/workloads/$runtime_ref" -H "Authorization: Bearer $token" >/dev/null
runtime_ref=

mapfile -t admission < <(admit 2 resume | extract_admission)
runtime_ref=${admission[0]}
grant_id=${admission[1]}
curl -fsS -X POST "http://127.0.0.1:8090/v1/workloads/$runtime_ref/start" -H "Authorization: Bearer $token" >/dev/null
run_workspace_audit "$grant_id"
curl -fsS -X DELETE "http://127.0.0.1:8090/v1/workloads/$runtime_ref" -H "Authorization: Bearer $token" >/dev/null
runtime_ref=
curl -fsS -X POST http://127.0.0.1:8090/v1/state/purge -H 'Content-Type: application/json' \
	-H "Authorization: Bearer $token" \
	--data-binary "{\"tenant_id\":\"$tenant_id\",\"node_id\":\"$node_id\",\"lineage_id\":\"$lineage_id\",\"generation\":2}" >/dev/null
state_volume=
"$ctl_bin" evidence verify -in "$work/evidence.bin" -public-key "$work/receipts.public" -node-id "$node_id" -epoch 1 | grep -q 'valid evidence chain'
echo "Hermes Steward acceptance passed: signed import, gVisor, Gateway inference and service, useful signed skill, resume, purge, and receipts verified."
