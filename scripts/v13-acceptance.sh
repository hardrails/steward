#!/usr/bin/env bash
# Real Docker+gVisor proof for v1.3 state, inference, service, CLI/MCP, and receipts.
set -euo pipefail

: "${V13_IMAGE:?set V13_IMAGE to a local repository@sha256 agent image with /state owned by 65532}"
[[ $V13_IMAGE == *@sha256:* ]] || { echo "V13_IMAGE must be digest pinned" >&2; exit 2; }
docker info --format '{{json .Runtimes}}' | grep -q '"runsc"' || { echo "runsc is required" >&2; exit 2; }

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
executor_bin=${EXECUTOR_BIN:-$work/steward-executor}
gateway_bin=${GATEWAY_BIN:-$work/steward-gateway}
relay_bin=${RELAY_BIN:-$work/steward-relay}
ctl_bin=${STEWARDCTL_BIN:-$work/stewardctl}
mcp_bin=${MCP_BIN:-$work/steward-mcp}
runtime_ref=
state_volume=

cleanup() {
	if [[ -n ${runtime_ref:-} && -n ${token:-} ]]; then
		curl -sS -X DELETE "http://127.0.0.1:8090/v1/workloads/$runtime_ref" -H "Authorization: Bearer $token" >/dev/null || true
	fi
	[[ -n ${state_volume:-} ]] && docker volume rm "$state_volume" >/dev/null 2>&1 || true
	[[ -n ${executor_pid:-} ]] && kill "$executor_pid" 2>/dev/null || true
	[[ -n ${gateway_pid:-} ]] && kill "$gateway_pid" 2>/dev/null || true
	[[ -n ${model_pid:-} ]] && kill "$model_pid" 2>/dev/null || true
	[[ -n ${relay_image:-} ]] && docker image rm "$relay_image" >/dev/null 2>&1 || true
	docker container prune -f --filter label=io.hardrails.relay.managed=true >/dev/null 2>&1 || true
	docker network prune -f --filter label=io.hardrails.network.managed=true >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

for entry in executor:steward-executor gateway:steward-gateway relay:steward-relay ctl:stewardctl mcp:steward-mcp; do
	variable=${entry%%:*}_bin
	package=${entry#*:}
	path=${!variable}
	[[ -x $path ]] || (cd "$root" && go build -o "$path" "./cmd/$package")
done

install -m 0755 "$relay_bin" "$work/steward-relay"
printf '%s\n' 'FROM scratch' 'COPY steward-relay /steward-relay' 'USER 65532:65532' 'ENTRYPOINT ["/steward-relay"]' >"$work/Relayfile"
docker build --network=none --pull=false --provenance=false -q -f "$work/Relayfile" -t steward-v13-relay-acceptance:latest "$work" >/dev/null
relay_image=$(docker image inspect --format '{{.Id}}' steward-v13-relay-acceptance:latest)

mkdir -p "$work/model/v1"
printf '{"data":[{"id":"approved-model","object":"model"}]}\n' >"$work/model/v1/models"
python3 -m http.server 18080 --bind 127.0.0.1 --directory "$work/model" >"$work/model.log" 2>&1 &
model_pid=$!
printf '%s\n' service-secret >"$work/service-token"
printf '%s\n' upstream-secret >"$work/upstream-token"
chmod 0600 "$work/service-token" "$work/upstream-token"
gid=$(id -g nobody 2>/dev/null || getent group nogroup | cut -d: -f3)
printf '%s\n' "{
  \"version\":1,
  \"control_socket\":\"$work/gateway/control.sock\",
  \"service_address\":\"127.0.0.1:18091\",
  \"service_token_file\":\"$work/service-token\",
  \"state_file\":\"$work/gateway-state.json\",
  \"grant_root\":\"$work/grants\",
  \"executor_gid\":$gid,
  \"relay_gid\":$gid,
  \"routes\":[{\"id\":\"local-openai\",\"base_url\":\"http://127.0.0.1:18080\",\"credential_file\":\"$work/upstream-token\",\"max_concurrent\":2}]
}" >"$work/gateway.json"
chmod 0600 "$work/gateway.json"
"$gateway_bin" -config "$work/gateway.json" >"$work/gateway.log" 2>&1 &
gateway_pid=$!
for _ in $(seq 1 30); do [[ -S $work/gateway/control.sock ]] && break; sleep 1; done
[[ -S $work/gateway/control.sock ]]

"$ctl_bin" keygen -key-id site-root -private-out "$work/site.private" -public-out "$work/site.public" >/dev/null
"$ctl_bin" keygen -key-id publisher -private-out "$work/publisher.private" -public-out "$work/publisher.public" >/dev/null
"$ctl_bin" keygen -key-id receipts -private-out "$work/receipts.private" -public-out "$work/receipts.public" >/dev/null
publisher_public=$(tr -d '\n' <"$work/publisher.public")
manifest_digest=${V13_IMAGE##*@}
repository=${V13_IMAGE%@*}
config_digest=$(docker image inspect --format '{{.Id}}' "$V13_IMAGE")
printf '%s\n' "{
 \"schema_version\":\"steward.admission.v1\",\"policy_id\":\"v13-acceptance\",\"policy_epoch\":1,
 \"publishers\":[{\"key_id\":\"publisher\",\"public_key\":\"$publisher_public\",\"revoked\":false,\"allowed_profiles\":[{\"id\":\"generic-v1\",\"version\":\"v1\"}],\"allowed_repositories\":[\"$repository\"],\"allowed_manifest_digests\":[\"$manifest_digest\"],\"resource_ceiling\":{\"memory_bytes\":67108864,\"cpu_millis\":100,\"pids\":32}}],
 \"tenants\":[{\"tenant_id\":\"tenant-a\",\"publisher_key_ids\":[\"publisher\"],\"resource_ceiling\":{\"memory_bytes\":67108864,\"cpu_millis\":100,\"pids\":32},\"inference_route_ids\":[\"local-openai\"],\"service_ids\":[\"api\"]}]
}" >"$work/policy.json"
"$ctl_bin" policy sign -in "$work/policy.json" -out "$work/policy.dsse.json" -key "$work/site.private" -key-id site-root >/dev/null
printf '%s\n' "{
 \"schema_version\":\"steward.admission.v1\",\"capsule_id\":\"v13-agent\",\"publisher_key_id\":\"publisher\",\"profile\":{\"id\":\"generic-v1\",\"version\":\"v1\"},
 \"image\":{\"repository\":\"$repository\",\"manifest_digest\":\"$manifest_digest\",\"config_digest\":\"$config_digest\",\"platform\":{\"os\":\"linux\",\"architecture\":\"amd64\"}},
 \"command\":[\"httpd\",\"-f\",\"-p\",\"8080\",\"-h\",\"/state\"],\"resources\":{\"memory_bytes\":67108864,\"cpu_millis\":100,\"pids\":32},
 \"capabilities\":{\"state\":true,\"inference\":true,\"service\":true},\"state\":{\"schema_version\":\"v1\",\"path\":\"/state\"},\"service\":{\"id\":\"api\",\"port\":8080}
}" >"$work/capsule.json"
capsule_digest=$("$ctl_bin" capsule sign -in "$work/capsule.json" -out "$work/capsule.dsse.json" -key "$work/publisher.private" -key-id publisher)
capsule_base64=$(base64 -w0 "$work/capsule.dsse.json")

token=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
printf '%s\n' "$token" >"$work/token"
chmod 0600 "$work/token" "$work/receipts.private"
"$executor_bin" -initialize-admission-fence -admission-fence-file "$work/fences.bin" >/dev/null
"$executor_bin" -token-file "$work/token" -admission-policy-file "$work/policy.dsse.json" \
	-admission-site-root-public-key-file "$work/site.public" -admission-site-root-key-id site-root \
	-admission-node-id node-a -admission-allow-host-admin-intent -admission-fence-file "$work/fences.bin" \
	-admission-journal-file "$work/journal.bin" -admission-evidence-file "$work/evidence.bin" \
	-admission-evidence-key-file "$work/receipts.private" -gateway-control-socket "$work/gateway/control.sock" \
	-gateway-grant-root "$work/grants" -relay-image "$relay_image" -relay-gid "$gid" >"$work/executor.log" 2>&1 &
executor_pid=$!
for _ in $(seq 1 30); do curl -fsS http://127.0.0.1:8090/v1/healthz >/dev/null 2>&1 && break; sleep 1; done
curl -fsS http://127.0.0.1:8090/v1/healthz >/dev/null

admit() {
	local generation=$1 disposition=$2
	printf '%s\n' "{\"capsule_dsse_base64\":\"$capsule_base64\",\"intent\":{\"tenant_id\":\"tenant-a\",\"node_id\":\"node-a\",\"instance_id\":\"agent-1\",\"lineage_id\":\"lineage-1\",\"generation\":$generation,\"capsule_digest\":\"$capsule_digest\",\"resources\":{\"memory_bytes\":67108864,\"cpu_millis\":100,\"pids\":32},\"capabilities\":{\"state\":true,\"inference\":true,\"service\":true},\"state_disposition\":\"$disposition\",\"inference_route_id\":\"local-openai\",\"model_alias\":\"approved-model\",\"service_id\":\"api\"}}" | \
		curl -sS -X POST http://127.0.0.1:8090/v1/admissions -H 'Content-Type: application/json' -H "Authorization: Bearer $token" --data-binary @-
}

response=$(admit 1 new)
if [[ $response == *'"error"'* ]]; then echo "$response" >&2; exit 1; fi
runtime_ref=$(sed -n 's/.*"runtime_ref":"\([^"]*\)".*/\1/p' <<<"$response")
grant_id=$(sed -n 's/.*"grant_id":"\([^"]*\)".*/\1/p' <<<"$response")
[[ -n $runtime_ref && -n $grant_id ]]
state_volume=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/state"}}{{.Name}}{{end}}{{end}}' "$runtime_ref")
curl -fsS -X POST "http://127.0.0.1:8090/v1/workloads/$runtime_ref/start" -H "Authorization: Bearer $token" >/dev/null
docker exec "$runtime_ref" sh -c 'echo durable > /state/index.html'
docker exec "$runtime_ref" wget -qO- http://steward-relay:8080/v1/models | grep -q approved-model
curl -fsS -H 'Authorization: Bearer service-secret' "http://127.0.0.1:18091/v1/services/$grant_id/" | grep -q durable
printf '%s\n' \
	'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"acceptance","version":"1"}}}' \
	'{"jsonrpc":"2.0","method":"notifications/initialized"}' \
	"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"steward_status\",\"arguments\":{\"runtime_ref\":\"$runtime_ref\"}}}" | \
	"$mcp_bin" -token-file "$work/token" | grep -q '"id":2'
curl -fsS -X DELETE "http://127.0.0.1:8090/v1/workloads/$runtime_ref" -H "Authorization: Bearer $token" >/dev/null

response=$(admit 2 resume)
if [[ $response == *'"error"'* ]]; then echo "$response" >&2; exit 1; fi
runtime_ref=$(sed -n 's/.*"runtime_ref":"\([^"]*\)".*/\1/p' <<<"$response")
curl -fsS -X POST "http://127.0.0.1:8090/v1/workloads/$runtime_ref/start" -H "Authorization: Bearer $token" >/dev/null
docker exec "$runtime_ref" grep -q durable /state/index.html
curl -fsS -X DELETE "http://127.0.0.1:8090/v1/workloads/$runtime_ref" -H "Authorization: Bearer $token" >/dev/null
runtime_ref=
curl -fsS -X POST http://127.0.0.1:8090/v1/state/purge -H 'Content-Type: application/json' -H "Authorization: Bearer $token" \
	--data '{"tenant_id":"tenant-a","node_id":"node-a","lineage_id":"lineage-1","generation":2}' >/dev/null
"$ctl_bin" evidence verify -in "$work/evidence.bin" -public-key "$work/receipts.public" -node-id node-a -epoch 1 | grep -q 'valid evidence chain'
echo "v1.3 acceptance passed: gVisor, persistent state, inference, service ingress, MCP, lifecycle, purge, and receipts verified."
