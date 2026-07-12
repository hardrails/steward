#!/usr/bin/env bash
# Real Docker+gVisor proof for v1.4 signed HTTP(S) egress and lifecycle enforcement.
set -euo pipefail

docker info --format '{{json .Runtimes}}' | grep -q '"runsc"' || { echo "runsc is required" >&2; exit 2; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }
: "${V14_IMAGE:?set V14_IMAGE to a preloaded repository@sha256 image containing /bin/sleep and curl}"
[[ $V14_IMAGE == *@sha256:* ]] || { echo "V14_IMAGE must be digest pinned" >&2; exit 2; }

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
runtime_ref=
cleanup() {
	status=$?
	[[ -z ${runtime_ref:-} || -z ${token:-} ]] || curl -sS -X DELETE "http://127.0.0.1:18090/v1/workloads/$runtime_ref" -H "Authorization: Bearer $token" >/dev/null || true
	[[ -z ${executor_pid:-} ]] || kill "$executor_pid" 2>/dev/null || true
	[[ -z ${gateway_pid:-} ]] || kill "$gateway_pid" 2>/dev/null || true
	[[ -z ${server_pid:-} ]] || kill "$server_pid" 2>/dev/null || true
	if (( status != 0 )); then
		for log in gateway.log executor.log upstream.log egress-audit.jsonl; do
			if [[ -s $work/$log ]]; then
				echo "--- $log ---" >&2
				sed -n '1,200p' "$work/$log" >&2
			fi
		done
	fi
	[[ -z ${relay_image:-} ]] || docker image rm "$relay_image" >/dev/null 2>&1 || true
	docker container prune -f --filter label=io.hardrails.relay.managed=true >/dev/null 2>&1 || true
	docker network prune -f --filter label=io.hardrails.network.managed=true >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

for package in steward-executor steward-gateway steward-relay stewardctl; do
	if [[ -n ${V14_BIN_DIR:-} ]]; then
		[[ -f $V14_BIN_DIR/$package ]] || { echo "V14_BIN_DIR is missing $package" >&2; exit 2; }
		install -m 0755 "$V14_BIN_DIR/$package" "$work/$package"
	else
		command -v go >/dev/null || { echo "go or V14_BIN_DIR with Linux binaries is required" >&2; exit 2; }
		(cd "$root" && go build -o "$work/$package" "./cmd/$package")
	fi
done

bridge_ip=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')
[[ -n $bridge_ip ]] || { echo "Docker bridge gateway is unavailable" >&2; exit 2; }
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=steward-egress-test' \
	-addext "subjectAltName=IP:$bridge_ip" -keyout "$work/tls.key" -out "$work/tls.crt" >/dev/null 2>&1
cp "$work/tls.crt" "$work/steward-test-ca.pem"
python3 - "$bridge_ip" "$work/tls.crt" "$work/tls.key" <<'PY' >"$work/upstream.log" 2>&1 &
import http.server, ssl, sys, threading
host, cert, key = sys.argv[1:]
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"steward-egress-ok\n"
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *_): pass
plain = http.server.ThreadingHTTPServer((host, 18082), Handler)
secure = http.server.ThreadingHTTPServer((host, 18443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key); secure.socket = context.wrap_socket(secure.socket, server_side=True)
threading.Thread(target=plain.serve_forever, daemon=True).start(); secure.serve_forever()
PY
server_pid=$!
for _ in $(seq 1 30); do curl --noproxy '*' -fsS "http://$bridge_ip:18082/" >/dev/null 2>&1 && break; sleep 1; done
curl --noproxy '*' -fsS "http://$bridge_ip:18082/" | grep -q steward-egress-ok

install -m 0755 "$work/steward-relay" "$work/relay"
printf '%s\n' 'FROM scratch' 'COPY relay /steward-relay' 'USER 65532:65532' 'ENTRYPOINT ["/steward-relay"]' >"$work/Relayfile"
docker build --network=none --pull=false --provenance=false -q -f "$work/Relayfile" -t steward-v14-egress-relay:latest "$work" >/dev/null
relay_image=$(docker image inspect --format '{{.Id}}' steward-v14-egress-relay:latest)

printf '%s\n' service-token >"$work/service-token"
chmod 0600 "$work/service-token"
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
  \"routes\":[],
  \"egress_audit_file\":\"$work/egress-audit.jsonl\",
  \"egress_routes\":[{
    \"id\":\"acceptance-web\",
    \"destinations\":[{\"host\":\"$bridge_ip\",\"ports\":[18082,18443],\"allowed_cidrs\":[\"$bridge_ip/32\"]}],
    \"max_concurrent\":4,\"max_request_bytes\":1048576,\"max_response_bytes\":1048576,\"max_tunnel_seconds\":30
  }]
}" >"$work/gateway.json"
chmod 0600 "$work/gateway.json"
"$work/steward-gateway" -config "$work/gateway.json" >"$work/gateway.log" 2>&1 & gateway_pid=$!
for _ in $(seq 1 30); do [[ -S $work/gateway/control.sock ]] && break; sleep 1; done
[[ -S $work/gateway/control.sock ]]

"$work/stewardctl" keygen -private-out "$work/site.private" -public-out "$work/site.public" >/dev/null
"$work/stewardctl" keygen -private-out "$work/publisher.private" -public-out "$work/publisher.public" >/dev/null
"$work/stewardctl" keygen -private-out "$work/receipts.private" -public-out "$work/receipts.public" >/dev/null
publisher_public=$(tr -d '\n' <"$work/publisher.public")
manifest_digest=${V14_IMAGE##*@}
repository=${V14_IMAGE%@*}
config_digest=$(docker image inspect --format '{{.Id}}' "$V14_IMAGE")
architecture=$(docker image inspect --format '{{.Architecture}}' "$V14_IMAGE")
printf '%s\n' "{
 \"schema_version\":\"steward.admission.v1\",\"policy_id\":\"v14-egress\",\"policy_epoch\":1,
 \"publishers\":[{\"key_id\":\"publisher\",\"public_key\":\"$publisher_public\",\"revoked\":false,
   \"allowed_profiles\":[{\"id\":\"generic-v1\",\"version\":\"v1\"}],\"allowed_repositories\":[\"$repository\"],
   \"allowed_manifest_digests\":[\"$manifest_digest\"],\"resource_ceiling\":{\"memory_bytes\":67108864,\"cpu_millis\":100,\"pids\":32}}],
 \"tenants\":[{\"tenant_id\":\"tenant-a\",\"publisher_key_ids\":[\"publisher\"],
   \"resource_ceiling\":{\"memory_bytes\":67108864,\"cpu_millis\":100,\"pids\":32},\"egress_route_ids\":[\"acceptance-web\"]}]
}" >"$work/policy.json"
"$work/stewardctl" policy sign -in "$work/policy.json" -out "$work/policy.dsse.json" -key "$work/site.private" -key-id site-root >/dev/null
printf '%s\n' "{
 \"schema_version\":\"steward.admission.v1\",\"capsule_id\":\"v14-agent\",\"publisher_key_id\":\"publisher\",
 \"profile\":{\"id\":\"generic-v1\",\"version\":\"v1\"},
 \"image\":{\"repository\":\"$repository\",\"manifest_digest\":\"$manifest_digest\",\"config_digest\":\"$config_digest\",\"platform\":{\"os\":\"linux\",\"architecture\":\"$architecture\"}},
 \"command\":[\"/bin/sleep\",\"300\"],\"resources\":{\"memory_bytes\":67108864,\"cpu_millis\":100,\"pids\":32},
 \"capabilities\":{\"state\":false,\"inference\":false,\"service\":false,\"egress\":true},
 \"state\":{\"schema_version\":\"v1\",\"path\":\"/state\"},\"service\":{}
}" >"$work/capsule.json"
capsule_digest=$("$work/stewardctl" capsule sign -in "$work/capsule.json" -out "$work/capsule.dsse.json" -key "$work/publisher.private" -key-id publisher)
capsule_base64=$(base64 <"$work/capsule.dsse.json" | tr -d '\n')

token=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
printf '%s\n' "$token" >"$work/token"; chmod 0600 "$work/token" "$work/receipts.private"
"$work/steward-executor" -initialize-admission-fence -admission-fence-file "$work/fences.bin" >/dev/null
"$work/steward-executor" -addr 127.0.0.1:18090 -token-file "$work/token" -admission-policy-file "$work/policy.dsse.json" \
	-admission-site-root-public-key-file "$work/site.public" -admission-site-root-key-id site-root -admission-node-id node-a \
	-admission-allow-host-admin-intent -admission-fence-file "$work/fences.bin" -admission-journal-file "$work/journal.bin" \
	-admission-evidence-file "$work/evidence.bin" -admission-evidence-key-file "$work/receipts.private" \
	-gateway-control-socket "$work/gateway/control.sock" -gateway-grant-root "$work/grants" -relay-image "$relay_image" -relay-gid "$gid" \
	>"$work/executor.log" 2>&1 & executor_pid=$!
for _ in $(seq 1 30); do curl -fsS http://127.0.0.1:18090/v1/healthz >/dev/null 2>&1 && break; sleep 1; done

payload="{\"capsule_dsse_base64\":\"$capsule_base64\",\"intent\":{\"tenant_id\":\"tenant-a\",\"node_id\":\"node-a\",\"instance_id\":\"agent-1\",\"lineage_id\":\"lineage-1\",\"generation\":1,\"capsule_digest\":\"$capsule_digest\",\"resources\":{\"memory_bytes\":67108864,\"cpu_millis\":100,\"pids\":32},\"capabilities\":{\"state\":false,\"inference\":false,\"service\":false,\"egress\":true},\"state_disposition\":\"none\",\"egress_route_ids\":[\"acceptance-web\"]}}"
admission_status=$(curl -sS -o "$work/admission-response.json" -w '%{http_code}' -X POST http://127.0.0.1:18090/v1/admissions \
	-H 'Content-Type: application/json' -H "Authorization: Bearer $token" --data-binary "$payload")
if [[ $admission_status != 200 && $admission_status != 201 ]]; then
	echo "admission failed with HTTP $admission_status: $(<"$work/admission-response.json")" >&2
	exit 1
fi
response=$(<"$work/admission-response.json")
runtime_ref=$(sed -n 's/.*"runtime_ref":"\([^"]*\)".*/\1/p' <<<"$response")
[[ $response == *'"egress_proxy":"http://steward-relay:8082"'* && -n $runtime_ref ]]
curl -fsS -X POST "http://127.0.0.1:18090/v1/workloads/$runtime_ref/start" -H "Authorization: Bearer $token" >/dev/null

docker inspect --format '{{json .HostConfig.Dns}}' "$runtime_ref" | grep -q '"127.0.0.1"'
if docker exec "$runtime_ref" curl --noproxy '*' --connect-timeout 2 -fsS "http://$bridge_ip:18082/direct-bypass" >/dev/null 2>&1; then
	echo "agent bypassed the relay from its internal network" >&2
	exit 1
fi
docker exec "$runtime_ref" curl -fsS "http://$bridge_ip:18082/allowed-secret-path?secret=must-not-log" | grep -q steward-egress-ok
docker exec "$runtime_ref" curl -kfsS "https://$bridge_ip:18443/" | grep -q steward-egress-ok
if docker exec "$runtime_ref" curl -fsS "http://$bridge_ip:18083/denied" >/dev/null 2>&1; then
	echo "unlisted destination port was reachable" >&2; exit 1
fi
"$work/stewardctl" node egress -node-url http://127.0.0.1:18090 -token-file "$work/token" -runtime-ref "$runtime_ref" | grep -q '"allowed":2'
grep -q '"decision":"allow"' "$work/egress-audit.jsonl"
grep -q '"decision":"deny"' "$work/egress-audit.jsonl"
grep -q '"decision":"terminal"' "$work/egress-audit.jsonl"
if grep -Eq 'allowed-secret-path|must-not-log' "$work/egress-audit.jsonl"; then
	echo "egress audit leaked URL path or query data" >&2
	exit 1
fi

curl -fsS -X POST "http://127.0.0.1:18090/v1/workloads/$runtime_ref/stop" -H "Authorization: Bearer $token" >/dev/null
curl -fsS -X POST "http://127.0.0.1:18090/v1/workloads/$runtime_ref/start" -H "Authorization: Bearer $token" >/dev/null
docker exec "$runtime_ref" curl -kfsS "https://$bridge_ip:18443/" | grep -q steward-egress-ok
curl -fsS -X DELETE "http://127.0.0.1:18090/v1/workloads/$runtime_ref" -H "Authorization: Bearer $token" >/dev/null
runtime_ref=
"$work/stewardctl" evidence verify -in "$work/evidence.bin" -public-key "$work/receipts.public" -node-id node-a | grep -q 'valid evidence chain'
echo "v1.4 egress acceptance passed: gVisor, HTTP, HTTPS CONNECT, denial, DNS isolation, audit, stats, lifecycle, and receipts verified."
