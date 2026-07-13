#!/usr/bin/env bash
# Real Docker/gVisor feasibility gate for the exact pinned Hermes adapter.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
adapter_root=$root/adapters/hermes-agent
revision=095b9eed3801c251796df93f48a8f2a527ff6e70
evidence_out=${HERMES_EVIDENCE_OUT:-$root/dist/acceptance/hermes/feasibility.json}
source_dir=${HERMES_SOURCE_DIR:-}
image=${HERMES_ADAPTER_IMAGE:-}
build_timeout=${HERMES_BUILD_TIMEOUT_SECONDS:-1800}
run_timeout=${HERMES_RUN_TIMEOUT_SECONDS:-180}
debug_keep=${HERMES_DEBUG_KEEP_FAILED_WORK:-NO}

[[ ${STEWARD_ACCEPT_DISPOSABLE_HOST_RISK:-} == YES ]] || {
	echo 'hermes-feasibility: set STEWARD_ACCEPT_DISPOSABLE_HOST_RISK=YES only on a disposable host' >&2
	exit 2
}
[[ $build_timeout =~ ^[0-9]+$ && $build_timeout -ge 60 && $build_timeout -le 3600 ]] || {
	echo 'hermes-feasibility: HERMES_BUILD_TIMEOUT_SECONDS must be 60..3600' >&2
	exit 2
}
[[ $run_timeout =~ ^[0-9]+$ && $run_timeout -ge 30 && $run_timeout -le 600 ]] || {
	echo 'hermes-feasibility: HERMES_RUN_TIMEOUT_SECONDS must be 30..600' >&2
	exit 2
}
[[ $debug_keep == NO || $debug_keep == YES ]] || {
	echo 'hermes-feasibility: HERMES_DEBUG_KEEP_FAILED_WORK must be YES or NO' >&2
	exit 2
}
command -v docker >/dev/null || { echo 'hermes-feasibility: docker is required' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'hermes-feasibility: python3 is required' >&2; exit 2; }
command -v timeout >/dev/null || { echo 'hermes-feasibility: GNU timeout is required' >&2; exit 2; }
docker info --format '{{json .Runtimes}}' | grep -q '"runsc"' || {
	echo 'hermes-feasibility: Docker runtime runsc is required' >&2
	exit 2
}

run_id=${STEWARD_ACCEPTANCE_RUN_ID:-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')}
[[ $run_id =~ ^[a-f0-9]{16}$ ]] || { echo 'hermes-feasibility: invalid STEWARD_ACCEPTANCE_RUN_ID' >&2; exit 2; }
name_prefix=steward-hermes-$run_id
network=$name_prefix
agent=$name_prefix-agent
model=$name_prefix-model
mcp=$name_prefix-mcp
work=$(mktemp -d /tmp/steward-hermes-feasibility.XXXXXX)
checks=$work/checks.tsv
state_root=$work/state
source_archive_digest=unavailable
image_config_digest=unavailable
runtime_observed=unknown
overall=failed
failure_code=unhandled_failure
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
required_checks=(
	source.inputs image.build image.contract network.internal fixture.services
	fixture.network
	runtime.policy agent.readiness adapter.negotiation runtime.identity runtime.filesystem runtime.network
	service.boundary fixture.workspace task.basic task.skill task.mcp
	restart.readiness task.restart restart.state feasibility.complete
)

record() {
	local check=$1 status=$2 detail=$3
	[[ $check =~ ^[a-z0-9_.-]+$ && $status =~ ^(passed|failed)$ && $detail =~ ^[A-Za-z0-9_.:@/+,-]+$ ]] || {
		echo 'hermes-feasibility: internal evidence field validation failed' >&2
		exit 1
	}
	printf '%s\t%s\t%s\n' "$check" "$status" "$detail" >>"$checks"
}

stop_gate() {
	local check=$1 code=$2
	failure_code=$code
	record "$check" failed "$code"
	if [[ $debug_keep == YES ]]; then
		for container in "$agent" "$model" "$mcp"; do
			docker logs "$container" >"$work/$container.log" 2>&1 || true
		done
	fi
	echo "hermes-feasibility: stop gate $check failed ($code)" >&2
	exit 1
}

write_evidence() {
	local exit_status=$1
	if [[ $exit_status -eq 0 ]]; then
		local required count
		for required in "${required_checks[@]}"; do
			count=$(awk -F '\t' -v required="$required" '$1 == required && $2 == "passed" { count++ } END { print count+0 }' "$checks")
			if [[ $count != 1 ]]; then
				overall=failed
				failure_code=required_check_set_incomplete
				record evidence.coverage failed required_check_set_incomplete
				exit_status=1
				break
			fi
		done
		if [[ $exit_status -eq 0 ]]; then
			record evidence.coverage passed required_check_set_complete
			overall=passed
			failure_code=none
		fi
	fi
	mkdir -p "$(dirname "$evidence_out")"
	local evidence_write_status=0
	python3 - "$checks" "$evidence_out" "$overall" "$failure_code" "$started_at" \
		"$revision" "$source_archive_digest" "$image_config_digest" "$runtime_observed" <<'PY' || evidence_write_status=$?
import json
import os
import pathlib
import sys

checks_path, output, overall, failure, started, revision, source_digest, image_digest, runtime = sys.argv[1:]
checks = []
path = pathlib.Path(checks_path)
if path.exists() and path.stat().st_size <= 64 * 1024:
    for line in path.read_text().splitlines():
        fields = line.split("\t")
        if len(fields) == 3:
            checks.append({"id": fields[0], "status": fields[1], "detail": fields[2]})
payload = {
    "schema_version": "steward.agent-feasibility.v1",
    "agent": "hermes-agent",
    "overall": overall,
    "failure_code": failure,
    "started_at": started,
    "upstream_revision": revision,
    "source_archive_sha256": source_digest,
    "image_config_digest": image_digest,
    "runtime": None if runtime == "unknown" else runtime,
    "contains_agent_content": False,
    "checks": checks,
}
destination = pathlib.Path(output)
temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
with temporary.open("x", encoding="utf-8") as stream:
    json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
os.replace(temporary, destination)
directory_fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PY
	if [[ $evidence_write_status -ne 0 ]]; then
		return "$evidence_write_status"
	fi
	return "$exit_status"
}

cleanup() {
	docker rm -f "$agent" "$model" "$mcp" >/dev/null 2>&1 || true
	docker network rm "$network" >/dev/null 2>&1 || true
	if [[ $overall == passed || $debug_keep != YES ]]; then
		rm -rf "$work"
	else
		echo "hermes-feasibility: preserved failed diagnostic workspace: $work" >&2
	fi
}

finalize() {
	local status=$?
	trap - EXIT
	write_evidence "$status" || status=$?
	cleanup
	exit "$status"
}
trap finalize EXIT

: >"$checks"

[[ -n $source_dir && -d $source_dir/.git ]] || stop_gate source.checkout pinned_source_checkout_required
actual_revision=$(git -C "$source_dir" rev-parse HEAD 2>/dev/null || true)
[[ $actual_revision == "$revision" ]] || stop_gate source.revision source_revision_mismatch
git -C "$source_dir" diff --quiet && git -C "$source_dir" diff --cached --quiet || stop_gate source.checkout source_checkout_dirty
(
	cd "$source_dir"
	sha256sum -c "$adapter_root/source-inputs.sha256"
) >"$work/source-inputs.log" 2>&1 || stop_gate source.inputs source_input_digest_mismatch
record source.inputs passed exact_pin_and_digests
source_archive_digest=$(git -C "$source_dir" archive --format=tar "$revision" | sha256sum | awk '{print $1}')
mkdir -p "$work/context/upstream" "$work/context/adapter"
git -C "$source_dir" archive --format=tar "$revision" | tar -xf - -C "$work/context/upstream"
cp -a "$adapter_root"/. "$work/context/adapter/"
image=${image:-steward-hermes-feasibility:$run_id}
timeout "$build_timeout" docker build --pull=false --provenance=false \
	--build-arg "HERMES_SOURCE_REVISION=$revision" \
	-f "$work/context/adapter/Dockerfile" -t "$image" "$work/context" \
	>"$work/build.log" 2>&1 || stop_gate image.build pinned_source_build_failed
record image.build passed pinned_source_build

docker image inspect "$image" >/dev/null 2>&1 || stop_gate image.present image_not_present
image_config_digest=$(docker image inspect --format '{{.Id}}' "$image")
[[ $image_config_digest =~ ^sha256:[a-f0-9]{64}$ ]] || stop_gate image.identity invalid_image_config_digest
image_user=$(docker image inspect --format '{{.Config.User}}' "$image")
[[ $image_user == 65532:65532 ]] || stop_gate image.user image_user_not_65532
volumes=$(docker image inspect --format '{{json .Config.Volumes}}' "$image")
[[ $volumes == null || $volumes == '{}' ]] || stop_gate image.volumes image_declares_volume
record image.contract passed nonroot_no_declared_volumes

mkdir -p "$state_root"
mkdir -p "$state_root/workspace/nested"
printf 'alpha\n' >"$state_root/workspace/alpha.txt"
printf 'beta\n' >"$state_root/workspace/nested/beta.txt"
chmod 0700 "$state_root"
chmod -R u=rwX,go= "$state_root/workspace"
chown -R 65532:65532 "$state_root"
docker network create --internal --label io.hardrails.feasibility=true "$network" >/dev/null
record network.internal passed no_external_route

closed_run=(--runtime runsc --network "$network" --read-only --cap-drop ALL
	--security-opt "no-new-privileges:true" --pids-limit 128 --memory 1073741824
	--memory-swap 1073741824 --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=67108864"
	--user 65532:65532)

docker run -d --name "$model" "${closed_run[@]}" \
	--entrypoint python3 "$image" /opt/steward/fixture_model.py >/dev/null || stop_gate fixture.model model_start_failed
docker run -d --name "$mcp" "${closed_run[@]}" \
	--entrypoint python3 "$image" /opt/steward/fixture_mcp.py >/dev/null || stop_gate fixture.mcp mcp_start_failed
model_ip=$(docker inspect --format "{{(index .NetworkSettings.Networks \"$network\").IPAddress}}" "$model")
mcp_ip=$(docker inspect --format "{{(index .NetworkSettings.Networks \"$network\").IPAddress}}" "$mcp")
python3 - "$model_ip" "$mcp_ip" <<'PY' || stop_gate fixture.network invalid_fixture_addresses
import ipaddress
import sys

model = ipaddress.ip_address(sys.argv[1])
mcp = ipaddress.ip_address(sys.argv[2])
assert model.version == 4 and mcp.version == 4 and model != mcp
PY
fixture_ready=false
for _ in $(seq 1 30); do
	if docker exec -u 65532:65532 "$model" python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8080/v1/models",timeout=2).read(65536)' >/dev/null 2>&1 && \
		docker exec -u 65532:65532 "$mcp" python3 -c 'import urllib.request; r=urllib.request.Request("http://127.0.0.1:8767/mcp",method="HEAD"); urllib.request.urlopen(r,timeout=2).read(1)' >/dev/null 2>&1; then
		fixture_ready=true
		break
	fi
	docker inspect --format '{{.State.Running}}' "$model" | grep -qx true || stop_gate fixture.model model_exited_before_ready
	docker inspect --format '{{.State.Running}}' "$mcp" | grep -qx true || stop_gate fixture.mcp mcp_exited_before_ready
	sleep 1
done
[[ $fixture_ready == true ]] || stop_gate fixture.services fixture_services_not_ready
agent_hosts=(--add-host "steward-relay:$model_ip" --add-host "steward-mcp:$mcp_ip")
docker run -d --name "$agent" --network-alias steward-agent "${closed_run[@]}" "${agent_hosts[@]}" \
	--mount "type=bind,src=$state_root,dst=/opt/data" \
	-e OPENAI_BASE_URL=http://steward-relay:8080/v1 -e OPENAI_API_KEY=steward-local \
	-e OPENAI_MODEL=steward-fixture-model "$image" >/dev/null || stop_gate agent.start agent_start_failed
record fixture.services passed model_and_mcp_gvisor
docker inspect --format '{{json .HostConfig.ExtraHosts}}' "$agent" | grep -Fq "steward-relay:$model_ip" || stop_gate fixture.network model_host_binding_missing
docker inspect --format '{{json .HostConfig.ExtraHosts}}' "$agent" | grep -Fq "steward-mcp:$mcp_ip" || stop_gate fixture.network mcp_host_binding_missing
record fixture.network passed fixed_private_service_hosts

for container in "$agent" "$model" "$mcp"; do
	[[ $(docker inspect --format '{{.HostConfig.Runtime}}' "$container") == runsc ]] || stop_gate runtime.runsc runtime_is_not_runsc
	[[ $(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container") == true ]] || stop_gate runtime.rootfs rootfs_not_read_only
	[[ $(docker inspect --format '{{.Config.User}}' "$container") == 65532:65532 ]] || stop_gate runtime.user runtime_user_not_65532
	docker inspect --format '{{json .HostConfig.CapDrop}}' "$container" | grep -q 'ALL' || stop_gate runtime.capabilities capabilities_not_dropped
	docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$container" | grep -q 'no-new-privileges:true' || stop_gate runtime.privileges no_new_privileges_missing
done
runtime_observed=runsc
record runtime.policy passed runsc_closed_policy

agent_get() {
	local path=$1
	timeout 15 docker exec -i -u 65532:65532 "$agent" python3 - "$path" <<'PY'
import sys
import urllib.request

request = urllib.request.Request("http://127.0.0.1:8766" + sys.argv[1])
request.add_header("Authorization", "Bearer untrusted-outer-caller")
with urllib.request.urlopen(request, timeout=10) as response:
    body = response.read(1 << 20)
    if response.read(1):
        raise SystemExit("response too large")
    sys.stdout.buffer.write(body)
PY
}

agent_post() {
	local path=$1 body=$2
	[[ ${#body} -le 65536 ]] || return 1
	timeout 15 docker exec -i -u 65532:65532 "$agent" python3 - "$path" "$body" <<'PY'
import sys
import urllib.request

body = sys.argv[2].encode()
request = urllib.request.Request("http://127.0.0.1:8766" + sys.argv[1], data=body, method="POST")
request.add_header("Authorization", "Bearer untrusted-outer-caller")
request.add_header("Content-Type", "application/json")
with urllib.request.urlopen(request, timeout=10) as response:
    payload = response.read(1 << 20)
    if response.read(1):
        raise SystemExit("response too large")
    sys.stdout.buffer.write(payload)
PY
}

health=
for _ in $(seq 1 90); do
	docker inspect --format '{{.State.Running}}' "$agent" 2>/dev/null | grep -qx true || stop_gate agent.process agent_exited_before_ready
	if candidate=$(agent_get /health 2>/dev/null) && [[ -n $candidate ]]; then
		health=$candidate
		break
	fi
	sleep 1
done
[[ -n $health ]] || stop_gate agent.readiness hermes_api_not_ready
python3 -c 'import json,sys; p=json.load(sys.stdin); assert p.get("status")=="ok" and p.get("platform")=="hermes-agent"' \
	<<<"$health" || stop_gate agent.readiness invalid_health_contract
record agent.readiness passed "health_sha256:$(printf %s "$health" | sha256sum | awk '{print $1}')"

negotiation_one=$(agent_get /steward/v1/negotiation) || stop_gate adapter.negotiation negotiation_failed
authority_before=$(find "$state_root" -type f \( -path '*/config.yaml' -o -path '*/skills/steward.workspace-audit/*' \) -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
negotiation_two=$(agent_get /steward/v1/negotiation) || stop_gate adapter.negotiation negotiation_replay_failed
authority_after=$(find "$state_root" -type f \( -path '*/config.yaml' -o -path '*/skills/steward.workspace-audit/*' \) -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
[[ $negotiation_one == "$negotiation_two" && $authority_before == "$authority_after" ]] || stop_gate adapter.negotiation negotiation_mutated_authority_state
python3 -c 'import json,sys; p=json.load(sys.stdin); assert set(p)=={"adapter","adapter_contract","capabilities","native_protocols","schema_version","task_protocol","upstream_revision"}; assert p["schema_version"]=="steward.adapter-negotiation.v1" and p["adapter"]=="hermes-agent" and p["adapter_contract"]=="steward.hermes-agent.v1" and p["upstream_revision"]==sys.argv[1]; assert p["task_protocol"]=="hermes.runs.v1" and p["native_protocols"]==["http"]; assert p["capabilities"]==[{"fixture_id":"fixture_echo","id":"mcp"},{"fixture_id":"steward.workspace-audit","id":"skill"},{"fixture_id":"fixed-response","id":"task"}]' "$revision" <<<"$negotiation_one" || stop_gate adapter.negotiation invalid_negotiation_contract
record adapter.negotiation passed side_effect_free_exact_contract

timeout 15 docker exec -i -u 65532:65532 "$agent" python3 - <<'PY' || stop_gate service.boundary service_boundary_contract_failed
import http.client
import urllib.error
import urllib.request

try:
    urllib.request.urlopen("http://127.0.0.1:8766/v1/runs/run_00000000000000000000000000000000/events", timeout=10)
except urllib.error.HTTPError as exc:
    if exc.code != 404:
        raise
else:
    raise SystemExit("event stream escaped the service allowlist")

for headers, expected in (({}, 411), ({"Content-Length": "65537"}, 413)):
    connection = http.client.HTTPConnection("127.0.0.1", 8766, timeout=10)
    connection.putrequest("POST", "/v1/runs", skip_accept_encoding=True)
    connection.putheader("Authorization", "Bearer untrusted-outer-caller")
    for name, value in headers.items():
        connection.putheader(name, value)
    connection.endheaders()
    response = connection.getresponse()
    response.read()
    connection.close()
    if response.status != expected:
        raise SystemExit(f"unexpected service-boundary response: {response.status}, wanted {expected}")
PY
record service.boundary passed allowlist_and_body_limits_enforced

docker exec -i -u 65532:65532 "$agent" python3 - <<'PY' || stop_gate runtime.identity process_identity_drift
import pathlib
for status in pathlib.Path("/proc").glob("[0-9]*/status"):
    text = status.read_text(errors="replace")
    uid = next(line for line in text.splitlines() if line.startswith("Uid:" )).split()[1:]
    gid = next(line for line in text.splitlines() if line.startswith("Gid:" )).split()[1:]
    if any(value != "65532" for value in uid + gid):
        raise SystemExit(f"identity drift in {status.parent.name}")
PY
record runtime.identity passed complete_process_tree_65532

if docker exec -u 65532:65532 "$agent" sh -c 'touch /steward-root-write-probe' >/dev/null 2>&1; then
	stop_gate runtime.rootfs rootfs_write_succeeded
fi
docker exec -u 65532:65532 "$agent" sh -c 'printf ok > /opt/data/steward/state-write-probe' || stop_gate runtime.state state_write_failed
[[ $(cat "$state_root/steward/state-write-probe") == ok ]] || stop_gate runtime.state state_write_not_observed
record runtime.filesystem passed fixed_state_only

if docker exec -i -u 65532:65532 "$agent" python3 - <<'PY' >/dev/null 2>&1
import urllib.request
urllib.request.urlopen("https://pypi.org/simple/", timeout=3)
PY
then
	stop_gate runtime.network unexpected_public_network_access
fi
record runtime.network passed runtime_download_route_absent

expected_digest=$(printf %s steward-hermes-phase1 | sha256sum | awk '{print $1}')
workspace_manifest_digest=$(python3 -c 'import json,sys; p=json.load(open(sys.argv[1],encoding="utf-8")); assert p["fixture_id"]=="steward.workspace-audit.small.v1"; print(p["manifest_digest"])' \
	"$adapter_root/fixtures/skill/workspace-fixture-contract.json") || stop_gate fixture.workspace invalid_workspace_contract
record fixture.workspace passed actual_workspace_work_contract

run_native_task() {
	local task_name=$1 input=$2 expected=$3
	local request response run_ref terminal
	request=$(python3 - "$input" "$task_name" <<'PY'
import json
import sys
print(json.dumps({"input": sys.argv[1], "session_id": "steward-" + sys.argv[2]}, separators=(",", ":")))
PY
)
	response=$(agent_post /v1/runs "$request") || stop_gate "task.$task_name" task_submit_failed
	run_ref=$(python3 -c 'import json,sys; p=json.load(sys.stdin); print(p.get("run_id", ""))' <<<"$response")
	[[ $run_ref =~ ^run_[a-f0-9]{32}$ ]] || stop_gate "task.$task_name" invalid_upstream_run_id
	terminal=
	for _ in $(seq 1 "$run_timeout"); do
		terminal=$(agent_get "/v1/runs/$run_ref") || stop_gate "task.$task_name" task_status_failed
		status=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("status", ""))' <<<"$terminal")
		case $status in
		completed) break ;;
		failed|cancelled) stop_gate "task.$task_name" "task_$status" ;;
		esac
		sleep 1
	done
	[[ $status == completed ]] || stop_gate "task.$task_name" task_timeout
	python3 -c 'import json,sys; p=json.load(sys.stdin); out=p.get("output"); raise SystemExit(0 if isinstance(out,str) and sys.argv[1] in out else 1)' \
		"$expected" <<<"$terminal" || stop_gate "task.$task_name" expected_result_missing
	record "task.$task_name" passed "result_sha256:$(printf %s "$terminal" | sha256sum | awk '{print $1}')"
}

run_native_task basic STEWARD_TASK_FIXTURE "steward-task:$expected_digest"
run_native_task skill STEWARD_WORKSPACE_AUDIT "$workspace_manifest_digest"
run_native_task mcp STEWARD_MCP_FIXTURE steward-hermes-phase1
persisted_authority_before_restart=$(find "$state_root" -type f \( -path '*/config.yaml' -o -path '*/skills/steward.workspace-audit/*' \) -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')

docker rm -f "$agent" >/dev/null
docker run -d --name "$agent" --network-alias steward-agent "${closed_run[@]}" "${agent_hosts[@]}" \
	--mount "type=bind,src=$state_root,dst=/opt/data" \
	-e OPENAI_BASE_URL=http://steward-relay:8080/v1 -e OPENAI_API_KEY=steward-local \
	-e OPENAI_MODEL=steward-fixture-model "$image" >/dev/null || stop_gate restart.start agent_restart_failed
for _ in $(seq 1 90); do
	if agent_get /health >/dev/null 2>&1; then break; fi
	sleep 1
done
agent_get /health >/dev/null 2>&1 || stop_gate restart.readiness restarted_agent_not_ready
record restart.readiness passed restarted_native_api_ready
persisted_authority_after_restart=$(find "$state_root" -type f \( -path '*/config.yaml' -o -path '*/skills/steward.workspace-audit/*' \) -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
[[ $persisted_authority_before_restart == "$persisted_authority_after_restart" ]] || stop_gate restart.state persisted_authority_changed
run_native_task restart STEWARD_WORKSPACE_AUDIT "$workspace_manifest_digest"
record restart.state passed workspace_skill_reused

overall=passed
failure_code=none
record feasibility.complete passed all_phase1_gates
echo "Hermes feasibility passed; metadata-only evidence: $evidence_out"
