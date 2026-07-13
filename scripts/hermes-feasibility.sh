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
overall=failed
failure_code=unhandled_failure
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

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
	echo "hermes-feasibility: stop gate $check failed ($code)" >&2
	exit 1
}

write_evidence() {
	local exit_status=$1
	if [[ $exit_status -eq 0 ]]; then
		overall=passed
		failure_code=none
	fi
	mkdir -p "$(dirname "$evidence_out")"
	python3 - "$checks" "$evidence_out" "$overall" "$failure_code" "$started_at" \
		"$revision" "$source_archive_digest" "$image_config_digest" <<'PY'
import json
import os
import pathlib
import sys

checks_path, output, overall, failure, started, revision, source_digest, image_digest = sys.argv[1:]
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
    "runtime": "runsc",
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
	return "$exit_status"
}

cleanup() {
	docker rm -f "$agent" "$model" "$mcp" >/dev/null 2>&1 || true
	docker network rm "$network" >/dev/null 2>&1 || true
	rm -rf "$work"
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

if [[ -n $source_dir ]]; then
	[[ -d $source_dir/.git ]] || stop_gate source.checkout source_checkout_missing
	actual_revision=$(git -C "$source_dir" rev-parse HEAD 2>/dev/null || true)
	[[ $actual_revision == "$revision" ]] || stop_gate source.revision source_revision_mismatch
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
elif [[ -z $image ]]; then
	stop_gate source.selection source_or_image_required
else
	[[ $image =~ @sha256:[a-f0-9]{64}$ || $image =~ ^sha256:[a-f0-9]{64}$ ]] || stop_gate image.reference prebuilt_image_not_digest_pinned
	record source.inputs passed prebuilt_digest_image
fi

docker image inspect "$image" >/dev/null 2>&1 || stop_gate image.present image_not_present
image_config_digest=$(docker image inspect --format '{{.Id}}' "$image")
[[ $image_config_digest =~ ^sha256:[a-f0-9]{64}$ ]] || stop_gate image.identity invalid_image_config_digest
image_user=$(docker image inspect --format '{{.Config.User}}' "$image")
[[ $image_user == 65532:65532 ]] || stop_gate image.user image_user_not_65532
volumes=$(docker image inspect --format '{{json .Config.Volumes}}' "$image")
[[ $volumes == null || $volumes == '{}' ]] || stop_gate image.volumes image_declares_volume
record image.contract passed nonroot_no_declared_volumes

mkdir -p "$state_root"
chmod 0700 "$state_root"
chown 65532:65532 "$state_root"
docker network create --internal --label io.hardrails.feasibility=true "$network" >/dev/null
record network.internal passed no_external_route

closed_run=(--runtime runsc --network "$network" --read-only --cap-drop ALL
	--security-opt "no-new-privileges:true" --pids-limit 128 --memory 1073741824
	--memory-swap 1073741824 --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=67108864"
	--user 65532:65532)

docker run -d --name "$model" --network-alias steward-model "${closed_run[@]}" \
	--entrypoint python3 "$image" /opt/steward/fixture_model.py >/dev/null || stop_gate fixture.model model_start_failed
docker run -d --name "$mcp" --network-alias steward-mcp "${closed_run[@]}" \
	--entrypoint python3 "$image" /opt/steward/fixture_mcp.py >/dev/null || stop_gate fixture.mcp mcp_start_failed
docker run -d --name "$agent" --network-alias steward-agent "${closed_run[@]}" \
	--mount "type=bind,src=$state_root,dst=/opt/data" \
	-e OPENAI_BASE_URL=http://steward-model:8080/v1 -e OPENAI_API_KEY=steward-local \
	-e OPENAI_MODEL=steward-fixture-model "$image" >/dev/null || stop_gate agent.start agent_start_failed

for container in "$agent" "$model" "$mcp"; do
	[[ $(docker inspect --format '{{.HostConfig.Runtime}}' "$container") == runsc ]] || stop_gate runtime.runsc runtime_is_not_runsc
	[[ $(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container") == true ]] || stop_gate runtime.rootfs rootfs_not_read_only
	[[ $(docker inspect --format '{{.Config.User}}' "$container") == 65532:65532 ]] || stop_gate runtime.user runtime_user_not_65532
	docker inspect --format '{{json .HostConfig.CapDrop}}' "$container" | grep -q 'ALL' || stop_gate runtime.capabilities capabilities_not_dropped
	docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$container" | grep -q 'no-new-privileges:true' || stop_gate runtime.privileges no_new_privileges_missing
done
record runtime.policy passed runsc_closed_policy

agent_get() {
	local path=$1
	timeout 15 docker exec -u 65532:65532 "$agent" python3 - "$path" <<'PY'
import sys
import urllib.request

request = urllib.request.Request("http://127.0.0.1:" + ("8766" if sys.argv[1].startswith("/steward/") else "8642") + sys.argv[1])
request.add_header("Authorization", "Bearer steward-feasibility")
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
request = urllib.request.Request("http://127.0.0.1:8642" + sys.argv[1], data=body, method="POST")
request.add_header("Authorization", "Bearer steward-feasibility")
request.add_header("Content-Type", "application/json")
with urllib.request.urlopen(request, timeout=10) as response:
    payload = response.read(1 << 20)
    if response.read(1):
        raise SystemExit("response too large")
    sys.stdout.buffer.write(payload)
PY
}

for _ in $(seq 1 90); do
	docker inspect --format '{{.State.Running}}' "$agent" 2>/dev/null | grep -qx true || stop_gate agent.process agent_exited_before_ready
	if agent_get /health >"$work/health.json" 2>/dev/null; then break; fi
	sleep 1
done
agent_get /health >"$work/health.json" 2>/dev/null || stop_gate agent.readiness hermes_api_not_ready
python3 -m json.tool "$work/health.json" >/dev/null || stop_gate agent.readiness invalid_health_json
record agent.readiness passed native_api_ready

negotiation_one=$(agent_get /steward/v1/negotiation) || stop_gate adapter.negotiation negotiation_failed
authority_before=$(find "$state_root" -type f \( -path '*/config.yaml' -o -path '*/skills/fixture-sha256/*' \) -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
negotiation_two=$(agent_get /steward/v1/negotiation) || stop_gate adapter.negotiation negotiation_replay_failed
authority_after=$(find "$state_root" -type f \( -path '*/config.yaml' -o -path '*/skills/fixture-sha256/*' \) -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
[[ $negotiation_one == "$negotiation_two" && $authority_before == "$authority_after" ]] || stop_gate adapter.negotiation negotiation_mutated_authority_state
python3 -c 'import json,sys; p=json.load(sys.stdin); assert p["upstream_revision"]==sys.argv[1]' "$revision" <<<"$negotiation_one" || stop_gate adapter.negotiation invalid_negotiation_contract
record adapter.negotiation passed side_effect_free_exact_contract

docker exec -u 65532:65532 "$agent" python3 - <<'PY' || stop_gate runtime.identity process_identity_drift
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

if docker exec -u 65532:65532 "$agent" python3 - <<'PY' >/dev/null 2>&1
import urllib.request
urllib.request.urlopen("https://pypi.org/simple/", timeout=3)
PY
then
	stop_gate runtime.network unexpected_public_network_access
fi
record runtime.network passed runtime_download_route_absent

expected_digest=$(printf %s steward-hermes-phase1 | sha256sum | awk '{print $1}')

run_native_task() {
	local task_name=$1 input=$2 expected=$3
	local request response run_ref terminal events
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
	events=$(agent_get "/v1/runs/$run_ref/events") || stop_gate "events.$task_name" event_stream_failed
	grep -q 'run.completed' <<<"$events" || stop_gate "events.$task_name" terminal_event_missing
	record "task.$task_name" passed "result_sha256:$(printf %s "$terminal" | sha256sum | awk '{print $1}')"
	record "events.$task_name" passed "events_sha256:$(printf %s "$events" | sha256sum | awk '{print $1}')"
}

run_native_task basic STEWARD_TASK_FIXTURE "steward-task:$expected_digest"
run_native_task skill STEWARD_SKILL_FIXTURE "$expected_digest"
run_native_task mcp STEWARD_MCP_FIXTURE steward-hermes-phase1

docker rm -f "$agent" >/dev/null
docker run -d --name "$agent" --network-alias steward-agent "${closed_run[@]}" \
	--mount "type=bind,src=$state_root,dst=/opt/data" \
	-e OPENAI_BASE_URL=http://steward-model:8080/v1 -e OPENAI_API_KEY=steward-local \
	-e OPENAI_MODEL=steward-fixture-model "$image" >/dev/null || stop_gate restart.start agent_restart_failed
for _ in $(seq 1 90); do
	if agent_get /health >/dev/null 2>&1; then break; fi
	sleep 1
done
agent_get /health >/dev/null 2>&1 || stop_gate restart.readiness restarted_agent_not_ready
[[ -f $state_root/skills/fixture-sha256/manifest.json && -f $state_root/config.yaml ]] || stop_gate restart.state persisted_state_missing
run_native_task restart STEWARD_TASK_FIXTURE "steward-task:$expected_digest"
record restart.state passed exact_state_reused

overall=passed
failure_code=none
record feasibility.complete passed all_phase1_gates
echo "Hermes feasibility passed; metadata-only evidence: $evidence_out"
