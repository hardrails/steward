#!/usr/bin/env bash
# Destructive Linux/amd64 Docker and gVisor qualification for one built bundle.
set -euo pipefail
umask 077
unset CDPATH NODE_OPTIONS
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly expected_revision=2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4
readonly expected_model=steward-openclaw-fixture
readonly expected_audit_digest=8a88036085cd27e3e0a85ab10f3fbfed492633fa76fd18a85bb478747c4d56d5
readonly default_run_timeout=180

bundle=
output=$root/dist/acceptance/openclaw/feasibility.json
run_timeout=$default_run_timeout
keep_failed=false

usage() {
	cat <<'USAGE'
Usage:
  STEWARD_ACCEPT_DISPOSABLE_HOST_RISK=YES \
    scripts/openclaw-feasibility.sh --bundle DIRECTORY [options]

Loads a bundle created by build-openclaw-adapter.sh and performs a destructive,
metadata-only qualification on a disposable Linux/amd64 Docker host with gVisor.

Options:
  --bundle DIRECTORY       Bundle containing image.tar and attestation.json
  --output FILE            New evidence file (default: dist/acceptance/openclaw/feasibility.json)
  --run-timeout SEC        Per-agent-run deadline (30..600; default 180)
  --keep-failed            Preserve the local diagnostic directory after failure
  -h, --help               Show this help

The gate starts only temporary containers, one internal Docker network, and one
temporary volume. It removes those resources on success and failure. The output
contains hashes and pass/fail metadata, never prompts, responses, or tool output.
USAGE
}

die() {
	echo "openclaw-feasibility: $*" >&2
	exit 1
}

inspect_image_archive() {
	local archive=$1
	if command -v stewardctl >/dev/null 2>&1; then
		stewardctl image inspect -archive "$archive"
		return
	fi
	local go_binary=
	if command -v go >/dev/null 2>&1; then
		go_binary=$(command -v go)
	elif [[ -x /usr/local/go/bin/go ]]; then
		go_binary=/usr/local/go/bin/go
	fi
	[[ -n $go_binary ]] || die "stewardctl or Go 1.24+ is required to verify the OCI archive"
	(
		cd "$root"
		env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off "$go_binary" run ./cmd/stewardctl image inspect -archive "$archive"
	)
}

usage_error() {
	echo "openclaw-feasibility: $*" >&2
	usage >&2
	exit 2
}

while (( $# > 0 )); do
	case $1 in
	--bundle)
		(( $# >= 2 )) || usage_error "--bundle requires a value"
		bundle=$2
		shift 2
		;;
	--output)
		(( $# >= 2 )) || usage_error "--output requires a value"
		output=$2
		shift 2
		;;
	--run-timeout)
		(( $# >= 2 )) || usage_error "--run-timeout requires a value"
		run_timeout=$2
		shift 2
		;;
	--keep-failed)
		keep_failed=true
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*) usage_error "unknown option: $1" ;;
	esac
done

[[ ${STEWARD_ACCEPT_DISPOSABLE_HOST_RISK:-} == YES ]] || usage_error "set STEWARD_ACCEPT_DISPOSABLE_HOST_RISK=YES only on a disposable host"
[[ -n $bundle ]] || usage_error "--bundle is required"
[[ $run_timeout =~ ^[1-9][0-9]{1,2}$ ]] || usage_error "--run-timeout must be 30..600"
(( run_timeout >= 30 && run_timeout <= 600 )) || usage_error "--run-timeout must be 30..600"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || die "the qualified runtime platform is Linux on amd64"
for command in docker python3 sha256sum timeout; do
	command -v "$command" >/dev/null 2>&1 || die "$command is required"
done
docker info --format '{{json .Runtimes}}' | grep -q '"runsc"' || die "Docker runtime runsc is required"

bundle=$(cd "$bundle" && pwd -P)
[[ -f $bundle/image.tar && -f $bundle/attestation.json ]] || die "bundle must contain image.tar and attestation.json"
output_parent=$(dirname "$output")
mkdir -p -m 0700 "$output_parent"
python3 -I - "$bundle" "$output_parent" "$output" <<'PY' || die "bundle or evidence destination is unsafe"
import os
import pathlib
import stat
import sys

for value in sys.argv[1:3]:
    path = pathlib.Path(value)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
        raise SystemExit(1)
try:
    os.lstat(sys.argv[3])
except FileNotFoundError:
    pass
else:
    raise SystemExit(1)
PY

work=$(mktemp -d /tmp/steward-openclaw-feasibility.XXXXXX)
checks=$work/checks.tsv
: >"$checks"
run_id=${STEWARD_ACCEPTANCE_RUN_ID:-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')}
[[ $run_id =~ ^[a-f0-9]{16}$ ]] || die "STEWARD_ACCEPTANCE_RUN_ID is invalid"
prefix=steward-openclaw-$run_id
network=$prefix-net
volume=$prefix-state
model_container=$prefix-model
agent_container=$prefix-agent
overall=failed
failure_code=unhandled_failure
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
harness_sha256=$(sha256sum "$root/scripts/openclaw-feasibility.sh" | awk '{print $1}')
image_tag=unavailable
image_manifest_digest=unavailable
image_config_digest=unavailable
runtime_image_id=unavailable
archive_sha256=unavailable
adapter_commit=unavailable
adapter_tree=unavailable
result_sha256=unavailable

required_checks=(
	bundle.contract image.load image.contract network.internal fixture.model runtime.policy
	agent.readiness adapter.negotiation service.boundary runtime.identity runtime.filesystem
	runtime.network task.skill restart.readiness restart.skill tamper.fail_closed feasibility.complete
)

record() {
	local check=$1 status=$2 detail=$3
	[[ $check =~ ^[a-z0-9_.-]+$ && $status =~ ^(passed|failed)$ && $detail =~ ^[A-Za-z0-9_.:@/+,-]+$ ]] || die "internal evidence field is invalid"
	printf '%s\t%s\t%s\n' "$check" "$status" "$detail" >>"$checks"
}

stop_gate() {
	local check=$1 code=$2
	failure_code=$code
	record "$check" failed "$code"
	echo "openclaw-feasibility: stop gate $check failed ($code)" >&2
	exit 1
}

write_report() {
	local exit_status=$1
	if (( exit_status == 0 )); then
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
		if (( exit_status == 0 )); then
			record evidence.coverage passed required_check_set_complete
			overall=passed
			failure_code=none
		fi
	fi
	python3 -I - "$checks" "$output" "$overall" "$failure_code" "$started_at" \
		"$expected_revision" "$archive_sha256" "$adapter_commit" "$adapter_tree" \
		"$image_tag" "$image_manifest_digest" "$image_config_digest" "$runtime_image_id" \
		"$result_sha256" "$harness_sha256" <<'PY'
import json
import os
import pathlib
import sys

(
    checks_path, output, overall, failure, started_at, revision, archive_sha,
    adapter_commit, adapter_tree, image_tag, image_manifest, image_config,
    runtime_image_id, result_sha, harness_sha,
) = sys.argv[1:]
checks = []
path = pathlib.Path(checks_path)
if path.stat().st_size > 64 * 1024:
    raise SystemExit("evidence checks exceed 64 KiB")
for line in path.read_text(encoding="utf-8").splitlines():
    fields = line.split("\t")
    if len(fields) == 3:
        checks.append({"detail": fields[2], "id": fields[0], "status": fields[1]})
payload = {
    "adapter_git_tree": None if adapter_tree == "unavailable" else adapter_tree,
    "adapter_steward_commit": None if adapter_commit == "unavailable" else adapter_commit,
    "agent": "openclaw",
    "archive_sha256": None if archive_sha == "unavailable" else archive_sha,
    "checks": checks,
    "contains_agent_content": False,
    "failure_code": failure,
    "harness_sha256": harness_sha,
    "image_config_digest": None if image_config == "unavailable" else image_config,
    "image_manifest_digest": None if image_manifest == "unavailable" else image_manifest,
    "image_tag": None if image_tag == "unavailable" else image_tag,
    "overall": overall,
    "platform": "linux/amd64",
    "result_sha256": None if result_sha == "unavailable" else result_sha,
    "runtime": "runsc",
    "runtime_image_id": None if runtime_image_id == "unavailable" else runtime_image_id,
    "schema_version": "steward.agent-feasibility.v1",
    "started_at": started_at,
    "upstream_revision": revision,
}
destination = pathlib.Path(output)
temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
with temporary.open("x", encoding="utf-8") as stream:
    json.dump(payload, stream, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
os.chmod(temporary, 0o600)
os.rename(temporary, destination)
directory = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
	return "$exit_status"
}

cleanup() {
	for container in "$agent_container" "$model_container"; do
		if [[ $overall != passed && $keep_failed == true ]]; then
			docker logs "$container" >"$work/$container.log" 2>&1 || true
		fi
		docker rm -f "$container" >/dev/null 2>&1 || true
	done
	docker network rm "$network" >/dev/null 2>&1 || true
	docker volume rm "$volume" >/dev/null 2>&1 || true
	[[ $image_tag == unavailable ]] || docker image rm "$image_tag" >/dev/null 2>&1 || true
	if [[ $overall == passed || $keep_failed != true ]]; then
		rm -rf "$work"
	else
		echo "openclaw-feasibility: preserved diagnostic directory $work" >&2
	fi
}

finalize() {
	local status=$?
	trap - EXIT
	write_report "$status" || status=$?
	cleanup
	exit "$status"
}
trap finalize EXIT

attestation_values=$(python3 -I - "$bundle/attestation.json" "$bundle/image.tar" "$expected_revision" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

attestation = pathlib.Path(sys.argv[1])
archive = pathlib.Path(sys.argv[2])
for path in (attestation, archive):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise SystemExit(1)
raw = attestation.read_bytes()
if len(raw) > 64 * 1024:
    raise SystemExit(1)
payload = json.loads(raw)
canonical = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode() + b"\n"
if raw != canonical or payload.get("schema_version") != "steward.openclaw-adapter-build-attestation.v1" or payload.get("contains_agent_content") is not False:
    raise SystemExit(1)
source = payload.get("source", {})
adapter = payload.get("adapter", {})
image = payload.get("image", {})
archive_record = payload.get("archive", {})
recipe = payload.get("build_recipe", {})
if (
    source.get("revision") != sys.argv[3]
    or source.get("repository") != "https://github.com/openclaw/openclaw.git"
    or source.get("release") != "v2026.7.1"
    or adapter.get("contract") != "steward.openclaw.v1"
    or recipe.get("id") != "steward.openclaw-adapter.docker-build.v1"
    or recipe.get("network_scope") != "pinned-base-pull;docker-build-network-none"
    or recipe.get("platform") != "linux/amd64"
    or archive_record.get("file") != "image.tar"
    or archive_record.get("bytes") != archive.stat().st_size
    or image.get("user") != "65532:65532"
):
    raise SystemExit(1)
digest = hashlib.sha256()
with archive.open("rb") as stream:
    for chunk in iter(lambda: stream.read(1 << 20), b""):
        digest.update(chunk)
if digest.hexdigest() != archive_record.get("sha256"):
    raise SystemExit(1)
digest_re = re.compile(r"sha256:[a-f0-9]{64}")
commit_re = re.compile(r"[a-f0-9]{40,64}")
manifest = image.get("manifest_digest", "")
config = image.get("config_digest", "")
runtime = image.get("runtime_image_id", "")
if (
    any(digest_re.fullmatch(value) is None for value in (manifest, config, runtime))
    or runtime not in {manifest, config}
    or commit_re.fullmatch(adapter.get("steward_commit", "")) is None
    or commit_re.fullmatch(adapter.get("git_tree", "")) is None
):
    raise SystemExit(1)
print(archive_record["sha256"])
print(image["tag"])
print(manifest)
print(config)
print(runtime)
print(adapter["steward_commit"])
print(adapter["git_tree"])
PY
) || stop_gate bundle.contract invalid_bundle_contract
mapfile -t attestation_fields <<<"$attestation_values"
(( ${#attestation_fields[@]} == 7 )) || stop_gate bundle.contract incomplete_bundle_contract
archive_sha256=${attestation_fields[0]}
image_tag=${attestation_fields[1]}
image_manifest_digest=${attestation_fields[2]}
image_config_digest=${attestation_fields[3]}
runtime_image_id=${attestation_fields[4]}
adapter_commit=${attestation_fields[5]}
adapter_tree=${attestation_fields[6]}
archive_image_json=$(inspect_image_archive "$bundle/image.tar") || stop_gate bundle.contract archive_inspection_failed
python3 -I - "$archive_image_json" "$image_tag" "$image_manifest_digest" "$image_config_digest" <<'PY' \
	|| stop_gate bundle.contract archive_identity_mismatch
import json
import sys

payload = json.loads(sys.argv[1])
assert payload.get("manifest_digest") == sys.argv[3]
assert payload.get("config_digest") == sys.argv[4]
assert payload.get("repo_tags") == [sys.argv[2]]
assert payload.get("platform") == {"architecture": "amd64", "os": "linux"}
PY
record bundle.contract passed exact_atomic_bundle

timeout 900 docker load --input "$bundle/image.tar" >"$work/docker-load.log" 2>&1 || stop_gate image.load docker_load_failed
actual_runtime_id=$(docker image inspect --format '{{.Id}}' "$image_tag" 2>/dev/null || true)
[[ $actual_runtime_id == "$runtime_image_id" ]] || stop_gate image.load runtime_image_id_mismatch
record image.load passed exact_bound_image_loaded
image_user=$(docker image inspect --format '{{.Config.User}}' "$image_tag")
image_platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image_tag")
image_volumes=$(docker image inspect --format '{{json .Config.Volumes}}' "$image_tag")
[[ $image_user == 65532:65532 && $image_platform == linux/amd64 ]] || stop_gate image.contract image_runtime_contract_invalid
[[ $image_volumes == null || $image_volumes == '{}' ]] || stop_gate image.contract unmanaged_volume_declared
record image.contract passed linux_amd64_nonroot_no_volume

docker network create --internal --label io.hardrails.feasibility=true "$network" >/dev/null || stop_gate network.internal network_create_failed
docker volume create --label io.hardrails.feasibility=true "$volume" >/dev/null || stop_gate network.internal volume_create_failed
record network.internal passed no_external_route

closed_model=(--runtime runsc --network "$network" --read-only --cap-drop ALL
	--security-opt no-new-privileges:true --user 65532:65532 --pids-limit 128
	--memory 536870912 --memory-swap 536870912 --cpus 1 --no-healthcheck
	--tmpfs /tmp:rw,noexec,nosuid,nodev,size=67108864)
closed_agent=(--runtime runsc --network "$network" --read-only --cap-drop ALL
	--security-opt no-new-privileges:true --user 65532:65532 --pids-limit 256
	--memory 2147483648 --memory-swap 2147483648 --cpus 1 --no-healthcheck
	--tmpfs /tmp:rw,noexec,nosuid,nodev,size=67108864)

docker run -d --name "$model_container" "${closed_model[@]}" --network-alias steward-relay \
	--entrypoint node "$image_tag" /opt/steward/fixture_model.mjs >/dev/null || stop_gate fixture.model model_start_failed
model_ready=false
for _ in $(seq 1 30); do
	if docker exec -u 65532:65532 "$model_container" node -e 'fetch("http://127.0.0.1:8080/health").then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))' >/dev/null 2>&1; then
		model_ready=true
		break
	fi
	docker inspect --format '{{.State.Running}}' "$model_container" | grep -qx true || stop_gate fixture.model model_exited_before_ready
	sleep 1
done
[[ $model_ready == true ]] || stop_gate fixture.model model_not_ready
model_ip=$(docker inspect --format "{{(index .NetworkSettings.Networks \"$network\").IPAddress}}" "$model_container")
[[ $model_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || stop_gate fixture.model model_address_invalid
record fixture.model passed exact_chat_completion_fixture

start_agent() {
	docker run -d --name "$agent_container" "${closed_agent[@]}" --add-host "steward-relay:$model_ip" \
		--mount "type=volume,src=$volume,dst=/home/node/.openclaw" \
		-e OPENAI_BASE_URL=http://steward-relay:8080/v1 \
		-e OPENAI_API_KEY=steward-local -e OPENAI_MODEL=$expected_model \
		"$image_tag" serve >/dev/null
}

agent_http() {
	local method=$1 path=$2 body=${3-}
	timeout 20 docker exec -i -u 65532:65532 "$agent_container" node - "$method" "$path" "$body" <<'NODE'
const [method, path, body] = process.argv.slice(2);
const options = { method, signal: AbortSignal.timeout(15000), headers: {} };
if (method === "POST") {
  options.headers["content-type"] = "application/json";
  options.body = body;
}
const response = await fetch(`http://127.0.0.1:18789${path}`, options);
const text = await response.text();
let parsed;
try { parsed = JSON.parse(text); } catch { parsed = null; }
process.stdout.write(JSON.stringify({body: parsed, status: response.status}));
NODE
}

wait_ready() {
	local ready=false response status
	for _ in $(seq 1 90); do
		docker inspect --format '{{.State.Running}}' "$agent_container" 2>/dev/null | grep -qx true || return 1
		if response=$(agent_http GET /health 2>/dev/null); then
			status=$(python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("status"))' <<<"$response")
			if [[ $status == 200 ]]; then ready=true; break; fi
		fi
		sleep 1
	done
	[[ $ready == true ]]
}

start_agent || stop_gate agent.start agent_start_failed
wait_ready || stop_gate agent.readiness agent_not_ready
record agent.readiness passed bounded_http_api_ready

for container in "$model_container" "$agent_container"; do
	[[ $(docker inspect --format '{{.HostConfig.Runtime}}' "$container") == runsc ]] || stop_gate runtime.policy runtime_not_runsc
	[[ $(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container") == true ]] || stop_gate runtime.policy rootfs_not_read_only
	[[ $(docker inspect --format '{{.Config.User}}' "$container") == 65532:65532 ]] || stop_gate runtime.policy user_not_65532
	docker inspect --format '{{json .HostConfig.CapDrop}}' "$container" | grep -q ALL || stop_gate runtime.policy capabilities_not_dropped
	docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$container" | grep -q no-new-privileges:true || stop_gate runtime.policy no_new_privileges_missing
done
[[ $(docker inspect --format '{{.HostConfig.Memory}}' "$agent_container") == 2147483648 ]] || stop_gate runtime.policy memory_limit_missing
[[ $(docker inspect --format '{{.HostConfig.PidsLimit}}' "$agent_container") == 256 ]] || stop_gate runtime.policy pid_limit_missing
record runtime.policy passed runsc_readonly_bounded_nonroot

negotiation=$(agent_http GET /steward/v1/negotiation) || stop_gate adapter.negotiation request_failed
python3 -I - "$expected_revision" "$expected_model" "$negotiation" <<'PY' || stop_gate adapter.negotiation invalid_contract
import json
import sys
p = json.loads(sys.argv[3])
b = p.get("body", {})
assert p.get("status") == 200
assert b.get("schema_version") == "steward.adapter-negotiation.v1"
assert b.get("adapter") == "openclaw" and b.get("adapter_contract") == "steward.openclaw.v1"
assert b.get("upstream_revision") == sys.argv[1] and b.get("model_alias") == sys.argv[2]
assert b.get("native_protocols") == ["http"] and b.get("task_protocol") == "openclaw.runs.v1"
PY
record adapter.negotiation passed exact_model_and_revision

boundary=$(agent_http GET /not-allowed) || stop_gate service.boundary unknown_route_request_failed
[[ $(python3 -I -c 'import json,sys; print(json.load(sys.stdin)["status"])' <<<"$boundary") == 404 ]] || stop_gate service.boundary unknown_route_not_rejected
timeout 20 docker exec -i -u 65532:65532 "$agent_container" node - <<'NODE' || stop_gate service.boundary oversized_body_not_rejected
const body = JSON.stringify({message: "x".repeat(65536)});
const response = await fetch("http://127.0.0.1:18789/v1/runs", {method:"POST", headers:{"content-type":"application/json"}, body});
if (response.status !== 413) process.exit(1);
NODE
record service.boundary passed allowlist_and_body_limit

docker exec -i -u 65532:65532 "$agent_container" node - <<'NODE' || stop_gate runtime.identity process_identity_drift
const fs = require("fs");
for (const entry of fs.readdirSync("/proc")) {
  if (!/^\d+$/.test(entry)) continue;
  let status;
  try { status = fs.readFileSync(`/proc/${entry}/status`, "utf8"); } catch { continue; }
  for (const key of ["Uid", "Gid"]) {
    const line = status.split("\n").find((candidate) => candidate.startsWith(`${key}:`));
    if (!line || line.split(/\s+/).slice(1).some((value) => value && value !== "65532")) process.exit(1);
  }
}
NODE
record runtime.identity passed complete_process_tree_65532

if docker exec -u 65532:65532 "$agent_container" node -e 'require("fs").writeFileSync("/rootfs-probe","x")' >/dev/null 2>&1; then
	stop_gate runtime.filesystem rootfs_write_succeeded
fi
docker exec -u 65532:65532 "$agent_container" node -e 'require("fs").writeFileSync("/home/node/.openclaw/workspace/state-probe","ok",{mode:0o600,flag:"wx"})' || stop_gate runtime.filesystem state_write_failed
record runtime.filesystem passed fixed_state_volume_only

if docker exec -u 65532:65532 "$agent_container" node -e 'fetch("https://example.com",{signal:AbortSignal.timeout(3000)}).then(()=>process.exit(0)).catch(()=>process.exit(1))' >/dev/null 2>&1; then
	stop_gate runtime.network public_network_reachable
fi
record runtime.network passed internal_network_only

submit=$(agent_http POST /v1/runs '{"message":"Run the Steward workspace audit.","session_id":"qualification"}') || stop_gate task.skill submit_failed
run_ref=$(python3 -I -c 'import json,sys; p=json.load(sys.stdin); print(p.get("body",{}).get("run_id",""))' <<<"$submit")
[[ $run_ref =~ ^run_[a-f0-9]{32}$ ]] || stop_gate task.skill invalid_run_id
second=$(agent_http POST /v1/runs '{"message":"This must not start.","session_id":"capacity"}') || stop_gate service.boundary capacity_request_failed
[[ $(python3 -I -c 'import json,sys; print(json.load(sys.stdin)["status"])' <<<"$second") == 429 ]] || stop_gate service.boundary concurrent_run_not_rejected

wait_run() {
	local reference=$1 terminal= response state
	for _ in $(seq 1 "$run_timeout"); do
		response=$(agent_http GET "/v1/runs/$reference") || return 1
		state=$(python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("body",{}).get("state",""))' <<<"$response")
		case $state in
		succeeded) printf '%s' "$response"; return 0 ;;
		failed)
			if [[ $keep_failed == true ]]; then
				printf '%s\n' "$response" >"$work/$reference-terminal.json"
				chmod 0600 "$work/$reference-terminal.json"
			fi
			return 1
			;;
		esac
		sleep 1
	done
	return 1
}

terminal=$(wait_run "$run_ref") || stop_gate task.skill run_failed_or_timed_out
result_sha256=$(
	python3 -I - "$expected_model" "$terminal" <<'PY'
import hashlib
import json
import sys
p = json.loads(sys.argv[2])
b = p.get("body", {})
r = b.get("result", {})
assert p.get("status") == 200 and b.get("state") == "succeeded"
assert r.get("payloads") == [{"media_url": None, "text": "STEWARD_OPENCLAW_WORKSPACE_AUDIT_OK"}]
assert r.get("meta") == {"duration_ms": r["meta"]["duration_ms"], "model": sys.argv[1], "provider": "steward", "tool_calls": 1, "tool_failures": 0, "tools": ["exec"]}
assert isinstance(r["meta"]["duration_ms"], int) and r["meta"]["duration_ms"] >= 0
canonical = json.dumps(r, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
digest = hashlib.sha256(canonical).hexdigest()
assert b.get("result_sha256") == digest
print(digest)
PY
) || stop_gate task.skill sanitized_result_invalid
audit=$(docker exec -u 65532:65532 "$agent_container" node -e 'process.stdout.write(require("fs").readFileSync("/home/node/.openclaw/workspace/qualification/result.json"))') || stop_gate task.skill audit_result_missing
python3 -I - "$expected_audit_digest" "$audit" <<'PY' || stop_gate task.skill audit_result_invalid
import json
import sys
p = json.loads(sys.argv[2])
assert p == {
    "digest": sys.argv[1],
    "file_count": 2,
    "files": p["files"],
    "schema_version": "steward.workspace-audit.result.v1",
    "total_bytes": 133,
}
assert [row["path"] for row in p["files"]] == ["alpha.txt", "nested.json"]
PY
record task.skill passed "result_sha256:$result_sha256"

docker rm -f "$agent_container" >/dev/null
start_agent || stop_gate restart.start restart_failed
wait_ready || stop_gate restart.readiness restarted_agent_not_ready
record restart.readiness passed persisted_state_reopened
restart_submit=$(agent_http POST /v1/runs '{"message":"Run the Steward workspace audit.","session_id":"qualification-restart"}') || stop_gate restart.skill submit_failed
restart_ref=$(python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("body",{}).get("run_id",""))' <<<"$restart_submit")
[[ $restart_ref =~ ^run_[a-f0-9]{32}$ ]] || stop_gate restart.skill invalid_run_id
wait_run "$restart_ref" >/dev/null || stop_gate restart.skill run_failed_or_timed_out
record restart.skill passed exact_skill_reused

docker rm -f "$agent_container" >/dev/null
docker run --rm --runtime runsc --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
	--user 65532:65532 --mount "type=volume,src=$volume,dst=/home/node/.openclaw" --entrypoint node "$image_tag" \
	-e 'const fs=require("fs");const p="/home/node/.openclaw/workspace/skills/steward-workspace-audit/SKILL.md";fs.chmodSync(p,0o600);fs.appendFileSync(p,"\ndrift\n")' \
	>/dev/null || stop_gate tamper.fail_closed tamper_setup_failed
start_agent || stop_gate tamper.fail_closed tampered_container_create_failed
tamper_rejected=false
for _ in $(seq 1 20); do
	if [[ $(docker inspect --format '{{.State.Running}}' "$agent_container") == false ]]; then
		tamper_rejected=true
		break
	fi
	sleep 1
done
[[ $tamper_rejected == true ]] || stop_gate tamper.fail_closed tampered_skill_started
docker logs "$agent_container" 2>&1 | grep -q 'persisted skill drifted' || stop_gate tamper.fail_closed wrong_tamper_failure
record tamper.fail_closed passed persisted_skill_drift_rejected

record feasibility.complete passed all_openclaw_gates
overall=passed
failure_code=none
echo "OpenClaw feasibility passed; metadata-only evidence: $output"
