#!/usr/bin/env bash
# Build and exercise the pinned OpenClaw adapter on a disposable Docker+gVisor host.
set -euo pipefail

source_dir=${1:-}
[[ -n $source_dir ]] || { echo "usage: $0 /path/to/pinned-openclaw-checkout" >&2; exit 2; }
[[ ${STEWARD_ACCEPT_DISPOSABLE_HOST_RISK:-} == YES ]] || { echo "set STEWARD_ACCEPT_DISPOSABLE_HOST_RISK=YES only on a disposable host" >&2; exit 2; }
command -v docker >/dev/null
command -v git >/dev/null
command -v python3 >/dev/null
docker info --format '{{json .Runtimes}}' | grep -q '"runsc"' || { echo "openclaw-feasibility: runsc is not registered" >&2; exit 2; }

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
adapter="$root/adapters/openclaw"
revision=7197eef3ebeb5ac294da51ca073fff33277ed429
tree=3954741563d7a16ac9a6b40a8b7a527d9232df43
[[ $(git -C "$source_dir" rev-parse HEAD) == "$revision" ]] || { echo "openclaw-feasibility: upstream revision mismatch" >&2; exit 1; }
[[ $(git -C "$source_dir" rev-parse HEAD^{tree}) == "$tree" ]] || { echo "openclaw-feasibility: upstream tree mismatch" >&2; exit 1; }
git -C "$source_dir" diff --quiet && git -C "$source_dir" diff --cached --quiet || { echo "openclaw-feasibility: upstream checkout is dirty" >&2; exit 1; }
(cd "$source_dir" && sha256sum -c "$adapter/source-inputs.sha256") >/dev/null

run_id=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
work=$(mktemp -d)
network="steward-openclaw-$run_id"
upstream_image="steward-openclaw-upstream:$run_id"
adapter_image="steward-openclaw-adapter:$run_id"
agent="steward-openclaw-agent-$run_id"
model="steward-openclaw-model-$run_id"
mcp="steward-openclaw-mcp-$run_id"
cleanup() {
  docker rm -f "$agent" "$model" "$mcp" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker image rm "$adapter_image" "$upstream_image" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

docker build --pull=false --build-arg "GIT_COMMIT=$revision" --build-arg OPENCLAW_BUILD_TIMESTAMP=2026-07-12T00:00:00Z -t "$upstream_image" "$source_dir" >/dev/null
docker build --pull=false -f "$adapter/Dockerfile" --build-arg "OPENCLAW_UPSTREAM_IMAGE=$upstream_image" --build-arg "OPENCLAW_SOURCE_REVISION=$revision" -t "$adapter_image" "$root" >/dev/null
[[ $(docker image inspect --format '{{.Config.User}}' "$adapter_image") == 65532:65532 ]] || { echo "openclaw-feasibility: adapter image user drift" >&2; exit 1; }
[[ $(docker image inspect --format '{{json .Config.Volumes}}' "$adapter_image") == null ]] || { echo "openclaw-feasibility: adapter image declares a volume" >&2; exit 1; }

docker network create --internal "$network" >/dev/null
install -d -m 0700 "$work/state" "$work/state/workspace" "$work/auth"
chown -R 65532:65532 "$work/state" "$work/auth"
printf '%s\n' "gateway-$run_id-gateway-$run_id" >"$work/auth/gateway-token"
chmod 0400 "$work/auth/gateway-token"
chown 65532:65532 "$work/auth/gateway-token"

common=(--runtime runsc --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --memory 512m --cpus 1 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m --network "$network")
docker run -d --name "$model" --network-alias steward-model "${common[@]}" --entrypoint node "$adapter_image" /opt/steward/fixture-model.mjs >/dev/null
docker run -d --name "$mcp" --network-alias steward-mcp "${common[@]}" --entrypoint node "$adapter_image" /opt/steward/fixture-echo-mcp.mjs >/dev/null
docker run -d --name "$agent" "${common[@]}" \
  --mount "type=bind,src=$work/state,dst=/home/node/.openclaw" \
  --mount "type=bind,src=$work/auth,dst=/home/node/.config/openclaw,readonly" \
  -e OPENAI_BASE_URL=http://steward-model:18080/v1 -e OPENAI_API_KEY=steward-local -e OPENAI_MODEL=steward-fixture-model \
  "$adapter_image" >/dev/null

for _ in $(seq 1 90); do
  docker exec --user 65532:65532 "$agent" node -e 'fetch("http://127.0.0.1:18789/readyz").then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))' >/dev/null 2>&1 && break
  docker inspect --format '{{.State.Running}}' "$agent" | grep -qx true || { echo "openclaw-feasibility: agent exited during startup" >&2; exit 1; }
  sleep 1
done

docker inspect "$agent" >"$work/inspect.json"
python3 - "$work/inspect.json" <<'PY'
import json, sys
item = json.load(open(sys.argv[1], encoding="utf-8"))[0]
host = item["HostConfig"]
assert item["State"]["Running"]
assert host["Runtime"] == "runsc"
assert host["ReadonlyRootfs"] is True
assert host["CapDrop"] == ["ALL"]
assert "no-new-privileges" in host["SecurityOpt"]
mounts = {(m["Destination"], m["RW"]) for m in item["Mounts"]}
assert mounts == {("/home/node/.openclaw", True), ("/home/node/.config/openclaw", False)}
PY
[[ $(docker exec --user 65532:65532 "$agent" id -u):$(docker exec --user 65532:65532 "$agent" id -g) == 65532:65532 ]] || { echo "openclaw-feasibility: process identity drift" >&2; exit 1; }

docker exec --user 65532:65532 "$agent" node /opt/steward/probe.mjs "$run_id" >"$work/probe-before.json"
docker restart "$agent" >/dev/null
for _ in $(seq 1 90); do
  docker exec --user 65532:65532 "$agent" node -e 'fetch("http://127.0.0.1:18789/readyz").then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))' >/dev/null 2>&1 && break
  sleep 1
done
restart_nonce=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
docker exec --user 65532:65532 "$agent" node /opt/steward/probe.mjs "$restart_nonce" >"$work/probe-after.json"

python3 - "$work/inspect.json" "$work/probe-before.json" "$work/probe-after.json" "$revision" "$tree" "$adapter_image" <<'PY'
import hashlib, json, sys
inspect = json.load(open(sys.argv[1], encoding="utf-8"))[0]
before = json.load(open(sys.argv[2], encoding="utf-8"))
after = json.load(open(sys.argv[3], encoding="utf-8"))
print(json.dumps({
  "schema_version": "steward.openclaw-feasibility.v1",
  "status": "pass",
  "upstream_revision": sys.argv[4],
  "upstream_tree": sys.argv[5],
  "image_id": inspect["Image"],
  "runtime": inspect["HostConfig"]["Runtime"],
  "uid_gid": "65532:65532",
  "read_only_root": True,
  "capabilities_dropped": True,
  "no_new_privileges": True,
  "runtime_network": "internal_fixture_only",
  "probe_before": before,
  "probe_after_restart": after,
  "content_excluded": True
}, sort_keys=True, separators=(",", ":")))
PY
