#!/usr/bin/env bash
# Real Linux-host proof for Steward's separate Docker/gVisor Executor process.
set -euo pipefail

: "${V1_IMAGE:?set V1_IMAGE to an already-local image pinned by @sha256}"
case "$V1_IMAGE" in
  *@sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo 'V1_IMAGE must be an immutable @sha256 image reference' >&2; exit 2 ;;
esac

if ! docker info --format '{{json .Runtimes}}' | grep -q '"runsc"'; then
  echo 'Docker runtime runsc is required; refusing an ordinary-Docker proof' >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
token="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
printf '%s\n' "$token" >"$work/token"
chmod 600 "$work/token"
refs=()

cleanup() {
  for ref in "${refs[@]}"; do
    curl -sS -X DELETE "http://127.0.0.1:8090/v1/workloads/$ref" \
      -H "Authorization: Bearer $token" >/dev/null || true
  done
  if [[ -n "${executor_pid:-}" ]]; then kill "$executor_pid" 2>/dev/null || true; fi
  if [[ -n "${build_container:-}" ]]; then docker rm -f "$build_container" >/dev/null 2>&1 || true; fi
  if [[ -n "${build_image:-}" ]]; then docker image rm "$build_image" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

if [[ -n "${EXECUTOR_BIN:-}" ]]; then
  cp "$EXECUTOR_BIN" "$work/steward-executor"
elif command -v go >/dev/null 2>&1; then
  (cd "$root" && go build -o "$work/steward-executor" ./cmd/steward-executor)
else
  build_image="steward-executor-acceptance-build:$$"
  docker build -q -f "$root/deploy/steward-executor.Dockerfile" -t "$build_image" "$root" >/dev/null
  build_container="$(docker create "$build_image")"
  docker cp "$build_container:/usr/local/bin/steward-executor" "$work/steward-executor"
  docker rm "$build_container" >/dev/null
fi
"$work/steward-executor" -token-file "$work/token" \
  -max-workloads 2 -max-workloads-per-tenant 1 >"$work/executor.log" 2>&1 &
executor_pid=$!
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8090/v1/healthz >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS http://127.0.0.1:8090/v1/healthz >/dev/null

payload() {
  printf '{"instance_id":"%s","tenant_id":"%s","profile_id":"acceptance","image":"%s","command":["sleep","300"],"resources":{"memory_bytes":67108864,"cpu_millis":100,"pids":32},"egress":{}}' "$2" "$1" "$V1_IMAGE"
}

provision() {
  curl -fsS -X POST http://127.0.0.1:8090/v1/workloads \
    -H 'Content-Type: application/json' -H "Authorization: Bearer $token" \
    --data "$(payload "$1" "$2")"
}

runtime_ref() {
  sed -n 's/.*"runtime_ref":"\([^"]*\)".*/\1/p'
}

expect_status() {
  local want="$1"; shift
  local got
  got="$(curl -sS -o /dev/null -w '%{http_code}' "$@")"
  test "$got" = "$want" || {
    echo "expected HTTP $want, got $got" >&2
    return 1
  }
}

first_ref="$(provision tenant-a shared-id | runtime_ref)"
refs+=("$first_ref")
# Exact replay is idempotent; mutable/unknown configuration is not admitted.
expect_status 200 -X POST http://127.0.0.1:8090/v1/workloads \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $token" \
  --data "$(payload tenant-a shared-id)"
expect_status 400 -X POST http://127.0.0.1:8090/v1/workloads \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $token" \
  --data '{"privileged":true}'
# A second workload for one tenant is rejected before Docker creation.
expect_status 503 -X POST http://127.0.0.1:8090/v1/workloads \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $token" \
  --data "$(payload tenant-a tenant-capacity-denied)"

second_ref="$(provision tenant-b shared-id | runtime_ref)"
refs+=("$second_ref")
test "$first_ref" != "$second_ref"
# The global host budget is now full.
expect_status 503 -X POST http://127.0.0.1:8090/v1/workloads \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $token" \
  --data "$(payload tenant-c host-capacity-denied)"

for ref in "$first_ref" "$second_ref"; do
  test "$(docker inspect --format '{{.HostConfig.Runtime}}' "$ref")" = runsc
  test "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$ref")" = none
  test "$(docker inspect --format '{{.HostConfig.IpcMode}}' "$ref")" = private
  test "$(docker inspect --format '{{.HostConfig.CgroupnsMode}}' "$ref")" = private
  test -z "$(docker inspect --format '{{.HostConfig.PidMode}}' "$ref")"
  test -z "$(docker inspect --format '{{.HostConfig.UTSMode}}' "$ref")"
  test "$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$ref")" = no
  test "$(docker inspect --format '{{.HostConfig.AutoRemove}}' "$ref")" = false
  test "$(docker inspect --format '{{.HostConfig.OomKillDisable}}' "$ref")" = false
  test "$(docker inspect --format '{{.HostConfig.OomScoreAdj}}' "$ref")" = 0
  test "$(docker inspect --format '{{.HostConfig.ShmSize}}' "$ref")" = 67108864
  test "$(docker inspect --format '{{.Config.User}}' "$ref")" = 65532:65532
  test "$(docker inspect --format '{{.Config.WorkingDir}}' "$ref")" = /workspace
  test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$ref")" = true
  docker inspect --format '{{json .HostConfig.CapDrop}}' "$ref" | grep -q '"ALL"'
  docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$ref" | grep -q 'no-new-privileges:true'
  docker inspect --format '{{json .HostConfig.Tmpfs}}' "$ref" | grep -q '"/workspace"'
  docker inspect --format '{{json .HostConfig.Tmpfs}}' "$ref" | grep -q '"/tmp"'
  curl -fsS -X POST "http://127.0.0.1:8090/v1/workloads/$ref/start" \
    -H "Authorization: Bearer $token" >/dev/null
  curl -fsS -X POST "http://127.0.0.1:8090/v1/workloads/$ref/stop" \
    -H "Authorization: Bearer $token" >/dev/null
done

echo 'Executor acceptance passed: tenant-scoped workloads ran only under gVisor.'
