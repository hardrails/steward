---
title: Operate an Executor workload
description: Provision, start, inspect, read logs from, stop, and destroy a digest-pinned OCI workload through Steward Executor's authenticated host-local API.
section: How-to guide
---

# Operate an Executor workload

Use this procedure to test a preloaded OCI image against Steward's fixed
sandbox. It targets the host-local Executor API at `127.0.0.1:8090`. Packaged
nodes bind it to loopback only; never expose that listener on a routable address.

## 1. Prepare a host-local token

Executor requires an owner-only, non-empty token file:

```console
sudo install -o steward-executor -g steward-executor -m 0600 /dev/null /etc/steward/executor-token
openssl rand -hex 32 | sudo tee /etc/steward/executor-token >/dev/null
sudo chown steward-executor:steward-executor /etc/steward/executor-token
TOKEN=$(sudo cat /etc/steward/executor-token)
```

Do not expose this listener beyond loopback. The token authorizes workload mutation
on the node; it is not a tenant end-user credential.

## 2. Preload and pin the image

Executor never pulls an image. Import it through your approved registry or offline
image-transfer workflow, then obtain its immutable repository digest:

```console
docker pull registry.example/agent:approved-version
IMAGE=$(docker image inspect --format '{% raw %}{{index .RepoDigests 0}}{% endraw %}' \
  registry.example/agent:approved-version)
printf '%s\n' "$IMAGE"
```

The value must end in `@sha256:` followed by 64 lowercase hexadecimal characters.
A local image ID such as `sha256:...` is not a repository digest and is rejected.

## 3. Provision a stopped workload

```console
curl --fail-with-body -sS \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{
    \"instance_id\": \"agent-001\",
    \"tenant_id\": \"tenant-a\",
    \"profile_id\": \"compatibility-test-v1\",
    \"image\": \"$IMAGE\",
    \"command\": [\"/path/in/image\", \"--help\"],
    \"resources\": {
      \"memory_bytes\": 536870912,
      \"cpu_millis\": 1000,
      \"pids\": 128
    },
    \"egress\": {}
  }" \
  http://127.0.0.1:8090/v1/workloads | tee workload.json

RUNTIME_REF=$(jq -r .runtime_ref workload.json)
```

Provision is idempotent for the exact same admitted workload. A conflicting
definition or any observed sandbox drift returns HTTP 409 rather than adopting it.

## 4. Start and inspect

```console
curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8090/v1/workloads/$RUNTIME_REF/start"

curl --fail-with-body -sS \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8090/v1/workloads/$RUNTIME_REF"
```

The container may exit immediately for a compatibility command such as `--help`.
That is expected; inspect its bounded combined output:

```console
curl --fail-with-body -sS \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8090/v1/workloads/$RUNTIME_REF/logs" | jq -r .logs
```

Executor returns at most the most recent 1 MiB of logs.

## 5. Stop and destroy

```console
curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8090/v1/workloads/$RUNTIME_REF/stop"

curl --fail-with-body -sS -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8090/v1/workloads/$RUNTIME_REF"
```

Destroy is idempotent and returns HTTP 204 when the managed workload is absent.

## Fixed sandbox

The request cannot ask for network, environment variables, mounts, devices,
privileged mode, a different runtime, or a different container user. Those fields
are absent from the contract. The exact API and response schemas are in the
[Executor OpenAPI reference]({{ '/reference/api/' | relative_url }}).
