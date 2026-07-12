---
title: Operate an Executor workload
description: Provision, start, inspect, read logs from, stop, and destroy a digest-pinned OCI workload through Steward Executor's authenticated host-local API.
section: How-to guide
---

# Operate an Executor workload

Use this procedure to test a preloaded Open Container Initiative (OCI) image in
Steward's fixed sandbox. It calls the host-local Executor API at
`127.0.0.1:8090`. Packaged nodes bind this API to loopback. Never expose it on a
routable address.

This guide uses the unsigned compatibility endpoint. It is available only when
signed admission is disabled. Production workflows should use
[signed admission]({{ '/guides/signed-admission/' | relative_url }}) and the
[policy-bound image importer]({{ '/reference/offline-tools/' | relative_url }}).
The commands require `curl`, `jq`, and Docker's command-line client.

## 1. Prepare a host-local token

The packaged installer creates an owner-only, non-empty token before Executor
starts. Read that existing token; do not replace it on a running or enrolled node:

```console
sudo test -s /etc/steward/executor-token
TOKEN=$(sudo cat /etc/steward/executor-token)
```

The token authorizes workload changes across the node; it is not a tenant end-user
credential. Executor reads it at startup, so changing the file does not rotate a
running process. Keep the listener on loopback.

## 2. Preload and pin the image

Executor never pulls images. Import one through an approved registry or offline
transfer process, then obtain its immutable repository digest:

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

Repeating provision for the exact same admitted workload returns the existing
result. A conflicting definition or observed sandbox drift returns HTTP 409;
Executor will not adopt it.

## 4. Start and inspect

```console
curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8090/v1/workloads/$RUNTIME_REF/start"

curl --fail-with-body -sS \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8090/v1/workloads/$RUNTIME_REF"
```

The container may exit immediately after a compatibility command such as `--help`.
This is expected. Inspect its bounded combined output:

```console
curl --fail-with-body -sS \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8090/v1/workloads/$RUNTIME_REF/logs" | jq -r .logs
```

Executor requests the most recent 1000 lines from Docker and returns them only if
the encoded response is at most 1 MiB. A larger response returns HTTP 502 with
`docker_error` instead of consuming unbounded host memory. Reduce agent log volume
or inspect operator-managed Docker log files through a separate privileged process.

## 5. Stop and destroy

```console
curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8090/v1/workloads/$RUNTIME_REF/stop"

curl --fail-with-body -sS -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8090/v1/workloads/$RUNTIME_REF"
```

Without signed admission, destroy is idempotent and returns HTTP 204 when the
managed workload is already absent. With signed admission, an authorized retry
returns 204 only when Executor retains the workload's destroyed tombstone. An
unknown signed runtime reference returns 404; an existing workload outside the
caller's signed authority returns 403.

## Fixed sandbox

The request cannot select a network, environment variables, mounts, devices,
privileged mode, runtime, or container user. The contract has no such fields. See
the exact API and response schemas in the
[Executor OpenAPI reference]({{ '/reference/api/' | relative_url }}).
