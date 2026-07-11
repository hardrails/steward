# Steward Executor

`steward-executor` is Steward's separate Docker/gVisor process for untrusted
tenant agents. It ships from the same public repository and release as `steward`.
The separation is a privilege boundary, not a product boundary:

- `steward` owns trusted lifecycle tracking and optional operator-authored OS
  process supervision. It never receives the Docker socket.
- `steward-executor` is the only Steward process that receives the Docker socket.
  It admits a deliberately narrow OCI workload and forces the `runsc` runtime.
- A control plane owns tenants, users, approvals, desired state, rollout policy,
  and profile resolution. Executor contains none of those systems and has no
  Railyard dependency.
- Inference remains outside both processes behind an operator-managed
  OpenAI-compatible gateway.

## Threat model and fixed policy

Images and every workload field are untrusted. Executor independently rejects
mutable image tags, zero or over-ceiling resource limits, networking, environment
injection, and unknown JSON fields. The API has no representation for privileged
mode, host mounts, devices, Docker socket access, host networking, added
capabilities, or writable-root requests.

Every admitted container is created with:

- Docker runtime `runsc` (gVisor), verified available before Executor starts;
- network mode `none`;
- read-only root filesystem;
- UID/GID `65532:65532`;
- all Linux capabilities dropped;
- `no-new-privileges:true`;
- mandatory cgroup memory, CPU, and PID limits.

The image stays read-only, while Executor supplies fixed, non-configurable 64 MiB
tmpfs mounts at `/workspace` and `/tmp`, forces `HOME=/workspace` and
`TMPDIR=/tmp`, and starts in `/workspace`. This gives Hermes, OpenClaw, and other
agents bounded ephemeral scratch space without exposing a host path or allowing a
tenant to choose a mount. Durable workspace and secret grants remain separate,
explicit future contracts; V1 images must contain their immutable approved content.

Executor labels each container with a SHA-256 fingerprint of the complete admitted
workload. An idempotent provision replay succeeds only when both that fingerprint
and the fixed hardening settings still match Docker's observed state. Drift is a
409 conflict, never silently adopted.

Host-owned admission ceilings default to 512 MiB, 1000 millicores, 128 PIDs, 32
workloads per host, and 4 workloads per tenant. They are startup flags, not request
fields. Existing Executor-managed Docker inventory is counted after a restart, so
restarting the process cannot reset capacity.

## Host-local API mode

The authoritative contract is
[`openapi/steward-executor.v1.yaml`](../openapi/steward-executor.v1.yaml). The
listener defaults to `127.0.0.1:8090` and every operation except `/v1/healthz`
requires the token in `-token-file`. That file must be regular, non-empty, and
owner-only (`0600` or stricter).

```console
steward-executor \
  -token-file /etc/steward/executor-token \
  -docker-socket /var/run/docker.sock
```

The listener has bounded read, write, header, and idle timeouts. Request bodies and
log responses are capped at 1 MiB. All errors, including standard 404/405 and a
recovered panic, use `{"error":"...","message":"..."}`.

## Outbound Executor uplink

For nodes behind NAT or an inbound firewall, `-uplink-url` enables a generic,
outbound-only command channel. `-disable-inbound-listener` leaves the local HTTP
handler in-process as the single policy implementation but binds no socket; the
uplink dispatcher invokes that same authenticated handler, so direct and outbound
modes cannot drift into two admission engines.

The credential is a versioned owner-only JSON file:

```json
{
  "version": 1,
  "tenant_id": "tenant-a",
  "node_id": "executor-1",
  "credential": "opaque-control-plane-bearer"
}
```

Executor posts `{}` to `/executor-uplink/poll` and reports each terminal outcome to
`/executor-uplink/report`. A command has this additive JSON shape:

```json
{
  "command_id": "opaque-command-id",
  "tenant_id": "tenant-a",
  "node_id": "executor-1",
  "runtime_ref": "uplink:10:executor-1:agent-1",
  "kind": "provision",
  "payload": {
    "profile_id": "hermes-v1",
    "image": "registry.local/hermes@sha256:<64 lowercase hex>",
    "command": ["hermes", "serve"],
    "resources": {"memory_bytes": 536870912, "cpu_millis": 1000, "pids": 128},
    "egress": {}
  },
  "claim_generation": 1,
  "instance_generation": 1,
  "command_sequence": 1
}
```

The polling endpoint must authenticate the credential against a node enrolled with
runtime class `executor-uplink`. It supplies `tenant_id` from that authenticated
identity; it is not copied from a queued workload payload. Executor checks tenant,
node, runtime reference, claim generation, instance generation, and causal command
sequence before mutation. For provision it discards any payload identity and derives
`tenant_id` from the enrolled credential expectation and `instance_id` from the
length-prefixed runtime reference.

Before first start, initialize a newly enrolled node's fence exactly once:

```console
steward-executor -initialize-uplink-state \
  -uplink-state-file /var/lib/steward/executor-uplink-state.json
```

Normal startup requires that file to exist. It never treats a missing file as an
empty first run: loss or a changed path is a fail-closed startup error, because
resetting the fence could let a redelivered old command mutate a newer workload.
Initialization uses exclusive creation and refuses to overwrite an existing file.

The state file records the highest applied `(instance_generation,
command_sequence)` plus its reported status per instance. It is atomically replaced,
fsynced, owner-only, and capped at 1 MiB. A stale or repeated command becomes a
successful no-op with the durable prior status. This prevents an old provision or
start from resurrecting a destroyed or replaced workload after a process restart.
A completed destroy also persists and reports `result.absent=true`; although the
shared lifecycle status vocabulary represents absence as `stopped`, the command's
terminal result never describes the removed container as merely restartable.

Poll and report bodies are capped at 1 MiB; a poll has at most 128 commands. Failed
round trips use bounded exponential backoff capped at five minutes. The credential
file is re-read on every poll for secret rotation, but a replacement that changes
tenant or node identity is refused.

Remote plaintext HTTP is refused by default. Private CA and mTLS deployments use
`-uplink-tls-ca-file`, `-uplink-tls-client-cert`, and
`-uplink-tls-client-key`; the key must be owner-only. The
`-uplink-tls-skip-verify` and `-uplink-allow-insecure-http` options are explicit,
loudly visible break-glass acknowledgements, never defaults.

## Deployment invariant

Run `steward` and `steward-executor` as different service units and Unix users.
Mount `/var/run/docker.sock` only into the Executor unit. A control plane may run
elsewhere and an inference gateway may run elsewhere; neither needs filesystem or
Docker access on the node. Multiple tenants share a host only through Executor's
tenant-labeled, gVisor-isolated containers and per-tenant admission ceiling.

`scripts/executor-acceptance.sh` exercises this boundary on a real Linux host. It
uses `EXECUTOR_BIN` when supplied, builds with a local Go toolchain when available,
or falls back to the checked-in Dockerfile. A deployment target therefore needs
Docker and `runsc`, not a resident Go compiler.
