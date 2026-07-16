---
title: Steward Executor
description: Detailed behavior, policy, host-local API, outbound uplink, capacity accounting, and deployment invariants for the Docker and gVisor Executor.
section: Component reference
---

# Steward Executor

`steward-executor` runs untrusted tenant agents through Docker and gVisor. It
ships in the same public repository and release as `steward`, but runs as a
separate process because it has different authority:

- `steward` tracks trusted lifecycle state and can optionally supervise
  operator-authored OS processes. It never receives the Docker socket.
- `steward-executor` is the only long-running Steward service with Docker-group
  membership. It admits a fixed-schema, deny-by-default Open Container Initiative
  (OCI) workload and forces the gVisor `runsc` runtime. gVisor is an
  application-kernel sandbox that
  reduces direct exposure to the host kernel. The root-run, one-shot
  `stewardctl image import` command is a separate bounded Docker client.
- Steward Control can own tenant records, enrollment, inventory, and signed-command
  delivery. Higher-level operator systems own users, approvals, desired state,
  rollout policy, and profile resolution. Executor implements none of those
  systems and does not depend on a particular controller.
- `steward-gateway` and a per-instance `steward-relay` broker approved inference,
  one declared service, and named signed HTTP(S) routes. The agent receives no raw
  host or Internet route.

`steward-executor -check-config` performs the same token, Docker socket, `runsc`,
host policy, TLS, credential, durable-fence, and uplink checks as normal startup.
When signed admission is enabled, the journal, evidence chain, and admission
fence must already exist; validation reads and verifies them but never creates or
appends to them. It then prints `executor configuration valid` and exits without
binding the local API or polling a control plane. Disconnected-node preflight
runs this command as the real `steward-executor` service user before upgrade or
rollback.
An unresolved prepared journal entry makes `-check-config` fail because normal
mutations are not ready, even though normal startup can serve the narrower
degraded containment mode.

## Threat model and fixed container policy

Executor treats images and all workload fields as untrusted. It rejects mutable
image tags, missing or over-limit resources, network access not authorized by a
signed grant, environment injection, and unknown JSON fields. Its API has no fields
for privileged mode, host mounts, devices, Docker socket access, host networking,
added capabilities, or a writable root filesystem.

Every admitted agent container uses:

- Docker runtime `runsc`, verified before Executor starts;
- `network=none`, or one internal per-instance Docker network when a signed
  inference, service, connector, or egress grant requires the trusted relay;
- a read-only root filesystem;
- UID/GID `65532:65532`;
- all Linux capabilities dropped;
- `no-new-privileges:true`;
- private interprocess communication (IPC) and control-group (cgroup) namespaces,
  plus Docker's private process ID (PID) and hostname/domain-name (UTS) modes;
  inspection rejects host, peer-container, and shareable namespace modes;
- mandatory cgroup memory, CPU, and PID limits;
- swap capped at the memory limit and Docker's bounded `local` log driver;
- Docker restart and automatic-removal policies disabled, with the out-of-memory
  (OOM) killer enabled;
- no custom cgroup parent, supplemental group, legacy link, inherited volume,
  device-cgroup rule, sysctl, or storage option;
- no image-declared writable volume, extra mount, device, published port, added
  capability, or extra network; and
- Docker's isolated internal bridge gateway mode for each network-enabled
  network, which lets the agent reach its fixed relay but not host services through
  the bridge gateway.

Capability networks also point DNS at an unavailable loopback resolver. Gateway,
not the container, resolves authorized egress destinations.

Isolated bridge gateway mode requires Docker Engine 28 or newer. Preflight checks
that requirement before enabling inference, service, connector, or egress. An agent
with no network-enabled inference, service, connector, or egress grant remains on
`network=none` and does not require this Docker feature.

Executor adds fixed, non-configurable 64 MiB tmpfs mounts at `/workspace` and
`/tmp`, sets `HOME=/workspace` and `TMPDIR=/tmp`, and starts in `/workspace`. This
provides bounded ephemeral scratch space without a host path or tenant-selected
mount. A signed state grant can replace `/workspace` with one Steward-owned Docker
volume at the profile's fixed state path. Docker's portable local volume driver
provides no hard byte or inode quota, so Executor rejects state by default. The
explicit `-allow-unquotaed-state-on-dedicated-host` compatibility flag enables a
volume without enforced byte or inode quotas. The flag requires complete signed
admission, is suitable only for a dedicated single-tenant host, and is rejected
unless the verified site policy contains exactly one tenant. Raw secret and
arbitrary file injection remain unavailable; the image must contain its approved
content.

Each agent container has a SHA-256 fingerprint of its complete admitted workload.
An idempotent provision replay succeeds only when the fingerprint and every fixed
hardening setting still match Docker's observed state. Drift returns 409 and is
never silently adopted.

The trusted per-instance relay uses `runc` because it mounts one host-owned,
per-grant Unix-socket directory. It receives the same closed namespace, lifecycle,
resource, host-attachment, mount, port, DNS, restart, and logging checks. Its only
deliberate differences are the runtime, fixed network membership and addresses
after Docker allocation, and that one
Executor-derived Gateway directory when a positive capability requires it.

Host-owned defaults cap each workload at 512 MiB, 1000 millicores, and 128 PIDs,
with 32 workloads per host and 4 per tenant. Aggregate defaults reserve at most
8 GiB, 8000 millicores, and 2048 PIDs for the host, and 2 GiB, 2000 millicores,
and 512 PIDs for one tenant. These are startup flags, not request fields. Executor
reconstructs reservations from every managed workload container, including stopped
containers, and adds the relay's fixed 64 MiB, 100 millicores, and 32 PIDs for each
workload with inference, service, connector, or egress. Restarting Executor cannot
reset those totals.

These reservations do not measure disk bytes, inodes, I/O bandwidth, or CPU time
already consumed. Size the host with room for Docker, gVisor, Gateway, the operating
system, and burst behavior; lower the configured ceilings when that headroom is not
available.

## Host-local API mode

The authoritative contract is
[`openapi/steward-executor.v1.yaml`](https://github.com/hardrails/steward/blob/main/openapi/steward-executor.v1.yaml).
The listener defaults to `127.0.0.1:8090`. Every operation except `/v1/healthz`
requires the bearer token from `-token-file`. The token file must be regular,
non-empty, and owner-only (`0600` or stricter).

```console
steward-executor \
  -token-file /etc/steward/executor-token \
  -docker-socket /var/run/docker.sock
```

The listener sets read, write, header, and idle timeouts. Request bodies and log
responses are capped at 1 MiB. Every error—including standard 404/405 responses
and recovered panics—uses `{"error":"...","message":"..."}`.

`GET /v1/readiness` is bearer-protected and separate from public process
liveness. It returns 200 only when the latest bounded reconciliation has verified
every present signed runtime. Missing or structurally changed objects and ambiguous
mutations return 503, with at most 64 bounded failure entries. A 503 does not
terminate Executor. The listener and outbound uplink remain available for
inspection and authenticated fail-closed containment.

Readiness covers present signed runtimes, not unused optional components. When no
present runtime needs Gateway, the scan does not probe Gateway health; a 200
response therefore does not promise that a later inference, service, connector, or
egress admission will succeed.

## Signed admission and receipts

Complete `-admission-*` trust configuration enables `POST /v1/admissions`.
Executor verifies a publisher-signed capsule through site-root-signed policy,
binds intent to the tenant, node, instance, lineage, and generation, intersects all
resource ceilings, and rejects policy or instance rollback.

Before changing Docker, Executor fsyncs (flushes to durable storage) a fixed-format
operation journal and a signed pre-effect receipt. After it creates and inspects
the workload, it appends a signed commit receipt, advances durable high-water
state, and marks the journal committed. A high-water state is a generation fence:
older authority cannot cross it. Executor refuses startup when the receipt key
changes or the chain is corrupt. A valid journal with an unresolved prepared
operation instead starts in degraded mode: readiness remains 503 and operations
that could create, start, destroy, or purge state remain blocked.

`stewardctl evidence verify` checks either a copied binary chain or a Steward
newline-delimited JSON (NDJSON) export offline. An optional externally retained
sequence and chain hash must match the exact final head; they are not lower bounds.
This detects a copy that is rolled back or unexpectedly advanced relative to the
checkpoint. `stewardctl evidence export` first verifies the chain, then emits
stable NDJSON signed-frame records and a final head for an auditor or evidence
store.

Signed admission selects the exact capsule-bound local config digest, never a tag.
`stewardctl image import` authenticates the capsule and site policy, scans a bounded
single-image Docker/OCI tar or gzip archive without extracting it, verifies every
descriptor and blob plus strict manifest/config/platform identity, and loads a
sanitized snapshot through Docker. It then inspects the exact config ID, platform,
and absence of declared volumes before Executor can admit the image.

The signed repository name is an authorization input, not proof of where the bytes
came from. The operator must authenticate build or promotion provenance separately.

The archive reader bounds compressed and uncompressed bytes, entries, metadata,
and layers. It accepts only regular files at safe paths and rejects duplicate
paths, links, devices, embedded or remote descriptors, unexpected entries, and
non-zero or excessive trailing data.

For an inference, connector, or egress grant, Gateway calculates a deterministic,
non-secret digest of the effective model alias, upstream and credential-file
identity, credential presence, routes, exact connector operations, destinations,
allowed IP ranges in Classless Inter-Domain Routing (CIDR) notation, concurrency,
call, byte, and lifetime limits. Gateway persists that digest and a
private credential-content binding with the retained grant. Executor persists the
public digest in its admission fence and commit receipt and returns it as
`route_policy_digest`.
Gateway refuses a semantic route change while a retained grant uses that route;
restart, start, and reconciliation also refuse a mismatch.

Inference authorization is limited to the signed `model_alias`. Every model-bearing
request must contain exactly one top-level string `model` with that value. Gateway
rejects a missing, malformed, duplicate, or different model before contacting the
upstream. `GET /v1/models` is synthesized from the same alias, so broader upstream
credential access does not expand tenant authority.

Signed mode disables legacy `POST /v1/workloads` creation. Authenticated start,
stop, destroy, and purge operations are journaled and receipted while Executor is
ready. Destroy records a
generation tombstone—a durable marker that prevents older commands from reviving
the removed instance. Direct tenant selection remains disabled unless an operator
enables `-admission-allow-host-admin-intent` as an explicit host-administrator
break-glass path.

A signed `start` proves the exact inactive network, relay, and Gateway state before
its first host mutation, then proves the exact active state before success. Drift on
a stopped runtime is rejected before mutation. If an idempotent `start` finds drift
on an already-running runtime, Executor deactivates or stops the exact objects it can
identify, marks readiness degraded, and returns HTTP 503. A failure during the
transition uses the same monotonic-containment rule: recovery may only narrow
authority. The journal remains pending when Executor cannot prove that the agent,
relay, and grant are all inactive.

A state grant uses one Steward-owned volume for a persistent workload history. It
is rejected unless the dedicated-host-only compatibility flag for a volume without
enforced byte or inode quotas is enabled. Only one live instance can hold the
writable lease for a `(tenant_id, lineage_id)` pair. Inference, service, connector,
and egress grants require the configured Gateway and hardened relay; partial
configuration fails closed. See
[positive-capability setup]({{ '/guides/positive-capabilities/' | relative_url }}),
[authenticated connector operations]({{ '/guides/connectors/' | relative_url }}),
[signed egress]({{ '/guides/egress/' | relative_url }}),
[the signed-admission guide]({{ '/guides/signed-admission/' | relative_url }}), and
[image and evidence tools]({{ '/reference/offline-tools/' | relative_url }}).

## Startup and periodic reconciliation

Reconciliation compares durable signed records with actual Docker and Gateway
objects. Before accepting normal mutations, Executor scans every present signed
fence in a stable, bounded order and verifies the exact container, config ID, fingerprint, state
volume, isolated network, relay, Gateway grant, and persisted route-policy digest.

Executor may repair only lifecycle or control drift, such as a stopped relay or a
Gateway restart that retained an inactive grant. It never recreates or adopts a
missing or structurally changed object. It first plans the complete scan. If any
record is ambiguous, that pass may deactivate grants and stop exactly identified
agents and relays, but it cannot start a relay, register a grant, or activate a
grant elsewhere on the host. Each actual repair is journaled and receipted; a clean
scan writes nothing. If the result of a mutation is ambiguous, the journal remains
pending and readiness stays degraded.

The scan repeats every 30 seconds. If current site policy no longer matches a
present admission, reconciliation deactivates Gateway first, then stops the agent
and relay. When startup or a later scan is degraded, admission, start, destroy, and
state purge return 503. An authenticated `stop` remains available as a narrower
containment path. It derives the grant and relay identities from the retained
signed fence, deactivates the grant, stops only an exactly identified managed agent
and relay, and then reinspects each boundary. It does not decide whether a pending
journal operation committed or compensated, and it never recreates, adopts, or
removes a drifted object. If Gateway is unavailable or an identity cannot be
proved, the request returns 503 after preserving any local stops it could verify.
Readiness returns to 200 automatically after a later complete reconciliation.

## Outbound Executor uplink

`-uplink-url` enables a generic outbound-only command channel for nodes behind
network address translation (NAT) or an inbound firewall.
`-disable-inbound-listener` binds no local socket, but
leaves the HTTP handler in-process. The uplink dispatcher calls that same
authenticated handler, so direct and outbound modes share one admission engine.

The preferred multi-tenant credential is node-scoped transport identity. It has no
tenant authority by itself:

```json
{
  "version": 2,
  "scope": "node",
  "node_id": "executor-1",
  "credential": "opaque-control-plane-bearer"
}
```

Executor accepts node scope only when:

- signed admission is fully configured;
- the credential `node_id` equals `-admission-node-id`;
- site-root-verified policy contains at least one site cleanup command key;
- the uplink uses HTTPS with certificate verification; and
- the credential is an owner-only regular file.

The site policy separates ordinary tenant authority from site-owned cleanup
authority:

```json
{
  "site_cleanup_command_keys": [{
    "key_id": "site-cleanup",
    "public_key": "BASE64_ED25519_PUBLIC_KEY",
    "operations": ["stop", "destroy", "purge"]
  }],
  "tenants": [{
    "tenant_id": "tenant-a",
    "command_keys": [{
      "key_id": "tenant-a-commands",
      "public_key": "BASE64_ED25519_PUBLIC_KEY",
      "operations": ["admit", "start", "stop", "destroy", "read", "purge"]
    }]
  }]
}
```

Tenant private keys stay on a tenant-authorized signing station or separate signing
service outside Steward Control. A separate site incident-response signer holds
the cleanup private key. Cleanup keys can
authorize only `stop`, `destroy`, and `purge`; they cannot authorize `admit`,
`start`, or `read`. Their top-level placement lets a site remove a compromised
tenant key or tenant rule without losing containment of that tenant's existing
workload while Executor is able to serve commands.

Steward rejects tenant and cleanup key-ID collisions. An emergency policy may
contain no tenant rules if it retains cleanup authority. That blocks new admission
while retaining cleanup authority for a running Executor.

Commands use DSSE (Dead Simple Signing Envelope), a standard format that signs a
typed payload. Executor uses the untrusted tenant and operation only to select
candidate public keys, then accepts the command only after signature verification.
The verified command binds tenant, node, instance, runtime reference, generations,
expiry, operation, and payload. Executor also checks the command against the
principal stored at admission, so a cleanup signer cannot redirect an operation by
changing unsigned transport fields.

Steward includes the optional self-hosted `steward-control` queue, enrollment, and
delivery service. It does not include a remote signer, approval workflow, or
scheduler. A trusted signing station or separately operated signing service must
protect tenant private keys and create DSSE envelopes before submitting them to
the controller. A compatible external controller may implement the same public
contract.

With a tenant-scoped compatibility credential, Executor posts `{}` to
`/executor-uplink/poll` and reports terminal outcomes to
`/executor-uplink/report`. With node scope and a durable delivery-state file, the
poll body advertises protocol version 3 and its capabilities:

```json
{
  "protocol_version": 3,
  "node_id": "executor-1",
  "credential_scope": "node",
  "capabilities": ["signed-commands-v2", "delivery-leases-v3", "multi-tenant", "read", "state-purge"]
}
```

The version-3 response carries fenced delivery records around exact DSSE command
bytes. Executor persists a delivery as accepted before applying it and reports a
terminal result after the local command fence and handler settle. A crash after
acceptance but before a provable terminal result becomes `outcome_unknown`; it is
never silently retried as a fresh effect. The controller may reclaim an expired
lease with a higher delivery generation, but cannot change the signed bytes.

Every delivered command is a DSSE envelope with payload type
`application/vnd.steward.executor-command.v2+json`. The verified payload has this
fixed JSON shape:

```json
{
  "schema_version": "steward.executor-command.v2",
  "command_id": "read-agent-1",
  "tenant_id": "tenant-a",
  "node_id": "executor-1",
  "instance_id": "agent-1",
  "runtime_ref": "uplink:v2:8:tenant-a:10:executor-1:agent-1",
  "kind": "read",
  "claim_generation": 1,
  "instance_generation": 1,
  "command_sequence": 1,
  "issued_at": "<issued-at-rfc3339nano>",
  "expires_at": "<expires-at-rfc3339nano>",
  "payload": {}
}
```

The signature covers the tenant, node, instance, tenant-aware byte-length-prefixed
runtime reference, operation, payload, claim and instance generations, command
sequence, and a validity window no longer than 15 minutes. Commands issued more
than two minutes in the future are rejected.

`admit` carries the OpenAPI `SignedAdmissionRequest`. `start`, `stop`, `destroy`,
and `read` require an empty payload. `purge` carries one bounded `lineage_id`. The
signed intent and every runtime-reference identity must describe the same tuple
before the local handler runs.

`read` must match the durable claim and instance generations, but does not advance
the lifecycle high-water sequence. This read-fence separation prevents a read-only
key from blocking a later stop, destroy, or admission command.

A tenant-scoped compatibility credential remains available for one tenant:

```json
{
  "version": 1,
  "tenant_id": "tenant-a",
  "node_id": "executor-1",
  "credential": "opaque-control-plane-bearer"
}
```

This scope keeps the legacy unsigned command format and cannot carry another
tenant's command. Node scope never accepts that unsigned format.

Initialize a newly enrolled node's command fence exactly once before first start:

```console
steward-executor -initialize-uplink-state \
  -uplink-state-file /var/lib/steward-executor/uplink-state.json
```

Normal startup requires the state file. A missing file is never treated as empty,
because resetting the fence could let an old command mutate a newer workload.
Initialization uses exclusive creation and will not overwrite a file.

The state file keys each position by `(tenant_id, instance_id)` and records the
highest applied claim generation, instance generation, command sequence, and
reported status. It is capped at 1 MiB, owner-only, fsynced, and replaced
atomically. A stale or repeated command returns the durable prior status as a
successful no-op. This prevents an old admission or start from resurrecting a
destroyed or replaced workload after restart, including when two tenants reuse one
instance ID. A completed destroy also records and reports `result.absent=true`.

Executor never migrates an older tenant-unaware state file automatically. Stop
Executor, verify the single tenant that owns every legacy entry, and run the
explicit migration as the service user:

```console
sudo -u steward-executor /usr/local/bin/steward-executor \
  -migrate-uplink-state-v1-tenant tenant-a \
  -uplink-state-file /var/lib/steward-executor/uplink-state.json
```

Migration assigns that tenant to every old entry and preserves the original as
`uplink-state.json.v1.bak`. It refuses to overwrite an existing backup or migrate
an already-current file. Keep the backup as evidence of the previous identity and
command-ordering state; never restore it over the migrated state.

Poll and report bodies are capped at 1 MiB, and one poll may contain at most 128
commands. Failed round trips use exponential backoff capped at five minutes. The
credential file is reread on every poll for secret rotation, but a replacement
cannot change its version, scope, tenant, or node identity. The report endpoint
must acknowledge `{"applied":true}`. A negative or malformed acknowledgement is
an error, not proof that the control plane stored the outcome.

Protocol version 2 remains available for compatible external controllers when no
delivery-state file is configured. Tenant-scoped version-1 credentials retain the
legacy protocol. The bundled controller enrolls node-scoped credentials and uses
version 3.

Remote plaintext HTTP is rejected by default. Private-CA and mutual TLS (mTLS)
deployments use
`-uplink-tls-ca-file`, `-uplink-tls-client-cert`, and
`-uplink-tls-client-key`; an explicit CA bundle replaces system roots, and the
private key must be owner-only.
`-uplink-tls-skip-verify` and `-uplink-allow-insecure-http` are explicit, logged
compatibility exceptions. Node-scoped credentials reject both and require verified
HTTPS.

Executor's durable anti-replay and audit files are deliberately finite. The
evidence log is capped at 64 MiB, the operation journal at 16 MiB, the admission
fence snapshot at 4 MiB and 65,535 records, and Executor uplink state at 1 MiB.
Destroyed identities remain as tombstones or positions because deleting them would
permit replay. There is currently no supported compaction or rollover command.
Monitor these files and capacity-plan the node's retained identity count; a full
store makes the affected mutation fail closed. See
[capability boundaries]({{ '/limitations/' | relative_url }}#durable-control-stores-have-fixed-lifetime-limits).

## Deployment invariant

Run `steward`, `steward-executor`, and `steward-gateway` as separate service units
and Unix users. Give Docker-group membership only to Executor. A control plane and
inference service may run elsewhere; neither needs filesystem or Docker access on
the node. Multiple tenants share a host only through signed tenant commands,
site-scoped cleanup authority, anti-replay state keyed by tenant and instance,
tenant-labeled gVisor containers, per-tenant aggregate resource and workload-count
caps, and per-instance networks and grants. Shared-host workloads must keep
persistent state disabled.

`scripts/executor-acceptance.sh` exercises this boundary on a real Linux host. It
uses `EXECUTOR_BIN` when supplied, builds with a local Go toolchain when available,
or uses the checked-in Dockerfile. A deployment target needs Docker and `runsc`,
not a resident Go compiler.
