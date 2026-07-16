---
title: Configuration reference
description: Steward Control, supervisor, Executor, Gateway, and MCP configuration, packaged defaults, validation commands, security-sensitive flags, paths, and service behavior.
section: Reference
---

# Configuration reference

## Steward Control configuration

`steward-control` uses flags. The dedicated installer writes a root-owned
`/etc/steward-control/control.env`, while the systemd unit runs the process as the
unprivileged `steward-control` account. The service is not a member of the Docker
group.

The packaged unit sets `TasksMax=256`, `LimitNOFILE=4096`, and `MemoryMax=1G` in
addition to its privilege and filesystem restrictions. The store independently
caps the encoded snapshot and write-ahead log at 64 MiB each. The 1 GiB process
limit leaves headroom for decoding, validation, in-memory indexes, and a bounded
compaction while preventing an unexpected allocation from consuming the host. If
measured, legitimate higher capacity requires more memory, use a reviewed systemd
drop-in rather than editing the packaged unit, and qualify startup, compaction,
backup, and restore under the new limit before production use.

| Flag | Default | Purpose |
| --- | --- | --- |
| `-addr` | `127.0.0.1:8443` | Control API listener; a non-loopback address requires TLS |
| `-state-dir` | `/var/lib/steward-control` | Owner-only durable snapshot, write-ahead log, manifest, authentication and witness keys, and lock |
| `-auth-key-file` | `<state-dir>/auth.key` | Owner-only key used to authenticate opaque bearer credentials |
| `-witness-private-key-file` | `<state-dir>/witness.private.pem` | Owner-only Ed25519 key used to sign controller evidence-witness exports |
| `-witness-public-key-file` | `<state-dir>/witness.public.pem` | Matching Ed25519 public key distributed to offline verifiers |
| `-tls-cert-file` | empty | PEM server certificate; must be paired with the key |
| `-tls-key-file` | empty | Owner-only PEM server private key |
| `-delivery-lease` | `2m` | Time-limited node ownership of a delivery; positive and at most `10m` |
| `-max-poll-deliveries` | `32` | Deliveries considered in one poll; 1 through 128 |
| `-max-tenants` | `256` | Retained tenant records |
| `-max-nodes` | `4096` | Retained node records |
| `-max-nodes-per-tenant` | `512` | Node bindings retained for one tenant |
| `-max-credentials` | `16384` | Retained operator and node credential verifiers |
| `-max-credentials-per-tenant` | `2048` | Credential records bound to one tenant |
| `-max-enrollments` | `4096` | Retained one-time enrollment records |
| `-max-enrollments-per-tenant` | `512` | Enrollment records bound to one tenant |
| `-max-commands` | `16384` | Retained exact signed commands |
| `-max-commands-per-tenant` | `1024` | Retained commands for one tenant |
| `-max-commands-per-node` | `256` | Retained commands for one node |
| `-terminal-retention` | `24h` | Minimum retention before a known terminal outcome may be reclaimed for command capacity |

When the certificate and key are configured, Steward Control accepts TLS 1.3 only.
The Steward Control client used by `stewardctl control` and `steward-mcp` likewise
requires TLS 1.3 for HTTPS. Plain HTTP remains limited to a literal loopback
listener.

`-initialize` creates a store or recovers initial bootstrap state containing no
tenant, node, enrollment, or command records and at most one bootstrap credential.
It publishes the first site-administrator token through `-admin-token-file`. That
output must be an absent clean absolute path distinct from the authentication key.
It is created without following a symlink and never written to standard output.
The recovered credential is identical to the first one; initialization does not
mint a second administrator. Initialization also creates the dedicated witness
key pair without overwriting either path. `-initialize-witness-key` is the explicit
migration command for an existing controller created before the pair existed. It
creates the pair only when both paths are absent, accepts an existing valid pair
without changing it, and fails on a partial pair, unsafe permissions, symlink, or
public/private mismatch. `-check-config` opens and validates the complete durable
store, witness pair, and TLS inputs without serving.

The packaged service keeps both witness files in the owner-only state directory.
The private key is mode `0600`; the public key is mode `0644`, but the directory is
mode `0700`, so an unprivileged host account still cannot traverse to it. The
stable public-key location is
`/var/lib/steward-control/witness.public.pem`. A root operator can copy that file
to an auditor or offline verification station. Upgrades and repeated installation
preserve both files. Steward has no implicit key-rotation path because changing
this identity would break continuity with previously verified witness exports.

All request bodies, responses, pages, identifiers, and retained collections are
bounded. Capacity options are startup invariants: restarting with values smaller
than the retained state fails rather than deleting records. The store permits one
active writer and has no live multi-replica mode. Expired enrollments and old
commands with known terminal outcomes are reclaimed only when their capacity is
needed. Pending, leased, `failed`, and `outcome_unknown` commands are not
automatically reclaimed. Revoked credentials and nodes remain retained and count
toward their ceilings; there is no supported purge operation for them.

The packaged `control-doctor` accepts `--json`, `--probe-url URL`, and
`--ca-file PEM`. On a TLS wildcard listener, the default check can prove only that
the local port accepts a TCP connection. Pass the certificate's real HTTPS origin
through `--probe-url` and its private CA through `--ca-file` to verify certificate
identity and readiness. The doctor never reads an operator or node bearer.

## Steward configuration precedence

The supervisor accepts flags, matching `STEWARD_` environment variables, and JSON.
Precedence is **flag → environment → config file → built-in default**. For example,
`-max-instances` becomes `STEWARD_MAX_INSTANCES` or JSON `max_instances`.
`-max-requests-per-second`, `-enable-metrics`, and `-audit-log-file` are flags or
environment variables only.

The packaged service starts with:

```console
steward -config /etc/steward/steward.json \
  -audit-log-file /var/log/steward/audit.jsonl
```

The packaged template uses an outbound-only uplink, durable state, disabled process
execution, and verified TLS.

### Supervisor settings

| Flag | Default | Purpose |
| --- | --- | --- |
| `-addr` | `127.0.0.1:8080` | Inbound listener address |
| `-log-level` | `info` | `debug`, `info`, `warn`, or `error` |
| `-max-instances` | `1024` | Capacity cap for tracked instances |
| `-max-requests-per-second` | `20` | Per-source inbound rate; non-positive disables |
| `-state-file` | empty | Durable JSON state path |
| `-disable-inbound-listener` | `false` | Disable the local listener; requires `-uplink-url`, which becomes the only management path |
| `-enable-metrics` | `false` | Expose Prometheus `/metrics` on inbound listener |
| `-audit-log-file` | empty | Append-only JSON Lines command audit path |
| `-uplink-url` | empty | Control-plane base URL |
| `-uplink-credential-file` | empty | Owner-only node credential; required with uplink |
| `-uplink-poll-interval` | `10s` | Base poll cadence with jitter/backoff |
| `-uplink-command-queue-depth` | `256` | Bounded received-command queue |
| `-uplink-tls-ca-file` | system roots | Private CA bundle; when set, replaces the system root set |
| `-uplink-tls-client-cert` | empty | Optional mutual TLS (mTLS) certificate |
| `-uplink-tls-client-key` | empty | Owner-only mTLS key |
| `-uplink-tls-skip-verify` | `false` | Disable server certificate verification for diagnostics (dangerous) |
| `-enable-process-exec` | `false` | Trusted local OS-process supervision only |
| `-allow-nonloopback-process-exec` | `false` | Acknowledge non-loopback process-execution risk |
| `-allow-root-process-exec` | `false` | Acknowledge root process-execution risk |
| `-process-stop-grace-period` | `10s` | SIGTERM-to-SIGKILL delay |

`-version`, `-check-config`, and `-schema` act and exit. Generate JSON Schema and
validate resolved configuration with the running release:

```console
steward -schema > steward.config.schema.json
steward -check-config -config /etc/steward/steward.json
```

Only `max_instances` can be reloaded with `SIGHUP`. A failed reload keeps the prior
value. Other changes require a restart.

## Executor configuration

Executor uses flags. The packaged unit maps `/etc/steward/executor.env` to flags and
binds its authenticated API to loopback. `-disable-inbound-listener` requires an
outbound-only deployment.

| Flag | Default | Purpose |
| --- | --- | --- |
| `-addr` | `127.0.0.1:8090` | Optional host-local API listener |
| `-docker-socket` | `/var/run/docker.sock` | Docker Engine Unix socket |
| `-token-file` | required | Owner-only local API bearer token |
| `-disable-inbound-listener` | `false` | Outbound-only operation; requires uplink |
| `-uplink-url` | empty | Control-plane base URL |
| `-uplink-credential-file` | empty | Owner-only Executor transport credential: legacy tenant scope or signed multi-tenant node scope |
| `-uplink-state-file` | empty | Durable anti-replay snapshot; required with uplink, capped at 1 MiB encoded |
| `-initialize-uplink-state` | `false` | Exclusively create current empty uplink state and exit |
| `-migrate-uplink-state-v1-tenant` | empty | Explicitly bind every legacy state entry to one tenant, migrate, retain `.v1.bak`, and exit |
| `-uplink-poll-interval` | `10s` | Base outbound poll cadence |
| `-uplink-allow-insecure-http` | `false` | Allow HTTP uplink (dangerous; forbidden with node-scoped credentials) |
| `-uplink-tls-ca-file` | system roots | Private CA bundle; when set, replaces the system root set |
| `-uplink-tls-client-cert`, `-uplink-tls-client-key` | empty | Optional mTLS identity |
| `-uplink-tls-skip-verify` | `false` | Disable server certificate verification (dangerous; forbidden with node-scoped credentials) |
| `-evidence-uplink` | `false` | Publish signed Executor receipt checkpoints independently from command polling |
| `-evidence-uplink-controller-instance-id` | empty | Controller identity authenticated during enrollment; required when evidence uplink is enabled |
| `-evidence-uplink-poll-interval` | `30s` | Base evidence checkpoint cadence; accepted range is 1 second to 1 hour |
| `-max-memory-bytes` | `536870912` | Per-workload admission ceiling |
| `-max-cpu-millis` | `1000` | Per-workload CPU ceiling |
| `-max-pids` | `128` | Per-workload process ceiling |
| `-max-workloads` | `32` | Managed workload cap for the host |
| `-max-workloads-per-tenant` | `4` | Managed workload cap per tenant |
| `-max-total-memory-bytes` | `8589934592` | Aggregate host reservation for workload and relay memory |
| `-max-total-cpu-millis` | `8000` | Aggregate host reservation for workload and relay CPU |
| `-max-total-pids` | `2048` | Aggregate host reservation for workload and relay processes |
| `-max-tenant-memory-bytes` | `2147483648` | Aggregate memory reservation for one tenant |
| `-max-tenant-cpu-millis` | `2000` | Aggregate CPU reservation for one tenant |
| `-max-tenant-pids` | `512` | Aggregate process reservation for one tenant |
| `-allow-unquotaed-state-on-dedicated-host` | `false` | With complete signed admission and exactly one policy tenant, allow persistent local Docker volumes without hard byte or inode quotas |
| `-admission-policy-file` | empty | Signed site-policy DSSE; enables signed admission |
| `-admission-site-root-public-key-file` | empty | Base64 Ed25519 site-root public key |
| `-admission-site-root-key-id` | empty | Required signature key ID for the site policy |
| `-admission-node-id` | empty | Stable node ID bound into intents and receipts |
| `-admission-fence-file` | `/var/lib/steward-executor/admission-fences.bin` | Highest accepted policy/generation snapshot; capped at 4 MiB and 65,535 records |
| `-initialize-admission-fence` | `false` | Exclusively create the empty fence and exit; normal startup never recreates it |
| `-admission-allow-host-admin-intent` | `false` | Dedicated-host compatibility: let the host-wide local token select an intent tenant and authorize signed lifecycle and activation-checkpoint calls; the token is host-administrator authority, not tenant authentication |
| `-admission-journal-file` | `/var/lib/steward-executor/operation-journal.bin` | Append-only host-mutation journal; capped at 16 MiB |
| `-admission-evidence-file` | `/var/lib/steward-executor/evidence.bin` | Append-only signed receipt chain; capped at 64 MiB |
| `-admission-evidence-key-file` | empty | Owner-only PKCS#8 Ed25519 receipt private key |
| `-admission-evidence-epoch` | `1` | Receipt-key epoch expected by offline verification |
| `-gateway-control-socket` | empty | Gateway Unix socket; enables inference, service, connector, and egress grants with a complete Gateway/relay setup |
| `-gateway-grant-root` | `/run/steward-gateway/grants` | Host directory containing per-grant capability sockets |
| `-relay-image` | empty | Trusted relay image pinned by repository digest or local Docker image ID |
| `-relay-gid` | `0` | Nonzero host GID used for per-grant relay socket access |

### Executor uplink credential scopes

A tenant-scoped compatibility credential names exactly one tenant:

```json
{"version":1,"tenant_id":"tenant-a","node_id":"node-a","credential":"<opaque-bearer>"}
```

A multi-tenant Executor uses a node-scoped credential with no `tenant_id`:

```json
{"version":2,"scope":"node","node_id":"node-a","credential":"<opaque-bearer>"}
```

Node scope authenticates the connection, not a tenant. It requires complete signed
admission, matching node IDs, verified HTTPS, and verified policy containing at
least one `site_cleanup_command_keys` entry. Every DSSE (Dead Simple Signing
Envelope) `steward.executor-command.v2` statement binds a typed payload to a
signature from either an authorized tenant-operation key or a site cleanup key for
`stop`, `destroy`, or `purge`. Cleanup keys cannot authorize
`admit`, `start`, or `read`, or share tenant-key IDs. They remain usable after a
tenant rule is removed, preventing stranded workloads. An emergency policy may have
cleanup keys and no tenant rules. The bearer credential cannot select a tenant. See
[Executor outbound uplink]({{ '/executor/' | relative_url }}#outbound-executor-uplink)
for the wire contract.

`-uplink-allow-insecure-http` and `-uplink-tls-skip-verify` weaken transport
authentication. They are disabled by default, unsuitable for production, and
rejected with node-scoped credentials.

Anti-replay state is keyed by tenant and instance. Steward never auto-migrates a
tenant-unaware file. Stop Executor and bind legacy entries to their known tenant:

```console
sudo -u steward-executor /usr/local/bin/steward-executor \
  -migrate-uplink-state-v1-tenant tenant-a \
  -uplink-state-file /var/lib/steward-executor/uplink-state.json
```

The command preserves the original at `uplink-state.json.v1.bak`. It will not
overwrite that backup, migrate a current-format file, or guess a tenant.

Signed admission is all-or-nothing: if any trust input is set, the policy, site-root
key and ID, node ID, and evidence key are all required. The packaged unit accepts
optional `EXECUTOR_ADMISSION_*` values from `/etc/steward/executor.env`.
`EXECUTOR_EVIDENCE_UPLINK_ENABLED`,
`EXECUTOR_EVIDENCE_UPLINK_CONTROLLER_INSTANCE_ID`, and
`EXECUTOR_EVIDENCE_UPLINK_POLL_INTERVAL` map the enrollment evidence handoff to the
three evidence-uplink flags. Evidence publishing additionally requires a
node-scoped credential, matching receipt key and node identity, and verified HTTPS.
See [signed admission and receipts]({{ '/guides/signed-admission/' | relative_url }}).

A tenant policy may contain at most eight `task_keys`. Each entry has a unique
bounded `key_id`, one canonical base64 Ed25519 `public_key`, and one through 32
sorted, unique `service_ids` already allowed by that tenant. The same public key
cannot appear under multiple IDs in one tenant. Executor projects only the public
keys whose scope includes the admitted `service_id` into the runtime grant; the
private task key stays off-node. A service with no matching task key keeps the
ordinary host-authenticated service behavior.

The installer, `configure-node`, and `configure-admission` accept
`--allow-unquotaed-state-on-dedicated-host`. The non-interactive installer also
accepts `STEWARD_ALLOW_UNQUOTAED_STATE_ON_DEDICATED_HOST=true`. These interfaces
map `EXECUTOR_STATE_ARG` to the dedicated-host state flag and run node preflight
before committing the configuration. Preflight accepts the flag only with complete
signed admission and a verified policy containing exactly one tenant. Omit it on a
shared host. The packaged aggregate settings reserve memory, CPU, and PIDs for the
host and each tenant, including fixed relay overhead. They do not cap disk bytes,
inodes, or I/O bandwidth.

`/etc/steward/executor-gateway.env` is either the empty packaged default or a
symbolic link that selects a root-owned relay binding under
`/var/lib/steward-node/relay-images`. A binding is an environment file containing
four Gateway/relay arguments plus the release, immutable image ID, and
`steward-relay` SHA-256. Steward builds the `scratch` image with Docker build
networking disabled. Preflight verifies the file owner and mode, target release,
binary digest, image ID, and image labels. `build-relay-image --configure` builds and
selects a binding for the active release; upgrade preparation omits `--configure`
and cannot rewrite the live Executor environment.

`steward-gateway` reads strict `/etc/steward/gateway.json`: clean absolute socket,
state, token, and audit paths; numeric Executor and relay GIDs; an explicit loopback
service address with a port from 1 through 65535; and at most 128 OpenAI-compatible
routes. Each inference route defines an ID, HTTP(S) origin, optional owner-only
credential file, and concurrency limit. Gateway and relay HTTP listeners cap request
headers at 64 KiB, and their outbound transports cap response headers at 64 KiB.

`egress_routes` contains at most 128 HTTP(S) proxy policies. Each has 1–128
destinations (`host`, `ports`, optional canonical `allowed_cidrs`) and four limits:
`max_concurrent`, `max_request_bytes`, `max_response_bytes`, and
`max_tunnel_seconds`. Write atomically with `stewardctl gateway route set`; activate
with `systemctl reload steward-gateway`. Reload can alter unreferenced routes and
rotate the service token, not socket, state, identity, grant, or audit paths. A grant
retained for a stopped workload pins security-relevant route fields; changing one
rejects the reload.

Gateway limits synchronous egress denial handling to 30 attempts per grant, 120
per tenant, and 480 across the host in each one-minute fixed window. Exhausting any
layer makes subsequent requests that are actually denied return
`egress_rate_limited` until reset, without another denial-audit write. Requests that
satisfy egress policy continue normally. An inactive or revoked grant keeps its
`grant_inactive` or `grant_revoked` response even when the corresponding denial
record is suppressed. These limits are fixed and have no configuration fields.

`connectors` contains at most 128 credential-brokered API policies. Each connector
defines one exact HTTPS origin, one owner-only credential file containing one line
of 12 to 16,384 visible ASCII bytes, `bearer` or
`x-api-key` injection, optional canonical address CIDRs, concurrency, request,
response, duration, and per-grant call limits, plus at most 64 operations. Each
operation is one ID, uppercase HTTP method, and canonical exact path without a
query, fragment, wildcard, or percent-encoded spelling. Connector grants also pin
the loaded credential digest. `credential_epoch` is an operator-managed counter
used only by a permit-enabled connector. It must be positive there and should be
incremented for every credential-authority rotation. It is included in the
effective route-policy digest and omitted when action permits are disabled. See
[authenticated API operations]({{ '/guides/connectors/' | relative_url }}) for the
complete boundary.

`service_operations` contains at most 128 exact tenant-authorized agent-service
operations. Each entry has `service_id`, operation `id`, method `POST`, one canonical
path with no query or percent-encoded alternate spelling, content type
`application/json`, the fixed lifecycle task protocol, one canonical status-path
prefix, and positive limits:

- `max_request_bytes`: at most 65536;
- `max_response_bytes`: at most 1048576;
- `max_seconds`: at most 120;
- `max_permit_seconds`: at most 900;
- `status_max_seconds`: at most 120; and
- `poll_interval_seconds`: from 1 through 60.

One service cannot map the same method and path to multiple operation IDs. These
entries do not make a service task-authorized by themselves. Signed site policy
must scope a tenant task key to the admitted service, and the live grant must carry
that public authority. Gateway then requires one canonical
`X-Steward-Task-Permit` for the configured operation and matches the node, tenant,
logical instance, runtime, grant, generation, admission and route-policy digests,
operation-policy digest, task, exact request digest and length, content type, and
validity window.

Use `stewardctl gateway service` to update and inspect the policy atomically:

```console
sudo stewardctl gateway service set \
  -config /etc/steward/gateway.json \
  -service-id hermes-api \
  -operation hermes.run=POST:/v1/runs \
  -lifecycle hermes.run=/v1/runs/ \
  -max-request-bytes 65536 \
  -max-response-bytes 1048576 \
  -max-seconds 120 \
  -max-permit-seconds 300 \
  -status-max-seconds 15 \
  -poll-interval 1s \
  -tenant-budget tenant-a=4194304
sudo stewardctl gateway service list -config /etc/steward/gateway.json
sudo stewardctl gateway service trust \
  -config /etc/steward/gateway.json -node-id node-a -tenant-id tenant-a \
  > hermes-service-trust.json
```

`set` replaces every operation for the named service and preserves other service,
connector, route, and action-authority configuration. Repeat `-operation` and add
one matching `-lifecycle OPERATION_ID=/status/path/` for every operation. The status
path is a prefix to which the service run ID is appended. `-status-max-seconds`
bounds each observation request; `-poll-interval` is signed into issued bundles and
sets the minimum observation interval. The command prints whether Gateway needs
reload or restart. `trust` requires an explicit node and tenant, verifies that the
tenant has a receipt budget, and exports strict, sorted
`steward.service-trust.v2` JSON with lifecycle policy, operation-policy digests, and
limits. The inventory is unsigned preflight input for `stewardctl task issue`;
authenticate its transfer. Gateway's current configuration and active grant remain
authoritative.

Action permits are opt-in per connector. `action_authorities` accepts at most 64
non-secret Ed25519 public keys. Each entry contains a bounded `key_id`, one exact
`tenant_id`, and canonical base64 `public_key`. The configurator treats key IDs as
immutable: changing a key or tenant requires a new ID. Reusing the same public key
bytes under another ID in one configuration is rejected, and every configured
authority must be referenced. Private action keys never belong in Gateway
configuration or on the node.

When any authority exists, `action_permit_node_id` is required and must be a
bounded stable node identity; without authorities it must be absent. A connector's
sorted `action_authority_ids` contains one through eight configured keys, and
`max_action_permit_seconds` is one through 86,400. Gateway then requires exactly
one canonical `X-Steward-Action-Permit` header for that connector and verifies the
key's tenant scope, node, instance, generation, admission digests, connector,
operation, `operation_policy_digest`, task, exact request digest and length, content
type, and validity window against live state. The operation-policy digest commits
to the canonical base URL, credential injection mode, credential epoch, connector
and operation IDs, HTTP method, and exact path without including credential bytes.
The non-secret mode is `bearer` or `x-api-key` and identifies the header Gateway
uses; the credential value remains excluded. Content type is
`application/json` for POST, PUT, and PATCH and empty for bodyless GET, HEAD, and
DELETE. A connector with no action key rejects an unsolicited permit header rather
than silently ignoring it.

Use repeatable `-action-authority KEY_ID=PUBLIC_KEY_FILE` flags with
`stewardctl gateway connector set`. For each new key, also pass
`-action-authority-tenant KEY_ID=TENANT_ID`. The first permit-enabled connector
requires `-action-node-id`; every permit-enabled connector requires a positive
`-max-action-permit-seconds`. `-clear-action-permit` removes the requirement and
credential epoch, and cannot be combined with action flags. Replacing a connector
without action flags preserves its existing action keys and lifetime. Explicitly
listing keys replaces that connector's list, and unreferenced global keys are
pruned.

A retained grant pins credential epoch, action-key digests and tenant scopes,
permit node identity, lifetime, operations, and all other effective connector
authority. Drain the retained grant before changing those fields; reload rejects
semantic drift. Rotate an action key with a new ID. Rotate a connector credential
only after draining, and increment its credential epoch before admitting replacement
workloads.

Run `stewardctl gateway connector trust` with
`-config /etc/steward/gateway.json` and `-tenant-id TENANT_ID` to export strict,
tenant-filtered `steward.action-trust.v1` JSON. The required root `tenant_id`
excludes other tenants' action-authority and connector metadata. The output
contains node, tenant/key, public-key-digest, connector origin, credential mode,
exact operation method, path and policy digest, credential epoch, and lifetime
metadata. The inventory is non-secret and unsigned. Authenticate it before using
it on a signing station. It is only an issuance preflight; Gateway's live
configuration remains authoritative.

`connector_receipt_file`, `connector_receipt_key_file`,
`connector_receipt_node_id`, and `connector_receipt_epoch` form one required group
when any connector or service-task operation exists. The key is an owner-only
PKCS#8 Ed25519 private key and
the ledger is an owner-only, signed newline-delimited JSON chain capped at 64 MiB.

For a task-enabled service grant, `connector_receipt_node_id` must be the admitted
node ID followed by `/gateway`, such as `node-a/gateway`. Gateway rejects the grant
if this derived identity does not match, and `gateway service trust` fails before
an operator can issue a task from a mismatched inventory. A connector-only setup
may retain another stable receipt identity. Before adding service-task operations
to such a setup, drain all grants and start a new empty receipt chain with the
derived identity, a new key, and a new epoch. Never relabel an existing chain.

Receipt paths must be separate from credentials, Gateway state, audit, token,
control socket, and the grant directory. The packaged installer creates an
independent Gateway key and writes its public half to
`/etc/steward/connector-receipts.public`. Plain HTTP connector origins additionally
require `allow_insecure_http: true`; the default is HTTPS only.

`connector_receipt_tenant_budgets` partitions that ledger into exact,
non-borrowing tenant allocations:

```json
"connector_receipt_tenant_budgets": [
  {"tenant_id": "tenant-a", "bytes": 4194304},
  {"tenant_id": "tenant=west", "bytes": 2097152}
]
```

Every connector-bearing or task-authorized service grant must match one listed
`tenant_id`; Gateway rejects an unbudgeted grant before creating its capability
socket. Each connector-only allocation must be at least 262146 bytes. A tenant with
a lifecycle service operation needs at least 393219 bytes, enough to reserve its
authorization, dispatch, and terminal records. The table may contain at most 128
entries, and the sum may not exceed 67108864 bytes (64 MiB). Usage is the exact
signed JSON line plus its newline. A lifecycle authorization reserves the remaining
dispatch and terminal capacity until those records are written. Unused capacity is
not shared with another tenant. Connector exhaustion returns HTTP 503
`connector_evidence_quota_exhausted`; service-task exhaustion returns HTTP 503
`task_evidence_quota_exhausted`. Neither consumes another tenant's slice.

`stewardctl gateway connector set -tenant-budget TENANT=BYTES` may be repeated.
It adds or updates exact tenant entries and does not remove existing entries. The
parser splits at the final `=`, so `tenant=west=2097152` updates tenant
`tenant=west`. Connector changes may use `systemctl reload steward-gateway`, but
any receipt identity or tenant-budget change requires
`systemctl restart steward-gateway`.

A budget can be reduced in place only after all retained connector grants that
bind the old route policy have been drained. The new allocation must still cover
the tenant's verified historical signed lines and any reconstructed terminal
reservation. Gateway checks those conditions at restart and fails closed when the
allocation is too small. The smaller value changes the route-policy digest for new
grants; it does not reclaim historical ledger bytes.

Removing a tenant that already has ledger history requires a new receipt file and
incremented `connector_receipt_epoch`. Make the retention and external-checkpoint
decision for the old chain, drain retained grants, preserve the old ledger and
verification material, configure the new file and table, and restart Gateway.
There is no CLI operation that removes a budget or compacts an existing ledger.

The same signed ledger may contain receipt formats 1 through 4. Format 1 is an
ordinary connector event, format 2 adds a connector action permit, and format 3 is
the historical two-record service-task contract. Current lifecycle tasks use format
4 and add task-local sequence and hash links across authorization, dispatch, and
terminal records. Gateway state format 4 separately retains the service ID and
public tenant task authorities for task-enabled grants. Keep the ledger, Gateway
state, and declared release-format compatibility together during backup, upgrade,
and rollback; do not downgrade either file independently.

`steward-mcp` can configure fleet tools with `-control-url` and the owner-only
`-control-token-file`; `-control-ca-file` optionally supplies a private controller
CA and replaces system roots for that controller connection. It can separately
configure node tools with `-node-url` (default
`http://127.0.0.1:8090`) and `-token-file`, an owner-only Executor bearer token.
At least one control or node client is required. Optional task tools require all three of
`-gateway-url`, `-gateway-token-file`, and `-task-result-dir`. The result directory
must already exist as a process-owned mode-`0700` directory under trusted,
non-replaceable ancestors. It is capped at 1,024 result files and 256 MiB. The MCP
server does not listen on the network.

To validate startup inputs without binding or polling, run the service command with
`-check-config` and the same flags it uses at startup. The packaged node doctor
assembles those checks and also inspects Docker, gVisor, systemd, loopback health and
readiness, Gateway, fixed stores, and filesystem capacity. Its default mode is
read-only. A missing Gateway state or audit file is a valid first-start path. Signed
admission journal, evidence, and fence files are rollback and audit authority, so
Executor requires them to exist before validation:

```console
sudo /usr/local/libexec/steward/node-doctor
sudo /usr/local/libexec/steward/node-doctor --json
```

The lower-level `/usr/local/libexec/steward/node-preflight` remains available for
configuration validation alone. If the journal records an operation as started but not
completed, `-check-config` fails because the node is not ready for normal
mutations. Normal startup accepts that same journal and serves in degraded
containment mode with readiness at 503.

For the exact accepted flags, use the installed release's `steward -h` and
`steward-executor -h` output. The [public APIs]({{ '/reference/api/' | relative_url }})
are versioned separately.
