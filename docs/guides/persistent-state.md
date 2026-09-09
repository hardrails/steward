---
title: Configure quota-enforced persistent state
description: Give agents durable state on a shared Linux host without allowing one tenant to consume the host filesystem.
section: How-to
---

# Configure quota-enforced persistent state

An agent often needs files to survive a container replacement. A normal Docker
volume preserves those files, but it does not reliably limit their bytes or file
count. On a shared host, one tenant could therefore fill the backing filesystem and
disrupt every other tenant.

Steward's OpenZFS storage worker closes that gap. It gives each tenant lineage a
separate ZFS dataset with a hard byte limit and hard object limit. An **object** is a
filesystem object such as a file or directory. Executor never receives ZFS or root
authority; it asks the separate worker for one exact volume over an authenticated
Unix socket.

Use this backend when different tenants share one Linux host. The older unquotaed
Docker-volume mode remains available only as an explicit compatibility choice for a
dedicated single-tenant host.

## Before you begin

The packaged worker requires AppArmor and runs in the host mount namespace so
Docker sees its ZFS mounts. A private mount namespace can pass worker-local checks
while Docker binds the underlying, unquotaed directory. Do not add namespace-based
hardening to this unit or bypass the mandatory profile. Before attaching tenant
work on a new host image, prove that Docker receives the mounted ZFS dataset and
that the sandbox runtime UID can write there and exhaust both quotas.

An Ubuntu 24.04 development deployment passed byte/object quota exhaustion from
gVisor, retained a marker across container replacement, and denied changes to
root-directory permissions. AppArmor also denied off-allowlist reads and mounts.
These results do not qualify every distribution, a production storage topology,
or a changed runtime source revision. Release qualification is a separate gate.

New and cloned roots are prepared as `root:65532` mode `0770`: the fixed runtime
group can create state, but the agent cannot chmod the dataset root. Preparation
requires `CAP_CHOWN` in the separate worker, in addition to ZFS administration.
Before changing ownership, the worker opens the directory without following a
final symlink and requires a distinct ZFS mount, not an underlying host directory
or an ordinary subdirectory on a ZFS-backed host. Inspection rejects changed
ownership or mode; replay does not silently repair it. The default access verifier
fails closed on non-Linux platforms. Deterministic tests inject a mount accessor;
that fake is not evidence of kernel quota enforcement.

You need:

- a Linux node installed from a Steward node package;
- Docker and gVisor configured as described in the
  [node setup guide]({{ '/getting-started/' | relative_url }});
- OpenZFS installed by the operating-system administrator;
- an AppArmor-enabled kernel, `/usr/sbin/apparmor_parser` and `/usr/bin/aa-exec`
  (on Ubuntu, provided by the `apparmor` package);
- an existing ZFS parent dataset reserved for Steward, such as
  `tank/steward`; and
- complete signed-admission configuration.

The worker does not create or import a pool. This keeps pool topology, encryption,
replication, disk replacement, and disaster recovery under the storage
administrator's control.

## Configure the node

The following example selects `tank/steward` and applies the packaged defaults: a
10 GiB byte limit and 1,000,000-object limit for each lineage.

1. Create an owner-only Executor token and a separate root-owned worker copy:

   ```bash
   sudo install -d -o root -g root -m 0755 /etc/steward
   openssl rand -hex 32 | sudo install -o steward-executor -g steward-executor \
     -m 0600 /dev/stdin /etc/steward/storage-zfs-token
   sudo install -o root -g root -m 0600 /etc/steward/storage-zfs-token \
     /etc/steward/storage-zfs-worker-token
   ```

2. Install the worker configuration and replace the dataset placeholder:

   ```bash
   sudo sed 's|@ZFS_DATASET_ROOT@|tank/steward|' \
     /opt/steward/current/integration/deploy/config/storage-zfs.json.in \
     | sudo install -o root -g root -m 0644 /dev/stdin \
       /etc/steward/storage-zfs.json
   ```

3. Add these values to `/etc/steward/executor.env`:

   ```text
   EXECUTOR_STATE_BACKEND_SOCKET=/run/steward-storage-zfs/storage.sock
   EXECUTOR_STATE_BACKEND_TOKEN_FILE=/etc/steward/storage-zfs-token
   EXECUTOR_STATE_VOLUME_BYTE_LIMIT=10737418240
   EXECUTOR_STATE_VOLUME_OBJECT_LIMIT=1000000
   ```

   Keep `EXECUTOR_STATE_ARG=` empty. That variable enables the unquotaed
   compatibility mode and cannot be combined with the qualified backend.

4. Validate and start the worker before restarting Executor:

   ```bash
   sudo steward-storage-zfs -check-config
   sudo systemctl enable --now steward-storage-zfs
   sudo /usr/local/libexec/steward/node-preflight
   sudo systemctl restart steward-executor
   sudo /usr/local/libexec/steward/node-doctor
   ```

Normal service startup is intentionally mutating. It creates a random scratch lineage,
proves real byte and object quota exhaustion, then exercises snapshot, clone,
Docker binding, and deletion. It removes the scratch objects before returning.
It does not signal systemd readiness until these checks pass. Running
`steward-storage-zfs -check-backend` directly repeats the backend check but does not
prove the packaged service's confinement or the sandbox boundary.

Before each worker start, systemd loads the policy from the selected immutable
release, then `aa-exec` starts the worker under that profile. An invalid policy
fails startup even if an older profile is already loaded; a missing profile does
not fall back to an unconfined worker. The policy is part of the verified node
payload. Only the fixed policy-loading command receives unrestricted host
privilege; the serving process does not.

The policy permits only the packaged configuration, token, binary, socket and
state paths. Custom paths require a separately reviewed policy and unit override,
not a broader wildcard. Existing configurations that point the worker at
`storage-zfs-token` must migrate to the root-owned copy before starting this unit.
Node activation runs the target binary's read-only `-check-packaged-config` before
stopping any service. It refuses legacy paths, a missing or mismatched token copy,
or missing AppArmor kernel/userspace support. It does not rotate credentials or
repair configuration automatically.

Before upgrading an existing stock installation:

1. Install the host's AppArmor userspace tools and enable AppArmor in the kernel.
   Both `/usr/sbin/apparmor_parser` and `/usr/bin/aa-exec` must be executable.
2. Keep the current Executor token unchanged. If the worker copy does not exist,
   copy that token to `/etc/steward/storage-zfs-worker-token` with owner `root:root`
   and mode `0600`, using the `install` command from the setup instructions above.
   If the copy already exists, compare it with `sudo cmp --silent` rather than
   overwriting it. Investigate a mismatch; do not rotate a live worker's token.
3. Use `sudoedit /etc/steward/storage-zfs.json` to change only `token_file` to the
   new worker-copy path. Preserve the dataset, limits and existing token value.
   Run the **target release's** `steward-storage-zfs -check-packaged-config`, with
   `-client-token-file` pointing to Executor's configured token file. Correct any
   error before retrying activation. This check leaves the running worker alone.

These checks validate the stock unit and its fixed policy paths. Automated stock
activation rejects custom paths even when an operator has a policy override;
such installations need a separately reviewed deployment procedure, not a bypass
that silently starts an unconfined service.

For token rotation, quiesce storage callers, stop Executor and the worker, replace
both owner-only copies with the same new value, then start the worker before
Executor. Never put tokens in commands, service arguments, logs or agent files.

The worker creates only fixed `volumes` and `tombstones` children beneath the
selected parent. After qualification, it creates a tenant dataset lazily when
Executor admits a signed workload that requests state.

## Migrate retained volume roots before upgrading

Releases that created ZFS roots as `root:root 0755` require an explicit offline
migration before you resume their workspaces under the sandbox-group contract.
Normal inspection and create replay never repair permissions. Back up retained
state and keep all workload/container creators and host writers quiesced throughout
the procedure. Stop or park workloads through their authorized lifecycle, remove
their container references through that lifecycle, and stop Executor and the
storage worker. A stopped container still counts as a reference.

Create an owner-only JSON file with the exact retained volume scope, for example:

```json
{"volume_id":"retained-volume","tenant_id":"tenant-a","lineage_id":"lineage-a","generation":1}
```

Use the values from the retained admission/storage record, not IDs inferred from
hashed dataset names. The migration accepts no host path, ownership choice or
quota override. Use the target release binary, before switching the active release:

```bash
sudo install -d -o root -g steward-executor -m 0750 /run/steward-storage-zfs
sudo /opt/steward/releases/vX.Y.Z/steward-storage-zfs \
  -config /etc/steward/storage-zfs.json \
  -migrate-volume-access /root/retained-volume-scope.json
```

Replace `vX.Y.Z` with your verified staged version. The scope file must be regular,
owner-only, bounded and non-symlink. The command holds the serving worker's lifetime
lock and verifies tenant, lineage, generation, deterministic references, quotas,
mount point and Docker binding. Docker must confirm that no running or stopped
container references the binding. This is a point-in-time check, not a lock against
other root-equivalent Docker clients; keep those clients and host writers stopped.

Only the distinct ZFS mount root changes, from `root:root 0755` to
`root:65532 0770`. An interrupted `root:65532 0755` transition resumes; an already
migrated root is a no-op. Other ownership/mode combinations require investigation
and are refused. The command never recursively changes files, edits ZFS records,
changes limits, deletes/recreates bindings or alters snapshots. Repeat the command
for each retained volume before completing the upgrade. If it fails, keep work
parked and investigate the named boundary; do not use recursive `chown` or weaken
inspection. After successful migration and target preflight, activate the release,
start the worker before Executor, and resume through the normal signed lifecycle.

The opt-in Linux test `TestOfflineVolumeMigrationOnRealZFS` proves CLI lock refusal,
running/stopped container refusal, migration/replay and preservation of contents,
file ownership/modes, identity, quotas and snapshots on a disposable child dataset.
It does not claim that arbitrary host processes are fenced by Docker's check.

## Verify enforcement

Inspect one created dataset on the host:

```bash
sudo zfs list -r -o name,used,available,refquota tank/steward/volumes
sudo zfs get -r projectquota,projectobjquota tank/steward/volumes
```

The dataset name is a hash, not a tenant name. Steward records the exact tenant,
lineage, generation, limits, and request identity in a bounded ZFS user property.
Do not infer ownership from the dataset name or edit that property manually.

If Docker binding or its verification fails after dataset preparation, the worker
retains that dataset and its exact creation record. A lost Docker acknowledgement
does not prove that creation failed. Retry the original request after restoring
connectivity; the worker verifies and reuses the retained state without replacing
its files. A changed request or conflicting Docker binding is rejected. Reconcile
conflicts explicitly; replay never deletes or adopts another binding. Use normal
volume deletion when you intend to discard a reconciled volume. Failures before
binding begins still clean up the newly created dataset.

Executor also checks the worker's advertised capabilities at startup. It refuses
qualified state if the backend does not report hard byte and object quotas,
crash-safe metadata, immutable cold snapshots, copy-on-write clones, and exact
Docker handles. The worker's startup conformance tests the actual pool, mount, and
Docker configuration behind that claim.

## What the worker is trusted to do

`steward-storage-zfs` runs as root because OpenZFS administration requires host
authority. Its systemd service bounds the worker to `CAP_SYS_ADMIN` and `CAP_CHOWN`,
with no new privileges and Unix sockets only. AppArmor confines filesystem access,
executables and mount targets without hiding those mounts from Docker. This is
not per-dataset authorization of ZFS ioctls: the worker can still affect ZFS and
can reach Docker's
root-equivalent socket. Treat the worker, Docker daemon, OpenZFS, Linux kernel, and
host root as trusted node infrastructure.

The narrower boundary matters:

- the unprivileged Executor can request only the storage protocol operations;
- the worker accepts bounded strict JSON and a bearer token over one Unix socket;
- tenant and lineage identity are required on every operation;
- dataset and Docker volume names are derived by the worker, never selected by the
  agent; and
- the Docker client is limited to exact local-driver bind volumes and rejects
  changed labels, paths, options, redirects, and oversized responses.

No agent container receives the storage token, Docker socket, host path, ZFS
command, or reusable host credential.

## Lifecycle and recovery

A state volume belongs to one `(tenant_id, lineage_id)` pair. Replacing that
workload can reattach the same volume. Two live instances cannot hold the same
writable lineage lease.

Purge removes the Docker binding and dataset only when no snapshot or clone still
depends on it. The worker writes a durable tombstone before destructive cleanup, so
an interrupted purge can resume without silently recreating old state. Purge retires
that lineage identity. Use a new lineage ID if you intentionally want fresh state.

Executor exposes the qualified backend through two signed operations:

- `snapshot-state` creates an immutable cold snapshot only after the complete
  source lineage has been destroyed. Merely stopping the container is not enough.
- `clone-state` creates a new, quota-enforced copy-on-write lineage in the same
  tenant. The target instance and lineage must be new. Normal signed admission
  with `state_disposition: resume` is still required before the fork can run.
- `delete-snapshot` removes the immutable checkpoint only after every dependent
  clone lineage has been destroyed and purged. This releases retained snapshot
  capacity and allows the source lineage to be purged.

Both operations bind tenant, node, instance, lineage, generation, and snapshot
identity to the signed command. Executor derives the dataset and Docker volume
identity, records the mutation in its durable journal, and appends a signed receipt.
Exact retries are idempotent. The storage worker's private socket remains an
internal boundary; operating it directly bypasses lifecycle authority and evidence.
The same bounded operations are available as `stewardctl node snapshot-state` and
`stewardctl node clone-state`, and as MCP tools `steward_snapshot_state` and
`steward_clone_state`. Those local surfaces use the configured Executor credential;
they do not weaken tenant authorization or enable host-admin intent implicitly.
Snapshot deletion is available as `stewardctl node delete-snapshot` and
`steward_delete_snapshot`.

If a snapshot may contain attacker-controlled instructions, compromised state,
or credentials that should never be copied again, block it as a source for new
forks without destroying forensic evidence:

```console
stewardctl control snapshot quarantine \
  -tenant-id tenant-a -node-id node-a -snapshot-id snapshot-a \
  -reason "suspected state contamination"
```

The quarantine is durable controller admission state. It does not change the ZFS
snapshot, delete data, stop a running agent, or revoke a fork that was already
created. Clear it with `stewardctl control snapshot unquarantine` only after the
snapshot is trusted again or no longer usable.

If Executor loses the worker response after preparing a mutation, it blocks every
unrelated mutation. Reissuing the exact same signed snapshot or clone request is the
only operation allowed to settle that journal entry. A different snapshot, lineage,
tenant, or generation remains blocked. After recovery, run reconciliation (normal
service operation does this automatically) before admitting more work.

Snapshots are node-local. Placement must select a node whose inventory advertises
the snapshot ID. Cross-node replication and retention automation are not yet part
of this workflow.

Back up and replicate the pool using reviewed OpenZFS procedures. Steward does not
configure pool encryption, `zfs send`, remote replication, scrub schedules, or key
escrow.

## Dedicated-host compatibility mode

If a node has exactly one policy tenant and no qualified storage backend, you can
instead set:

```text
EXECUTOR_STATE_ARG=-allow-unquotaed-state-on-dedicated-host
```

This mode uses a normal Docker volume. It has no hard byte or object limit. Never
use it to claim storage isolation between tenants.
