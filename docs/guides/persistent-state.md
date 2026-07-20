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

You need:

- a Linux node installed from a Steward node package;
- Docker and gVisor configured as described in the
  [node setup guide]({{ '/getting-started/' | relative_url }});
- OpenZFS installed by the operating-system administrator;
- an existing ZFS parent dataset reserved for Steward, such as
  `tank/steward`; and
- complete signed-admission configuration.

The worker does not create or import a pool. This keeps pool topology, encryption,
replication, disk replacement, and disaster recovery under the storage
administrator's control.

## Configure the node

The following example selects `tank/steward` and applies the packaged defaults: a
10 GiB byte limit and 1,000,000-object limit for each lineage.

1. Create an authentication token that only Executor can read:

   ```bash
   sudo install -d -o root -g root -m 0755 /etc/steward
   openssl rand -hex 32 | sudo install -o steward-executor -g steward-executor \
     -m 0600 /dev/stdin /etc/steward/storage-zfs-token
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
   sudo steward-storage-zfs -check-backend
   sudo systemctl enable --now steward-storage-zfs
   sudo /usr/local/libexec/steward/node-preflight
   sudo systemctl restart steward-executor
   sudo /usr/local/libexec/steward/node-doctor
   ```

`-check-backend` is intentionally mutating. It creates a random scratch lineage,
proves real byte and object quota exhaustion, then exercises snapshot, clone,
Docker binding, and deletion. It removes the scratch objects before returning.
Normal worker startup repeats this test and does not signal systemd readiness until
it passes. Executor therefore starts only after the configured host substrate is
qualified.

The worker creates only fixed `volumes` and `tombstones` children beneath the
selected parent. After qualification, it creates a tenant dataset lazily when
Executor admits a signed workload that requests state.

## Verify enforcement

Inspect one created dataset on the host:

```bash
sudo zfs list -r -o name,used,available,refquota tank/steward/volumes
sudo zfs get -r projectquota,projectobjquota tank/steward/volumes
```

The dataset name is a hash, not a tenant name. Steward records the exact tenant,
lineage, generation, limits, and request identity in a bounded ZFS user property.
Do not infer ownership from the dataset name or edit that property manually.

Executor also checks the worker's advertised capabilities at startup. It refuses
qualified state if the backend does not report hard byte and object quotas,
crash-safe metadata, immutable cold snapshots, copy-on-write clones, and exact
Docker handles. The worker's startup conformance tests the actual pool, mount, and
Docker configuration behind that claim.

## What the worker is trusted to do

`steward-storage-zfs` runs as root because OpenZFS administration requires host
authority. Its systemd service bounds the process to `CAP_SYS_ADMIN`, a protected
runtime directory, the configured state path, Unix sockets, and the packaged
binary. It can still affect the selected ZFS pool and can reach Docker's
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

The storage protocol includes held snapshots and copy-on-write clones. Steward does
not yet connect those primitives to the public fork workflow, retention policy, or
fleet scheduler. Until that integration exists, do not operate the worker's private
socket directly; doing so would bypass the lifecycle and evidence boundary.

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
