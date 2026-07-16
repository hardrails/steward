---
title: Upgrade and roll back Steward
description: Stage and verify one complete release, switch its binaries and host integration together, and preserve durable identity state.
section: How-to guide
---

# Upgrade and roll back Steward

Steward nodes store immutable releases under `/opt/steward/releases/<version>` and
select the complete node release through the `/opt/steward/current` symbolic link.
The node payload contains all seven binaries, three node systemd units, helper
scripts, configuration templates, and `release.json`; it never installs a
controller service. The manifest binds the release tag, operating
system, architecture, and SHA-256 digest of every executable and integration file.
Configuration, durable state, audit logs, relay images, and anti-replay state remain
outside release directories. Each manifest also declares the durable formats the
release can read and the format it writes. Activation compares those declarations
with existing Gateway state, connector receipt log, admission fences, operation
journal, Executor evidence log, Executor lifecycle uplink fence
(`uplink-state.json`), separate durable delivery ledger
(`uplink-delivery-state.json`), and supervisor state before a binary switch.

Connector receipt format 1 records ordinary connector events. Format 2 records the
action-authority key ID, permit digest, and exact request digest for permit-backed
events. Format 3 is the historical two-record service-task contract. Format 4 is
the current lifecycle contract: it records task-local authorization, dispatch, and
terminal outcomes, including the service, operation-policy, permit, request, run,
task sequence, and prior-task hash bindings. A single ledger may contain all four
schemas in one signed hash chain. Current release manifests declare
`connector_receipt_log` readers 1 through 4 and writer 4. The inspector reports the
highest format present. It reports format 2 when action authorities are configured
and format 4 when service-task operations are configured, even before the receipt
file exists or contains that schema, because the running configuration can write the
required format immediately.

Current release manifests declare `gateway_state` readers 1 through 4 and writer 4.
Format 4 retains the service identity and tenant task authorities of task-authorized
grants. Activation therefore blocks a rollback that cannot preserve those bindings.

Executor evidence format 1 contains the original admission, mutation, lifecycle,
policy, drift, and revocation vocabulary. Format 2 adds the closed
`activation_begin` and `activation_checkpoint` marker types. One signed evidence
chain may contain both formats, and the inspector reports the highest format
present. Current release manifests declare `evidence_log` readers 1 through 2 and
writer 2.

After authority, policy, and read-only admission preflights pass, Executor fsyncs
`activation_begin` before the admission-allow receipt, mutation journal, or host
mutation. The evidence log therefore reaches format 2 before that activation can
start a workload or produce a checkpoint. Once a format 2 marker exists,
destroying the workload does not downgrade the append-only log; a release whose
evidence reader stops at format 1 is no longer a safe rollback target.

Current release manifests declare `uplink_delivery_state` readers 2 through 3
and writer 3. Format 2 is the earlier protocol-3 delivery ledger. Format 3 records
the wire protocol and claim generation for each delivery and can retain the bounded,
typed admission projection returned by protocol 4. Read-only preflight can inspect
format 2 without changing it. Normal Executor startup atomically rewrites a readable
format-2 ledger as format 3 before polling, including an empty ledger. Draining or
compacting acknowledged deliveries does not change the file back to format 2.

Staging verifies the manifest and writes only a new immutable release directory.
It does not change active helpers or units and does not run `systemctl daemon-reload`.

## Stage the latest release

On an enrolled node, the guided upgrade validates and preserves the existing
configuration:

```console
curl --proto '=https' --tlsv1.2 -fsSLo install-steward.sh \
  https://github.com/hardrails/steward/releases/latest/download/install-steward.sh
less install-steward.sh
sudo install -d -o root -g root -m 0700 /root/steward-upgrade
sudo install -o root -g root -m 0700 install-steward.sh \
  /root/steward-upgrade/install-steward.sh
sudo /bin/bash -p /root/steward-upgrade/install-steward.sh --reuse-configuration
```

To download and install without activating or requiring a running Docker daemon:

```console
sudo /bin/bash -p /root/steward-upgrade/install-steward.sh \
  --non-interactive --stage-only
```

Native packages also leave the active release unchanged and do not restart services.

## Upgrade Steward Control separately

The controller installer keeps immutable releases under
`/opt/steward-control/releases/<version>` and selects
`/opt/steward-control/current`. It does not invoke the node activator or modify
`/opt/steward`.

```console
curl --proto '=https' --tlsv1.2 -fsSLo install-control.sh \
  https://github.com/hardrails/steward/releases/latest/download/install-control.sh
less install-control.sh
sudo install -d -o root -g root -m 0700 /root/steward-control-upgrade
sudo install -o root -g root -m 0700 install-control.sh \
  /root/steward-control-upgrade/install-control.sh
sudo /bin/bash -p /root/steward-control-upgrade/install-control.sh
sudo /usr/local/libexec/steward-control/control-doctor
```

The installer downloads and verifies the dedicated controller archive, stages an
immutable release, validates its binary, service configuration, TLS inputs, and
durable state, then switches the service. It preserves
`/etc/steward-control` and `/var/lib/steward-control`. If candidate activation
fails, it restores the prior release and service state.

The controller's evidence-witness key pair is part of durable state. Upgrades
preserve `/var/lib/steward-control/witness.private.pem` and
`witness.public.pem`. When upgrading state created before those files existed, the
installer creates them once and records their stable paths in `control.env`. It
never replaces an existing file: a partial pair, mismatched pair, symlink, or
unsafe permissions stop activation.

The installer also persists a root-only transaction journal. After a process kill
or power loss, rerun the same installer command; its next invocation restores the
prior links, configuration, token handoff, and service state before attempting the
upgrade again. No boot-time unit performs that recovery automatically.

For a TLS service bound to `0.0.0.0` or `::`, the default doctor verifies only a
local TCP connection because a wildcard address is not a certificate identity.
Pass `--probe-url` with the real HTTPS origin and `--ca-file` with its private CA to
verify certificate identity and HTTP readiness after an upgrade.

Stop the controller before taking a backup; its exclusive writer lock and
hash-chained state require copying the complete state directory as one unit. Keep
the prior release and a tested backup until enrollment, node polling, and command
status have succeeded under the new release. Do not run the old and new controller
over one state directory or restore one state file independently.

Staging does not build or select a relay image. When Gateway and relay topology is
configured, activation builds the target release's `steward-relay` in a `scratch`
image with Docker build networking disabled.
It records the immutable image ID, release, and relay-binary SHA-256 in
`/var/lib/steward-node/relay-images/<release>.env`. The live Executor environment is
not changed until target preflight verifies that binding.

Repeated activation reuses the binding after rechecking the image ID and labels, so
it does not rebuild an image that is already present. If an operator removed the
bound image, activation rebuilds it with fixed UTC context timestamps and
`SOURCE_DATE_EPOCH=0`. A matching image ID restores the binding directly. If the ID
still differs, the drained activation archives the old binding under
`relay-images/retired/` before writing the replacement. Normal upgrades retain prior
release bindings and images for an eligible rollback.

## Migrate legacy Executor uplink state when required

Executor's current command fence, which prevents replay, is keyed by
`(tenant_id, instance_id)`. Activation never guesses which tenant owns a legacy
tenant-unaware entry. Target preflight returns a migration-required error instead.

After validating the candidate and confirming the one tenant that owns every legacy
entry, stop Executor and run the target binary's explicit migration:

```console
TARGET_RELEASE="<release-tag>"
sudo systemctl stop steward-executor
sudo -u steward-executor \
  "/opt/steward/releases/$TARGET_RELEASE/steward-executor" \
  -migrate-uplink-state-v1-tenant tenant-a \
  -uplink-state-file /var/lib/steward-executor/uplink-state.json
```

The command atomically installs tenant-and-instance-keyed state and preserves the
original as `uplink-state.json.v1.bak`. It will not overwrite that backup, migrate a
current-format file, or downgrade. Verify and retain the backup as fencing evidence,
then activate the same target release. This is an operator-approved identity
migration. An older binary that understands only tenant-unaware state is no longer a
routine rollback target, and restoring the backup is not an application rollback.
Activation does not start a service stopped for migration. Record the prior service
state and restore it only after activation succeeds.

## Activate the release

A release transition requires a fully drained node. No managed agent container,
relay container, or capability network may remain; stopped containers count. The
state check also rejects a live admission fence, pending mutation-journal entry, or
retained Gateway grant. State volumes may remain. Destroy workloads through
Steward before activation. A pending journal entry blocks activation because
Steward cannot safely determine whether the interrupted mutation took effect.
Follow an approved recovery procedure for that specific mutation; Steward has no
generic journal-recovery command. Do not delete Docker objects or fencing files by
hand.

```console
TARGET_RELEASE="<release-tag>"
sudo "/opt/steward/releases/$TARGET_RELEASE/integration/scripts/activate-node-release.sh" \
  "$TARGET_RELEASE" --restart
```

Use the target helper for a forward upgrade because the active release may predate
the current transaction checks. Activation verifies `release.json`, checks every
target binary, and takes an exclusive node-activation lock. With `--restart`, it
records which services are active, then stops Gateway, Steward, and Executor. While
they are stopped, it confirms that no managed Docker objects or retained grants
remain, verifies that the target can read every durable file, checks the target relay
image binding, and runs the target's full preflight. It then switches the active
release and relay binding, reloads systemd, and starts only the services that were
previously active, in Gateway, Steward, Executor order. It does not enable an
intentionally disabled service.

`--no-restart` is accepted only when all three services are already inactive. This
prevents the active-release symlink from changing underneath a running process.

Target preflight is read-only: it validates existing state, audit, connector
receipt, journal, evidence, and fence files without creating or appending to them.
It also reports a missing prospective Gateway state, audit, or connector receipt
path as valid. If activation fails before the target services start, it attempts to
restore the prior active-release symlink, relay binding, and service state. After
target services have started, it restores the
prior release only when that release's manifest declares support for every observed
format and inspection accepts the range. Otherwise activation leaves the target selected and all Steward services
stopped. Repair the target or follow an approved migration procedure; do not force
an older binary over newer durable state.

An older target whose connector-receipt reader stops below the required format is
therefore not a safe rollback target. Action-authority configuration requires format
2; current service-task configuration requires format 4. Removing either configuration can
lower the prospective requirement only before a record of that format has been
written; it does not rewrite or downgrade existing evidence. Do not split, edit, or
reserialize a mixed ledger to regain rollback eligibility.

The same rule applies to Executor evidence: after read-only admission preflights,
the target activation marker is written as evidence format 2 before the
admission-allow receipt or host mutation. The rollback inspection must run after
target services stop and before an older release is restored, so it sees that
durable marker and rejects an evidence reader limited to format 1.

It also applies to the Executor delivery ledger. A prior release that reads only
format 2 may remain eligible until the new Executor first starts. After normal
startup migrates the ledger to format 3, that prior release is no longer a software
rollback target, even if the ledger contains no active delivery. Steward provides
no reverse migration because removing protocol identity or an admission projection
could make a retained outcome ambiguous. If recovery requires older software,
restore only a complete, matching pre-upgrade backup under an approved procedure
that accounts for every command and external effect after the backup.

## Roll back the release

If the prior release directory remains present:

```console
PRIOR_RELEASE="<release-tag>"
sudo /usr/local/libexec/steward/activate-node-release \
  "$PRIOR_RELEASE" --restart
```

Use the active release's helper for rollback so the newest installed transaction and
format checks remain in force. Rollback selects the earlier release's binaries,
systemd units, helpers, and retained per-release relay binding after verifying its
manifest. It does not restore configuration or data. A release without the current
manifest schema and explicit durable-state reader ranges is not an eligible rollback
target; build or obtain a reviewed package with a valid manifest instead of
bypassing the integrity check.

<div class="callout warning">
  <strong>Preserve identity and fencing state</strong>
  Do not delete or restore <code>/var/lib/steward-executor/uplink-state.json</code>
  or <code>/var/lib/steward-executor/uplink-delivery-state.json</code> as part of
  a software rollback.
  Preserve <code>/etc/steward</code>,
  <code>/var/lib/steward</code>, <code>/var/lib/steward-executor</code>,
  <code>/var/lib/steward-gateway</code>, <code>/var/lib/steward-node</code>, and
  <code>/var/log/steward</code> unless an approved recovery procedure explicitly
  changes node identity, command history, retained route policy, or audit history.
</div>

## Confirm the result

```console
readlink -f /opt/steward/current
steward -version
steward-control -version
steward-executor -version
steward-gateway -version
steward-relay -version
stewardctl -version
steward-mcp -version
sudo /usr/local/libexec/steward/node-doctor
```

Run the doctor after services restart. It checks the active release's configuration,
runtime dependencies, service state, loopback readiness, Gateway, durable-store
usage, and filesystem headroom. Use its opt-in signed canary when the change also
needs an end-to-end agent-work check; retain the same canary bundle through any
timeout or recovery.

For release construction and maintainer procedures, see
[Releasing Steward]({{ '/releasing/' | relative_url }}).
