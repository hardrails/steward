---
title: Upgrade and roll back Steward
description: Stage and verify one complete release, switch its binaries and host integration together, and preserve durable identity state.
section: How-to guide
---

# Upgrade and roll back Steward

Steward stores immutable releases under `/opt/steward/releases/<version>` and selects
the complete release through the `/opt/steward/current` symbolic link. A release
contains all six binaries, the systemd units, helper scripts, configuration
templates, and `release.json`. The manifest binds the release tag, operating
system, architecture, and SHA-256 digest of every executable and integration file.
Configuration, durable state, audit logs, relay images, and anti-replay state remain
outside release directories. Each manifest also declares the durable formats the
release can read and the format it writes. Activation compares those declarations
with existing Gateway state, admission fences, operation journal, evidence log,
Executor uplink state, and supervisor state before a binary switch.

Staging verifies the manifest and writes only a new immutable release directory.
It does not change active helpers or units and does not run `systemctl daemon-reload`.

## Stage the latest release

On an enrolled node, the guided upgrade validates and preserves the existing
configuration:

```console
curl -fsSLo install-steward.sh \
  https://github.com/hardrails/steward/releases/latest/download/install-steward.sh
sudo bash install-steward.sh --reuse-configuration
```

To download and install without activating or requiring a running Docker daemon:

```console
sudo bash install-steward.sh --non-interactive --stage-only
```

Native packages also leave the active release unchanged and do not restart services.

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

Target preflight is read-only: it validates existing state, audit, journal,
evidence, and fence files without creating or appending to them. It also reports a
missing prospective Gateway state or audit path as valid. If activation fails before
the target services start, it attempts to restore the prior active-release symlink,
relay binding, and service state. After target services have started, it restores the
prior release only when that release's manifest proves it can read every observed
format. Otherwise activation leaves the target selected and all Steward services
stopped. Repair the target or follow an approved migration procedure; do not force
an older binary over newer durable state.

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
  as part of a software rollback. Preserve <code>/etc/steward</code>,
  <code>/var/lib/steward</code>, <code>/var/lib/steward-executor</code>,
  <code>/var/lib/steward-gateway</code>, <code>/var/lib/steward-node</code>, and
  <code>/var/log/steward</code> unless an approved recovery procedure explicitly
  changes node identity, command history, retained route policy, or audit history.
</div>

## Confirm the result

```console
readlink -f /opt/steward/current
steward -version
steward-executor -version
steward-gateway -version
steward-relay -version
stewardctl -version
steward-mcp -version
sudo /usr/local/libexec/steward/node-preflight
systemctl is-active steward steward-executor steward-gateway
```

For release construction and maintainer procedures, see
[Releasing Steward]({{ '/releasing/' | relative_url }}).
