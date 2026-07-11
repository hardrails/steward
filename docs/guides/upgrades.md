---
title: Upgrade and roll back Steward
description: Stage a Steward release without disruption, preflight it, atomically activate both binaries, and roll back application code without corrupting identity state.
section: How-to guide
---

# Upgrade and roll back Steward

Steward keeps immutable releases under `/opt/steward/releases/<version>` and selects
both binaries through one `/opt/steward/current` symlink. Configuration, durable
state, audit logs, and anti-replay state live outside release directories.

## Stage the latest release

On an enrolled node, the guided upgrade validates and retains existing configuration:

```console
curl -fsSLo install-steward.sh \
  https://github.com/hardrails/steward/releases/latest/download/install-steward.sh
sudo bash install-steward.sh --reuse-configuration
```

To download and install without activating or requiring a running Docker daemon:

```console
sudo bash install-steward.sh --non-interactive --stage-only
```

Native packages also stage upgrades. They do not silently restart services or select
a new active version.

## Activate atomically

```console
sudo /usr/local/libexec/steward/activate-node-release v0.1.0 --restart
```

Activation checks both target binaries and runs full node preflight before switching
the one symlink. `--restart` uses `systemctl try-restart`, so intentionally stopped
or disabled services do not become active.

## Roll back application code

If the prior release directory remains present:

```console
sudo /usr/local/libexec/steward/activate-node-release <prior-version> --restart
```

This rolls back binaries and packaged integration only. It does not roll back data.

<div class="callout warning">
  <strong>Preserve identity and fencing state</strong>
  Do not delete or restore <code>/var/lib/steward-executor/uplink-state.json</code>
  as part of a software rollback. Preserve <code>/etc/steward</code>,
  <code>/var/lib/steward</code>, <code>/var/lib/steward-executor</code>, and
  <code>/var/log/steward</code> unless an approved recovery procedure explicitly
  changes node identity or command history.
</div>

## Confirm the result

```console
readlink -f /opt/steward/current
steward -version
steward-executor -version
sudo /usr/local/libexec/steward/node-preflight
systemctl is-active steward steward-executor
```

For release construction and maintainer procedures, see
[Releasing Steward]({{ '/releasing/' | relative_url }}).
