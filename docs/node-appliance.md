# Disconnected Steward node appliance

The Linux release archive is an offline-installable node payload for both Steward
processes. It contains the two static binaries, hardened systemd units, fail-closed
configuration templates, and small Bash utilities for install, preflight, and
version activation. It contains no Railyard code and makes no network call during
installation.

This is the open-source node half of a sovereign deployment. A separately delivered
control-plane bundle may carry this archive, customer trust material, and approved
OCI images, but Steward remains independently downloadable, buildable, installable,
and operable.

## Host contract

- Linux with systemd;
- Docker already installed, with a local `docker` group and gVisor registered as
  runtime `runsc`;
- one of the published Linux `amd64` or `arm64` Steward archives; and
- customer-provisioned Railyard CA, node credentials, and Executor host token.

The installer does not install Docker or gVisor, fetch packages, contact GitHub, pull
images, create credentials, or trust an embedded vendor endpoint. Those are explicit
operator inputs. It also does not enable or start either service.

## Offline install

Verify the archive using the release `checksums.txt`, transfer it into the facility,
then unpack and install as root. A checksum proves integrity against the manifest you
received; it does not by itself authenticate who supplied that manifest. When this
archive is carried inside a signed appliance bundle, verify that outer signature and
its pinned trust key before checking these inner hashes.

```console
sha256sum -c checksums.txt
tar -xzf steward_v0.1.0_linux_amd64.tar.gz
sudo bash scripts/install-node.sh
```

The installer:

1. requires Linux and an existing Docker group;
2. verifies that `steward` and `steward-executor` report the same safe version;
3. creates distinct unprivileged `steward` and `steward-executor` service users,
   adding only the Executor identity to the root-equivalent Docker group;
4. copies immutable binaries under `/opt/steward/releases/<version>` and atomically
   selects both through one `/opt/steward/current` symlink;
5. installs vendor systemd units under `/usr/local/lib/systemd/system` and
   configuration templates without overwriting an operator's existing configuration
   or `/etc/systemd/system` overrides; and
6. leaves both services disabled and stopped.

An exact legacy unit written to `/etc/systemd/system` by the prototype installer is
migrated automatically. A differing full-unit override is treated as operator-owned:
installation stops and instructs the operator to move local settings into a standard
`/etc/systemd/system/<unit>.d/*.conf` drop-in before retrying. It is never silently
deleted or shadowed by the new vendor unit.

The two service identities intentionally do not share authority. The lifecycle
supervisor cannot read the Docker socket. The Executor can access Docker, but its
unit grants no Linux capabilities and applies systemd filesystem, device, namespace,
kernel, home, and privilege hardening around that unavoidable root-equivalent socket.
Agent containers never receive the socket.

## Provision trust material

Replace `railyard.example.invalid` in both `/etc/steward/steward.json` and
`/etc/steward/executor.env`. Install these files from the customer's enrollment and
PKI workflow:

| Path | Owner/mode | Purpose |
| --- | --- | --- |
| `/etc/steward/uplink-credential.json` | `steward:steward`, `0600` | Steward node credential |
| `/etc/steward/executor-uplink.json` | `steward-executor:steward-executor`, `0600` | Executor node credential |
| `/etc/steward/executor-token` | `steward-executor:steward-executor`, `0600` | host-local Executor bearer secret |
| `/etc/steward/railyard-ca.pem` | `root:root`, `0644` | customer control-plane CA bundle |

Initialize the Executor's durable command fence exactly once, as its service user:

```console
sudo -u steward-executor /usr/local/bin/steward-executor \
  -initialize-uplink-state \
  -uplink-state-file /var/lib/steward-executor/uplink-state.json
```

A missing fence on ordinary startup is fatal. Reinitializing an existing fence is
also fatal; an operator cannot silently erase the anti-replay boundary.

## Preflight and activation

Run the complete preflight as root:

```console
sudo /usr/local/libexec/steward/node-preflight
sudo systemctl enable --now steward steward-executor
```

Preflight checks the real service identities, Docker `runsc`, both binaries, every
required Executor setting, credential/state/CA readability and permissions through
the binaries' own validators, and both installed systemd units. Neither binary binds
a listener or starts an uplink poll during its configuration check.

`steward` remains in status-tracker mode because the appliance template explicitly
sets `enable_process_exec: false`. Untrusted tenant workloads go only through the
separate Executor/gVisor boundary.

## Upgrade and rollback

Installing another archive preserves the prior release directory and existing
configuration. A first install selects its binaries only so the disabled node can be
configured; a later install only stages the new version and does not change or restart
the active release. Activate or roll back atomically:

```console
sudo /usr/local/libexec/steward/activate-node-release v0.2.0 --restart
sudo /usr/local/libexec/steward/activate-node-release v0.1.0 --restart
```

Every activation runs the target binaries through full node preflight before the
single active-release symlink changes. `--restart` additionally uses
`systemctl try-restart`, which restarts only services that were already running and
never turns an intentionally disabled service on. Node state, credentials, audit log,
and Executor fence live outside the release directory and survive either direction.

Application rollback is not a state rollback. Preserve `/var/lib/steward`,
`/var/lib/steward-executor`, `/var/log/steward`, and `/etc/steward`; deleting or
restoring those paths changes lifecycle, audit, identity, or anti-replay state and
requires a separate operator-approved recovery procedure.
