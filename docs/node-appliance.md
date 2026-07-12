---
title: Steward node appliance
description: Detailed Linux appliance packaging, installation, enrollment, preflight, activation, rollback, removal, and filesystem ownership behavior.
section: Operator reference
---

# Installing the Steward node appliance

Every Linux release is available as DEB, RPM, and a universal systemd archive. All
three contain the same six static binaries, hardened systemd units, fail-closed
configuration templates, and small Bash utilities for install, enrollment,
preflight, version activation, and removal. They contain no control-plane code.

This is the open-source node half of a sovereign deployment. A separately delivered
control-plane bundle may carry this archive, customer trust material, and approved
OCI images, but Steward remains independently downloadable, buildable, installable,
and operable.

## Host contract

- Linux with systemd on `amd64` or `arm64`;
- Docker already installed, with a local `docker` group and gVisor registered as
  runtime `runsc` (the guided installer can install/register official gVisor);
- one matching Steward release artifact; and
- customer-provisioned control-plane CA, node credentials, and Executor host token.

Docker is deliberately not installed or reconfigured beyond optional gVisor
registration: it is a host prerequisite controlled by the operator. No path pulls an
agent image, creates a control-plane credential, or trusts an embedded endpoint.

## Platform and artifact matrix

| Target family | Preferred artifact | Installer behavior |
| --- | --- | --- |
| Debian, Ubuntu, derivatives | `steward-node_<version>_<arch>.deb` | Installs with `dpkg` |
| RHEL, Rocky, Alma, CentOS Stream, Fedora, Amazon Linux, Oracle Linux, SUSE | `steward-node_<version>_<arch>.rpm` | Installs with `rpm` |
| Other systemd Linux distributions | `steward_<version>_linux_<arch>.tar.gz` | Uses the generic node installer |

The release architectures are `amd64` and `arm64`; RPM metadata maps those to
`x86_64` and `aarch64`. Alpine/OpenRC, macOS, Windows, BSD, and non-systemd Linux are
not advertised as Executor node platforms. The universal archive is a distribution
fallback, not a way to bypass the Linux/systemd/gVisor host contract.

## Guided online install

Download the immutable release asset rather than piping an unreviewed mutable branch
into a root shell:

```console
curl -fsSLo install-steward.sh \
  https://github.com/hardrails/steward/releases/latest/download/install-steward.sh
less install-steward.sh
sudo bash install-steward.sh
```

The interactive flow detects the platform, asks for the release (latest by default),
enrollment URL, two credential files, and CA. It generates the host-local Executor
token when one is not supplied. If Docker does not advertise `runsc`, it asks before
installing gVisor from the official release channel, verifies both gVisor binaries
against their published SHA-512 values, runs `runsc install`, reloads Docker, and
checks that Docker now reports the runtime. It preserves and restores an existing
Docker daemon configuration if registration fails.

After package installation, enrollment is transactional through node preflight:
invalid credentials, modes, CA material, configuration, gVisor, or systemd units
restore the previous `/etc/steward` files. A newly created empty Executor fence is
removed if that same enrollment transaction fails before service start; any
pre-existing fence is never reset or removed. A valid target version is then
activated atomically and the three services are enabled and started. Fresh
configuration also builds the trusted relay from the shipped static binary with
`--network=none`, pins its Docker image digest, and validates the derived topology.

## Unattended install

The same flow has no prompts with `--non-interactive`. Values are file paths, not
secrets on the command line:

```console
sudo bash install-steward.sh \
  --non-interactive \
  --version v1.4.0 \
  --install-gvisor \
  --control-plane-url https://control.customer.example \
  --steward-credential /secure/enrollment/steward.json \
  --executor-credential /secure/enrollment/executor.json \
  --ca-file /secure/enrollment/control-plane-ca.pem
```

This is suitable for cloud-init, Packer, configuration management, or a customer
golden image. Use `--no-start` on an already-stopped node to configure and activate
without starting it, `--stage-only` to install an upgrade without requiring a
running Docker daemon or gVisor and without configuring or activating it, and
`--reuse-configuration` to validate and retain an already-enrolled node during an
upgrade. `--dry-run` resolves the platform plan without root, downloads, or mutation.
Every option has a documented `STEWARD_*` environment equivalent in
`install-steward.sh --help`.

## Air-gapped install

Transfer `install-steward.sh`, `checksums.txt`, and the matching DEB/RPM/archive into
one directory. A checksum proves integrity against the manifest you received; it does
not authenticate who supplied the manifest. Verify the signed outer appliance bundle
and its pinned trust key before importing these files into the facility.

```console
sudo bash install-steward.sh \
  --offline-dir /media/steward-v1.4.0 \
  --control-plane-url https://control.customer.example \
  --steward-credential /media/enrollment/steward.json \
  --executor-credential /media/enrollment/executor.json \
  --ca-file /media/enrollment/control-plane-ca.pem
```

This path makes no Steward network request. If gVisor is not already registered,
also transfer `runsc`, `containerd-shim-runsc-v1`, and their official `.sha512`
files, then add `--install-gvisor --gvisor-dir /media/gvisor`. In unattended mode,
add `--non-interactive`.

For a deliberately staged two-phase rollout, native packages can be installed
directly (`dpkg -i ...deb` or `rpm -Uvh ...rpm`). The universal equivalent remains:

```console
sha256sum -c checksums.txt
tar -xzf steward_v1.4.0_linux_amd64.tar.gz
sudo bash scripts/install-node.sh
```

The installer:

1. requires Linux and an existing Docker group;
2. verifies that all six Steward binaries report the same safe version;
3. creates distinct unprivileged `steward` and `steward-executor` service users,
   adding only the Executor identity to the root-equivalent Docker group;
4. copies immutable binaries under `/opt/steward/releases/<version>` and atomically
   selects all binaries through one `/opt/steward/current` symlink;
5. installs vendor systemd units under `/usr/local/lib/systemd/system` and
   configuration templates without overwriting an operator's existing configuration
   or `/etc/systemd/system` overrides; and
6. leaves services disabled and stopped. Only the top-level guided installer
   proceeds through enrollment, preflight, activation, and explicit enablement.

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

Replace `control.example.invalid` in both `/etc/steward/steward.json` and
`/etc/steward/executor.env`. Install these files from the customer's enrollment and
PKI workflow:

| Path | Owner/mode | Purpose |
| --- | --- | --- |
| `/etc/steward/uplink-credential.json` | `steward:steward`, `0600` | Steward node credential |
| `/etc/steward/executor-uplink.json` | `steward-executor:steward-executor`, `0600` | Executor node credential |
| `/etc/steward/executor-token` | `steward-executor:steward-executor`, `0600` | host-local Executor bearer secret |
| `/etc/steward/control-plane-ca.pem` | `root:root`, `0644` | customer control-plane CA bundle |

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

Preflight checks the real service identities, Docker `runsc`, all three binaries, every
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
sudo /usr/local/libexec/steward/activate-node-release v1.4.0 --restart
sudo /usr/local/libexec/steward/activate-node-release v1.4.0 --restart
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

The guided upgrade equivalent is:

```console
sudo bash install-steward.sh --version v1.4.0 --reuse-configuration
```

## Removal

Use the native package manager (`apt remove steward-node` or
`rpm -e steward-node`) for native installations. Removal stops and disables both
services and removes package-owned integration, but retains enrollment and durable
state. Debian `apt purge` additionally removes `/etc/steward`; it still retains
`/opt/steward` and `/var/lib` because deleting anti-replay or lifecycle state must be
an explicit recovery decision.

For the universal archive, run:

```console
sudo /usr/local/libexec/steward/uninstall-node
```

It retains configuration and state by default. `--purge-config` and `--purge-data`
are separate, explicit destructive acknowledgements.
