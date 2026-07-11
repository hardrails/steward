---
title: Install Steward on Linux
description: Install Steward interactively or unattended on a systemd Linux server with Docker, optional gVisor setup, preflight validation, and safe staged activation.
section: Getting started
---

# Install Steward on Linux

This tutorial installs the complete Steward node appliance: the lifecycle
supervisor, Docker/gVisor Executor, hardened systemd services, configuration
templates, preflight, and atomic release-management tools.

## Before you begin

You need:

- a systemd Linux server on `amd64` or `arm64`;
- root or passwordless `sudo` access;
- Docker Engine already installed and running; and
- internet access to GitHub Releases, unless you use the [air-gapped path]({{ '/guides/air-gapped/' | relative_url }}).

To fully activate a remotely managed node, you also need a control-plane HTTPS URL,
two enrollment credential files, and the control plane's CA certificate. You can
install without them by choosing **stage only**.

## Run the guided installer

Paste this command in the server's terminal:

```bash
curl -fsSL https://github.com/hardrails/steward/releases/latest/download/install-steward.sh | sudo bash
```

The script reads prompts from the terminal even though its source arrives through a
pipe. It detects the Linux family and selects a DEB, RPM, or universal systemd
archive. If Docker lacks `runsc`, the installer offers to fetch and verify the
official gVisor binaries before registering the runtime.

For a first evaluation without enrollment, answer **no** when asked to configure and
activate the node. The software is installed but both services stay disabled.

## Verify the staged installation

```console
steward -version
steward-executor -version
systemctl status steward steward-executor --no-pager
```

Both binaries should report the same release. Staged services should be inactive;
packages deliberately do not start an unenrolled node.

## Inspect before piping to root

The single-command path is convenient, not the highest-assurance path. To inspect
the script first:

```console
curl -fsSLo install-steward.sh \
  https://github.com/hardrails/steward/releases/latest/download/install-steward.sh
less install-steward.sh
sudo bash install-steward.sh
```

The installer verifies its selected package against the release SHA-256 manifest.
For a disconnected or independently authenticated import, follow the
[air-gapped installation guide]({{ '/guides/air-gapped/' | relative_url }}).

## Unattended staging

This prompt-free command installs the correct artifact but does not require Docker
to be running, install gVisor, configure enrollment, or activate services:

```bash
curl -fsSL https://github.com/hardrails/steward/releases/latest/download/install-steward.sh | \
  sudo bash -s -- --non-interactive --stage-only
```

For a complete unattended enrollment, pass file paths rather than secret values:

```console
sudo bash install-steward.sh \
  --non-interactive \
  --install-gvisor \
  --control-plane-url https://control.customer.example \
  --steward-credential /secure/enrollment/steward.json \
  --executor-credential /secure/enrollment/executor.json \
  --ca-file /secure/enrollment/control-plane-ca.pem
```

Run `bash install-steward.sh --help` for every automation option and environment
equivalent. Continue with [node enrollment]({{ '/getting-started/enroll/' | relative_url }})
or read the [platform support matrix]({{ '/reference/platform-support/' | relative_url }}).

## What the installer changes

- Adds dedicated `steward` and `steward-executor` service identities.
- Gives only Executor membership in the Docker group.
- Installs immutable versions under `/opt/steward/releases/`.
- Selects both binaries through one atomic `/opt/steward/current` symlink.
- Installs hardened vendor units and configuration templates.
- Preserves operator-owned configuration and systemd drop-ins.
- Runs fail-closed preflight before activation.

It does not install Docker, pull an agent image, invent enrollment credentials, or
embed a vendor control-plane endpoint.
