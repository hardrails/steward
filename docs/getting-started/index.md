---
title: Install Steward on Linux
description: Install Steward interactively or unattended on a systemd Linux server with Docker, optional gVisor setup, preflight validation, and fail-closed staged activation.
section: Getting started
---

# Install Steward on Linux

This tutorial installs the supervisor, Docker/gVisor Executor, hardened systemd
services, configuration templates, preflight checks, and release-selection tools.

## Before you begin

To stage the software, you need:

- a systemd Linux server on `amd64` or `arm64`;
- root or passwordless `sudo` access;
- Docker Engine installed so the local `docker` group exists; and
- public Internet access to GitHub Releases, unless you use the [air-gapped path]({{ '/guides/air-gapped/' | relative_url }}).

Staging does not require a running Docker daemon. Activation requires Docker to be
running and gVisor registered as runtime `runsc`. Inference, service, connector,
and egress networks require Docker Engine 28 or newer. Steward uses Docker's
isolated bridge gateway mode so containers cannot reach host services through the
bridge gateway. A `network=none` workload does not need this Docker feature.

Remote activation needs the control plane's HTTPS URL, two credential files, and
certificate authority (CA) certificate. Choose **stage only** to install without
them. Multi-tenant enrollment also needs a signed site policy, site-root public key
and key ID, and the stable node ID in the node-scoped credential.

## Run the guided installer

Paste this command in the server's terminal:

```bash
curl -fsSL https://github.com/hardrails/steward/releases/latest/download/install-steward.sh | sudo bash
```

The script reads prompts from the terminal even through a pipe. It selects a DEB,
RPM, or universal systemd archive for the host. If Docker lacks `runsc`, it offers
to download, verify, and register official gVisor.

That optional online step downloads gVisor binaries and checksum files from the same
Google-hosted release channel. The checksum detects a mismatch, but it does not
independently authenticate the release, and the default `latest` selector can
change. Pin `--gvisor-version` to a dated release for a reproducible install, or use
independently authenticated files through the
[air-gapped path]({{ '/guides/air-gapped/' | relative_url }}).

For evaluation, accept the default loopback-only option. To install without
configuration or startup, decline both local-only and remote enrollment. Signed
multi-tenant admission is a separate remote-enrollment option.

## Verify the selected installation mode

```console
steward -version
steward-executor -version
steward-gateway -version
steward-relay -version
stewardctl -version
steward-mcp -version
```

All six binaries must report the same release. Then verify the mode you selected.
For a staged, unenrolled install, all services must remain inactive:

```console
systemctl is-active steward steward-executor steward-gateway
```

For the default loopback evaluation or a completed remote enrollment, run the node
doctor:

```console
sudo /usr/local/libexec/steward/node-doctor
```

The default diagnostic is read-only. It runs the installed preflight, pins Docker
inspection to Executor's configured socket, checks Docker Engine 28 and `runsc`,
requires all three systemd services to be active, probes supervisor and Executor
health and readiness, probes Gateway's Unix control socket, and reports fixed-store
and filesystem capacity. `--json` emits bounded `steward.node-doctor.v1` output for
automation. Exit status 0 permits warnings; exit status 1 means at least one check
failed.

### Prove the path with a signed canary

The optional canary is intentionally mutating: it submits one current, one-use
signed lifecycle task and waits for verified terminal bytes. Prepare the bundle on
the trusted signing station, transfer it owner-only, and choose a new result path
under a protected root-owned directory:

```console
sudo install -d -o root -g root -m 0700 /var/lib/steward-node/canary-results
sudo /usr/local/libexec/steward/node-doctor \
  --canary-bundle /root/steward-canary.task.json \
  --canary-result /var/lib/steward-node/canary-results/canary-001.result
```

The result path must be absolute and absent. Its parent and every ancestor must
already exist as root-owned, non-symlink directories that are not group- or
world-writable. A passing canary creates a non-empty owner-only result of at most
1 MiB. The default Gateway token, origin, submit timeout, and wait timeout can be
overridden with `--canary-token-file`, `--canary-gateway-url`,
`--canary-submit-seconds`, and `--canary-wait-seconds`.

A submit timeout is a warning if the subsequent wait recovers the same task. If the
canary fails after submission, the task may still be running. Keep the exact bundle
and wait for it; do not issue a new task ID or mint replacement authority:

```console
sudo stewardctl task wait \
  -bundle /root/steward-canary.task.json \
  -gateway-url http://127.0.0.1:8091 \
  -token-file /etc/steward/gateway-service-token \
  -result-out /var/lib/steward-node/canary-results/canary-001.result \
  -wait-timeout 15m
```

If that result path already exists, inspect and preserve it and choose a different
new path under the same protected parent. Changing the output path does not change
task authority; changing the bundle or task ID does.

## Inspect before piping to root

The single command trusts the fetched script before inspection. For higher
assurance, download and review it first:

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

This prompt-free command installs without requiring a running Docker daemon. It
does not install gVisor, enroll the node, or start services:

```bash
curl -fsSL https://github.com/hardrails/steward/releases/latest/download/install-steward.sh | \
  sudo bash -s -- --non-interactive --stage-only
```

For a complete unattended enrollment, pass file paths rather than secret values:

```console
sudo bash install-steward.sh \
  --non-interactive \
  --install-gvisor \
  --gvisor-version "<YYYYMMDD-or-YYYYMMDD.N>" \
  --control-plane-url https://control.customer.example \
  --steward-credential /secure/enrollment/steward.json \
  --executor-credential /secure/enrollment/executor-node.json \
  --ca-file /secure/enrollment/control-plane-ca.pem \
  --admission-policy /secure/enrollment/site-policy.dsse.json \
  --site-root-public-key /secure/enrollment/site-root.public \
  --site-root-key-id site-root-1 \
  --node-id node-a
```

Run `bash install-steward.sh --help` for all automation options and environment
variable equivalents. Continue with
[node enrollment]({{ '/getting-started/enroll/' | relative_url }}) or check the
[platform support matrix]({{ '/reference/platform-support/' | relative_url }}).

For Terraform, use the provided non-secret cloud-init module. Do not put enrollment
credentials in Terraform state. See
[Terraform bootstrap]({{ '/guides/terraform/' | relative_url }}).

## What the installer changes

- Adds dedicated supervisor, Executor, Gateway, and relay-group identities.
- Gives only Executor membership in the Docker group.
- Installs each root-owned release under `/opt/steward/releases/`; its
  `release.json` binds every binary and integration file by SHA-256.
- Selects all six binaries, helper scripts, and systemd units through one
  `/opt/steward/current` symlink.
- Installs hardened vendor units and configuration templates with the release.
- Preserves operator-owned configuration and systemd drop-ins.
- Runs preflight and refuses activation if any required check fails.
- With complete signed admission, builds the trusted relay from the shipped static
  binary using `--network=none` and pins its Docker image digest automatically.

It does not install Docker, pull an agent image, invent control-plane credentials,
or embed a vendor control-plane endpoint.
