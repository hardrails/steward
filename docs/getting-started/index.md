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

Remote activation through bundled Steward Control needs its HTTPS URL, one
node-scoped Executor credential, and certificate authority (CA) certificate.
Multi-tenant enrollment also needs a signed site policy, site-root public key and
key ID, and the stable node ID in the credential. A compatible external controller
may additionally supply a generic supervisor credential. Choose **stage only** to
install without enrollment inputs.

## Run the guided installer

Paste this command in the server's terminal:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/hardrails/steward/releases/latest/download/install-steward.sh | sudo /bin/bash -p
```

Keep `/bin/bash -p` in this command. Privileged Bash mode prevents the root
installer from loading user-controlled startup files or imported shell functions
before its own checks run. The installer refuses an explicit non-privileged Bash
invocation.

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
steward-control -version
steward-executor -version
steward-gateway -version
steward-relay -version
steward-storage-zfs -version
stewardctl -version
steward-mcp -version
```

Every binary must report the same release. Then verify the mode you selected.
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
requires the three core systemd services to be active, probes supervisor and Executor
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

The node-doctor canary verifies the signed-task path. Keep its task signing key
off-node, preserve the exact bundle for recovery, and verify Gateway receipts
offline after the run.

## Inspect before piping to root

The single command trusts the fetched script before inspection. For higher
assurance, download and review it first:

```console
curl --proto '=https' --tlsv1.2 -fsSLo install-steward.sh \
  https://github.com/hardrails/steward/releases/latest/download/install-steward.sh
less install-steward.sh
sudo install -d -o root -g root -m 0700 /root/steward-install
sudo install -o root -g root -m 0700 install-steward.sh \
  /root/steward-install/install-steward.sh
sudo /bin/bash -p /root/steward-install/install-steward.sh
```

The installer verifies its selected package against the release SHA-256 manifest.
For a disconnected or independently authenticated import, follow the
[air-gapped installation guide]({{ '/guides/air-gapped/' | relative_url }}).

## Unattended staging

This prompt-free command installs without requiring a running Docker daemon. It
does not install gVisor, enroll the node, or start services:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/hardrails/steward/releases/latest/download/install-steward.sh | \
  sudo /bin/bash -p -s -- --non-interactive --stage-only
```

For a complete unattended enrollment, pass file paths rather than secret values:

```console
sudo /bin/bash -p /root/steward-install/install-steward.sh \
  --non-interactive \
  --install-gvisor \
  --gvisor-version "<YYYYMMDD-or-YYYYMMDD.N>" \
  --control-plane-url https://control.customer.example:8443 \
  --executor-credential /secure/enrollment/executor-node.json \
  --ca-file /secure/enrollment/control-plane-ca.pem \
  --admission-policy /secure/enrollment/site-policy.dsse.json \
  --site-root-public-key /secure/enrollment/site-root.public \
  --site-root-key-id site-root-1 \
  --node-id node-a \
  --executor-evidence-config /secure/enrollment/executor-evidence.env \
  --executor-evidence-private-key /secure/enrollment/node-receipts.private.pem \
  --executor-evidence-public-key /secure/enrollment/node-receipts.public
```

When `--steward-credential` is omitted, Executor uses Steward Control's signed
delivery protocol. The generic supervisor stays on `127.0.0.1`, keeps durable local
state, and has process execution disabled. Supply `--steward-credential` only for a
compatible controller that also implements the separate generic supervisor uplink.

Run `./install-steward.sh --help` for all automation options and environment
variable equivalents. Continue with
[node enrollment]({{ '/getting-started/enroll/' | relative_url }}) or check the
[platform support matrix]({{ '/reference/platform-support/' | relative_url }}).

For Terraform, use the provided non-secret cloud-init module. Do not put enrollment
credentials in Terraform state. See
[Terraform bootstrap]({{ '/guides/terraform/' | relative_url }}).

## What the installer changes

- Adds dedicated supervisor, Executor, Gateway, and relay-group identities.
- Requires a dedicated host with no existing Docker-group users, then makes
  Executor the group's only member because Docker socket access is root-equivalent.
- Installs each root-owned release under `/opt/steward/releases/`; its
  `release.json` binds every binary and integration file by SHA-256.
- Selects every binary, helper script, and systemd unit through one
  `/opt/steward/current` symlink.
- Installs hardened vendor units and configuration templates with the release.
- Preserves operator-owned configuration and systemd drop-ins.
- Runs preflight and refuses activation if any required check fails.
- With complete signed admission, builds the trusted relay from the shipped static
  binary using `--network=none` and pins its Docker image digest automatically.

It does not install Docker, pull an agent image, invent control-plane credentials,
or embed a vendor control-plane endpoint.

## Do useful work next

Installation establishes the enforcement boundary; it does not invent authority
for an agent. Create the site's signed trust package on the operator workstation
before remote enrollment:

```console
stewardctl site init steward-site \
  -site-id site-a \
  -tenant-id tenant-a \
  -control-server-names control.customer.example
stewardctl site verify steward-site
```

The package groups files by public or private handling and signs an inventory over
every byte and expected file mode. It does not copy keys to a node or turn Control
into a tenant signing service. Follow
[Create a site authority]({{ '/getting-started/site-authority/' | relative_url }})
to separate key custody and use the generated inputs.

After Control is installed, use its initial site-administrator token once to
establish routine tenant-scoped access:

```console
stewardctl site connect steward-site \
  -control-url https://control.customer.example:8443 \
  -token-file /secure/control/site-admin.token
```

The command creates the tenant if needed, issues a recoverable tenant operator,
writes its bearer to a new owner-only file outside the signed package, and selects
that least-privilege CLI context. It stores no bearer value in the context or
command output.

Prepare the node handoff from the resulting context without manually copying
trust and enrollment fields:

```console
stewardctl site node prepare steward-site node-a
```

Transfer the resulting owner-only directory to `node-a`, verify it against the
independent site-root pin, and activate it there:

```console
stewardctl site node verify steward-node-node-a \
  -site-root-public-key /secure/checkpoints/site-a-root.public
stewardctl site node activate steward-node-node-a \
  -out /secure/enrollment/node-a
```

Activation retains the node receipt key before the enrollment exchange, so a lost
response is recovered by rerunning the same command rather than creating a second
node identity. Its output supplies the exact installer argument array.

Next, build the Hermes adapter and create its portable
definition. Publish the inspected archive and issue finite controller authority
from the trusted workstation:

```console
stewardctl agent create workspace-auditor -runtime hermes
cd workspace-auditor
stewardctl agent build
stewardctl agent publish ../steward-site \
  -archive /secure/builds/hermes/image.tar
stewardctl agent authorize ../steward-site \
  -controller-public-key /secure/control/controller.public.pem \
  -node-ids node-a
```

On `node-a`, install the built image through the signed import path, place the
bundle where the node operator can read it, and activate the qualified Gateway
service:

```console
sudo stewardctl agent service activate \
  -bundle agent.bundle.json \
  -tenant-id tenant-a \
  -node-id node-a \
  -trust-out /secure/steward/service-trust.json
```

Run the exact `systemctl` activation command returned in the JSON. Transfer the
non-secret trust inventory through an authenticated channel, make Gateway loopback
reachable directly or through SSH, and join the paths to the tenant context:

```console
stewardctl site task connect ../steward-site \
  -trust /secure/steward/service-trust.json \
  -gateway-token-file /secure/steward/gateway-service.token

stewardctl agent apply workspace-auditor
stewardctl task run workspace-auditor \
  "Review the workspace and report one concrete issue"
```

The task command does not put the signing key or Gateway credential in the agent.
It stores only their file paths in the owner-only CLI context, writes the exact
signed task bundle before dispatch, and leaves that bundle available for safe
recovery if the terminal or host fails mid-run.

Follow [Build and run an agent application]({{ '/guides/build-agents/' |
relative_url }}) for the complete adapter, import, deployment, and task workflow.
The explicit context form remains available for automation and installations that
use a separate signing system:

```console
stewardctl context set production \
  -control-url https://control.customer.example:8443 \
  -ca-file /secure/steward/control-ca.pem \
  -token-file /secure/steward/operator.token \
  -tenant-id tenant-a \
  -gateway-token-file /secure/steward/gateway-service.token \
  -service-trust /secure/steward/service-trust.json \
  -task-key /secure/steward/tenant-task.private.pem \
  -task-key-id tenant-task-1

stewardctl task run workspace-auditor \
  -request workspace-audit.request.json \
  -operation-id hermes.run
```
