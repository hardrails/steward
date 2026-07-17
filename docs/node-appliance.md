---
title: Steward node appliance
description: Linux appliance packaging, installation, enrollment, preflight, activation, rollback, removal, and filesystem ownership.
section: Operator reference
---

# Install the Steward node appliance

Steward ships Linux releases as DEB, RPM, and universal systemd archives. Each
format contains the same seven static binaries, hardened systemd units, fail-closed
configuration templates, and Bash utilities for installation, enrollment,
preflight, activation, rollback, and removal. Release payloads also contain the
`steward-control` binary for version parity and operator tooling. The node package
does not contain its deployment assets, create a controller user, install a
controller unit, or start the controller; use the dedicated controller archive and
installer on its management host.

The node appliance remains independently operated and open source. An operator may
deliver it inside a separate appliance bundle with trust material and approved Open
Container Initiative (OCI) images, but it remains independently downloadable,
buildable, installable, and operable without the bundled controller.

## Host requirements

Staging requires:

- Linux with systemd on `amd64` or `arm64`; and
- one matching Steward release artifact; and
- an existing local `docker` group, normally created by the Docker package. The
  Docker daemon does not need to be running for `--stage-only`.

Activation also requires the Docker daemon and the gVisor sandbox runtime
registered as `runsc`, plus operator-provided enrollment inputs.
The guided installer can install official gVisor, register `runsc`, and generate
the host-local Executor token. Inference, service, connector, or egress topology
requires Docker Engine 28 or newer.

Persistent Docker state is disabled by default. The portable local volume driver
has no hard byte or inode quota, so the compatibility flag that enables state is
limited to a dedicated single-tenant host and requires complete signed admission
with exactly one tenant in verified site policy. Leave it disabled on a shared node.

Steward does not install Docker. It changes Docker configuration only when the
operator approves gVisor registration. No installation path pulls an agent image,
creates a control-plane credential, or trusts an embedded endpoint.

## Artifact matrix

| Target family | Preferred artifact | Installer behavior |
| --- | --- | --- |
| Debian, Ubuntu, derivatives | `steward-node_<version>_<arch>.deb` | Installs with `dpkg` |
| RHEL, Rocky, Alma, CentOS Stream, Fedora, Amazon Linux, Oracle Linux, SUSE | `steward-node_<version>_<arch>.rpm` | Installs with `rpm` |
| Other systemd Linux distributions | `steward_<version>_linux_<arch>.tar.gz` | Uses the generic node installer |

Published architectures are `amd64` and `arm64`; RPM names them `x86_64` and
`aarch64`. Alpine/OpenRC, macOS, Windows, BSD, and non-systemd Linux are not
supported Executor node platforms. The universal archive does not bypass the
Linux, systemd, Docker, or gVisor requirements.

## Guided online install

Download the current release installer instead of piping a branch into a root
shell:

```console
curl --proto '=https' --tlsv1.2 -fsSLo install-steward.sh \
  https://github.com/hardrails/steward/releases/latest/download/install-steward.sh
less install-steward.sh
sudo install -d -o root -g root -m 0700 /root/steward-install
sudo install -o root -g root -m 0700 install-steward.sh \
  /root/steward-install/install-steward.sh
sudo /bin/bash -p /root/steward-install/install-steward.sh
```

The `latest` URL changes when a new release is published. For a reproducible
install, select an exact tag and authenticate its checksum or signed outer bundle
through your own trust process before running the installer.

The interactive installer detects the platform and offers a local-only node,
remote enrollment, or staging without activation. Bundled-controller enrollment
requests the control-plane URL, node-scoped Executor credential, CA, and signed
admission trust material. A compatible external controller may also supply a
generic supervisor credential. The installer generates a host-local Executor token
unless one is supplied.

If Docker does not report `runsc`, the installer asks before downloading official
gVisor binaries. It verifies both binaries against their published SHA-512 values,
runs `runsc install`, reloads Docker, and confirms runtime registration. If
registration fails, it restores the previous Docker daemon configuration.

The online path downloads each binary and checksum file from Google-hosted gVisor
release storage. Because both come from the same release channel, the checksum
detects transfer or file mismatch but does not independently authenticate the
release. The default `latest` selector can change. Pin `--gvisor-version` to a dated
release for reproducible installation, or transfer independently authenticated
files and use `--gvisor-dir`.

Enrollment is one transaction: a failure in credentials, permissions, CA
material, configuration, gVisor, or systemd validation restores the previous
`/etc/steward` files. If this transaction created new empty admission-fence,
operation-journal, or evidence files, it removes those files and the new receipt key
before service start. It never resets or removes an existing control store. After
successful preflight, the installer selects the complete target release and enables
all three services. With complete signed admission, it also
builds the trusted relay from the shipped static binary using `--network=none`,
pins the local Docker image ID and relay-binary SHA-256, and validates the
Gateway/relay configuration and host prerequisites. Per-workload networks and
relays are created only during admission.

Rollback covers handled installer errors, not an uncatchable `SIGKILL` or host
power loss during node configuration. After either event, keep the node services
stopped and follow an approved whole-configuration recovery. A rerun does not
prove that it restored every pre-change file; do not delete fencing, journal, or
evidence state to force activation.

## Unattended install

Use `--non-interactive` for cloud-init, Packer, configuration management, or a
golden image. Pass secret file paths, not secret values. Stage those files under a
root-owned, non-writable directory such as `/secure/enrollment`; the installer
rejects credentials or policy beneath a writable or non-root-owned ancestor.

```console
RELEASE_TAG="<release-tag>"
sudo /bin/bash -p /root/steward-install/install-steward.sh \
  --non-interactive \
  --version "$RELEASE_TAG" \
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

Related modes:

- `--no-start` configures and activates an already-stopped node without starting
  its services.
- `--stage-only` installs an inactive release without requiring a running Docker
  daemon or gVisor and without configuring or activating it.
- `--reuse-configuration` validates and keeps an enrolled node's current
  configuration during upgrade.
- `--dry-run` resolves the platform plan without root, downloads, or changes.

`install-steward.sh --help` lists automation inputs with `STEWARD_*` environment
equivalents. Mode and inspection switches remain command-line flags.

## Air-gapped install

Transfer `install-steward.sh`, `checksums.txt`, and the matching package or archive
into one directory. A checksum detects changes relative to the received manifest;
it does not authenticate the manifest's source. Verify the signed outer appliance
bundle and its pinned trust key before importing files into the facility. Then copy
the selected files and enrollment material into root-owned directories; do not run
an installer or read a secret directly from removable media.

```console
RELEASE_TAG="<release-tag>"
sudo /bin/bash -p "/root/steward-$RELEASE_TAG/install-steward.sh" \
  --offline-dir "/root/steward-$RELEASE_TAG" \
  --control-plane-url https://control.customer.example:8443 \
  --executor-credential /root/steward-enrollment/executor-node.json \
  --ca-file /root/steward-enrollment/control-plane-ca.pem \
  --admission-policy /root/steward-enrollment/site-policy.dsse.json \
  --site-root-public-key /root/steward-enrollment/site-root.public \
  --site-root-key-id site-root-1 \
  --node-id node-a \
  --executor-evidence-config /root/steward-enrollment/executor-evidence.env \
  --executor-evidence-private-key /root/steward-enrollment/node-receipts.private.pem \
  --executor-evidence-public-key /root/steward-enrollment/node-receipts.public
```

The installer makes no artifact-download request in this mode. Once it starts an
enrolled node, the services connect to the configured control plane, which must be
reachable inside the air gap. Add `--no-start` if the services must remain offline.
If `runsc` is not registered, also transfer `runsc`,
`containerd-shim-runsc-v1`, and their official `.sha512` files. Add
`--install-gvisor --gvisor-dir /root/steward-gvisor`; also add `--non-interactive` for
unattended use.

To stage native packages directly, use `dpkg -i ...deb` or `rpm -Uvh ...rpm` only
after authenticating and root-staging the exact package. For the universal archive,
use `install-steward.sh`; its bounded archive inspection rejects special files,
path traversal, link entries, oversized metadata, and extraction bombs before any
payload becomes executable. A raw `tar -xzf` is not an equivalent trust boundary.

Use a dedicated node with no human or unrelated service account in the `docker`
group, and no account using that group as its primary group. Docker-group access
can control the daemon and is therefore root-equivalent. Check the host with
`getent group docker` and the local account database before installation. Move
administrative Docker work to audited `sudo` or root workflows and remove stale
memberships with the operating system's account-management tools. Log out affected
sessions before installing so old group credentials are not retained. Steward
then makes `steward-executor` the sole Docker-group member; it fails closed instead
of preserving broader socket authority.

The node installer:

1. requires Linux and an existing Docker group;
2. requires the expected release tag, then verifies that `release.json` binds that
   tag, Linux architecture, all seven binaries, and every host-integration asset;
3. verifies that all seven binaries report the expected release tag;
4. creates unprivileged `steward`, `steward-executor`, and `steward-gateway`
   users, requiring Executor to be the Docker group's only member;
5. installs the root-owned binaries, units, helper scripts, templates, and manifest
   under `/opt/steward/releases/<version>` and selects the first release through
   `/opt/steward/current`;
6. creates stable binary, helper, and systemd-unit links that resolve through
   `/opt/steward/current`, without replacing existing configuration or modified
   `/etc/systemd/system` overrides; and
7. leaves services disabled and stopped. Only the guided installer continues
   through enrollment, preflight, activation, and enablement.

The installer automatically migrates an exact legacy unit created by the
prototype installer. If an `/etc/systemd/system` full-unit override differs, it
stops and asks the operator to move local settings into
`/etc/systemd/system/<unit>.d/*.conf`. It never deletes or shadows that override.

The service accounts divide authority. `steward` cannot read the Docker socket.
Executor can access that root-equivalent socket, but its unit grants no Linux
capabilities and applies filesystem, device, namespace, kernel, home, and
privilege restrictions. Gateway owns route credentials and uses narrow local
interfaces to reach Executor and per-instance relays; it cannot read Docker.
Agent containers never receive the socket.

## Provision trust material

Obtain these files from the operator's enrollment and public-key infrastructure
(PKI) workflow. `configure-node` installs fixed ownership and modes; do not edit
generated configuration in place.

| Path | Owner/mode | Purpose |
| --- | --- | --- |
| `/etc/steward/uplink-credential.json` | `steward:steward`, `0600` | Steward node credential |
| `/etc/steward/executor-uplink.json` | `steward-executor:steward-executor`, `0600` | Executor tenant- or node-scoped credential |
| `/etc/steward/executor-token` | `steward-executor:steward-executor`, `0600` | Host-local Executor bearer secret |
| `/etc/steward/control-plane-ca.pem` | `root:root`, `0644` | Control-plane CA bundle |
| `/etc/steward/site-policy.dsse.json` | `root:steward-executor`, `0640` | Signed tenant, publisher, and command-key policy |
| `/etc/steward/site-root.public` | `root:root`, `0644` | Site-root verification key |

The explicit control-plane CA bundle replaces the host's system roots for Steward
uplink connections. It is not appended to the public Web PKI roots.

Signed admission means Executor verifies a site-root-signed DSSE (Dead Simple
Signing Envelope) policy before it accepts tenant authority. A node-scoped
Executor credential has
`{"version":2,"scope":"node","node_id":"...","credential":"..."}` and no
`tenant_id`. Executor accepts it only when:

- signed admission is complete;
- its `node_id` exactly matches the admitted node;
- the signed site policy contains at least one site cleanup command key; and
- the uplink uses HTTPS with certificate verification.

Tenant keys authorize normal operations. The site cleanup key authorizes only
stop, destroy, and purge, so an operator can remove abandoned workloads after
tenant access is revoked. Configure the node in one fail-closed transaction:

```console
sudo /usr/local/libexec/steward/configure-node \
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

The transaction verifies trust before deriving relay topology or activating the
credential. If later preflight fails, it rolls back configuration and newly
created fences, journal, evidence, and keys. It never resets existing identity
state. Private signing keys stay on a trusted signing station or separate signing
service, outside the controller and node. A legacy
tenant-scoped Executor credential remains available for a single-tenant node but
does not enable multi-tenant commands. See [Signed admission]({{ '/guides/signed-admission/' | relative_url }})
and [Executor uplink]({{ '/executor/' | relative_url }}#outbound-executor-uplink).

For a node-scoped credential, `configure-node` selects Executor uplink protocol 4,
which reports a bounded typed admission result to the controller. If the controller
supports only the durable lease protocol, add
`--executor-uplink-protocol-version 3`. Local and tenant-scoped configurations use
the safe compatibility value `0` and cannot select 3 or 4.

With protocol 4 and the packaged Gateway topology, Executor also advertises the
closed `activation-canary-v1` capability. It accepts only Steward's fixed,
tenant-signed Hermes workspace-audit task—not a URL, shell command, free-form
prompt, or generic workflow step. The capability disappears while a canary is
active, but containment commands continue through the normal poller.

`configure-node` validates the enrollment evidence sidecar, imports the exact
receipt key used during enrollment, and initializes the durable command and
signed-admission fences, plus the empty operation journal and evidence chain. A
fence is durable high-water state that rejects replayed commands or policies. For a
manual configuration, initialize the uplink fence exactly once as the service user:

```console
sudo -u steward-executor /usr/local/bin/steward-executor \
  -initialize-uplink-state \
  -uplink-state-file /var/lib/steward-executor/uplink-state.json
```

Ordinary startup fails if the fence is missing. Initialization fails if one
already exists, preventing silent loss of anti-replay state.

Current uplink state is keyed by tenant and instance. A tenant-unaware legacy
file never migrates automatically. Stop Executor, then bind every entry to the
single tenant that owned the node:

```console
sudo -u steward-executor /usr/local/bin/steward-executor \
  -migrate-uplink-state-v1-tenant tenant-a \
  -uplink-state-file /var/lib/steward-executor/uplink-state.json
```

Migration retains the original as `uplink-state.json.v1.bak` and refuses to
overwrite that backup. Preserve both files. Never restore the tenant-unaware
backup over current state.

## Preflight and activation

Run preflight and enable the services as root:

```console
sudo /usr/local/libexec/steward/node-preflight
sudo systemctl enable --now steward-gateway steward steward-executor
```

Preflight checks the actual node service identities, Docker `runsc`, all seven binaries,
required Executor settings, credential/state/CA readability and permissions,
Gateway receipt-key ownership, and all three systemd units. Binary configuration
checks do not bind a listener or start an uplink poll. They inspect existing durable
files through read-only file descriptors and leave prospective Gateway state,
audit, and connector receipt paths absent. Executor requires its admission fence,
journal, and evidence chain to be initialized before preflight because silently
replacing any of them would weaken rollback protection or audit continuity.

The appliance sets `enable_process_exec: false`, so `steward` remains a status
tracker. Untrusted workloads run only through Executor and gVisor.

## Upgrade and rollback

Installing another release preserves configuration and prior binary directories.
The first install selects the complete release so the disabled node can be
configured. Later installs verify and stage a new immutable release without changing
the active binaries, helper scripts, or systemd units. Staging does not reload
systemd or restart services.

```console
TARGET_RELEASE_TAG="<release-tag>"
PRIOR_RELEASE_TAG="<release-tag>"
sudo "/opt/steward/releases/$TARGET_RELEASE_TAG/integration/scripts/activate-node-release.sh" \
  "$TARGET_RELEASE_TAG" --restart
sudo /usr/local/libexec/steward/activate-node-release \
  "$PRIOR_RELEASE_TAG" --restart
```

Forward activation uses the target helper; rollback uses the active helper so the
newest transaction and state-format checks remain in force. A release transition
requires no managed agent or relay container and no capability network, including
stopped containers. It also rejects live fences, pending journal operations, and
retained Gateway grants. Retained state volumes are allowed.

With `--restart`, activation records service state, stops Gateway, Steward, and
Executor in that order, and validates the target manifest and durable formats. When
Gateway and relay support is configured, it also builds and preflights a
release-bound relay image without network access. It switches the active-release
symlink and relay binding, reloads systemd, and restarts only services that were
active. `--no-restart` requires all three services to be inactive. State,
credentials, audit logs, prior relay bindings, and Executor fences remain outside
release directories and survive either direction.

If preflight requires Executor uplink-state migration, do not delete or reset the
file. Stop Executor, run the target binary with
`-migrate-uplink-state-v1-tenant`, verify `.v1.bak`, and retry activation. The
operator must supply the tenant; package activation never guesses it. Because
activation preserves the service state recorded at its start, it will not restart
an Executor that was already stopped. Restore its intended state only after
activation succeeds.

Release rollback verifies and restores the selected release's units, helper scripts,
and relay binding, but it is not state rollback. A target without explicit
durable-format reader ranges is not eligible. Preserve `/var/lib/steward`,
`/var/lib/steward-executor`, `/var/lib/steward-gateway`,
`/var/lib/steward-node`, `/var/log/steward`, and `/etc/steward`. Deleting or
restoring them changes lifecycle, route commitments, audit, identity, or anti-replay
state and needs a separate operator-approved recovery procedure.

The delivery ledger has a specific one-way transition. Upgrade inspection leaves a
format-2 or format-3 `uplink-delivery-state.json` unchanged, while normal Executor
startup atomically migrates it to format 4 before polling. After that startup, a
prior release limited to format 2 or 3 is not eligible for software rollback, even
if the ledger is empty. Draining the node does not downgrade the file.

The guided upgrade is:

```console
RELEASE_TAG="<release-tag>"
sudo /bin/bash -p /root/steward-install/install-steward.sh \
  --version "$RELEASE_TAG" --reuse-configuration
```

## Removal

Package removal and the archive uninstaller refuse to proceed while a managed agent
container, relay container, or capability network remains; stopped containers also
count. Destroy workloads through Steward before removing the node software. Do not
delete Docker objects by hand because the durable fences and receipts would no
longer match observed state.

For native packages, run `apt remove steward-node` or `rpm -e steward-node`.
Removal stops and disables all three services and removes package-owned
integration while retaining enrollment and durable state. Debian `apt purge`
also preserves `/etc/steward`: package removal is not node-identity retirement, and
deleting keys without their evidence and fences would leave state that cannot be
reopened safely.

On a signed-admission node, the receipt private key under `/etc/steward` and the
evidence chain under `/var/lib/steward-executor` are one cryptographic identity.
Deleting either side alone prevents a later Executor from reopening that evidence.
The package lifecycle therefore never performs a partial identity purge.

For the universal archive:

```console
sudo /usr/local/libexec/steward/uninstall-node
```

It retains configuration and data by default. Explicit node retirement requires
`--purge-config --purge-data` together. The helper refuses either option alone and
also requires every Steward-managed state volume to be removed first.
