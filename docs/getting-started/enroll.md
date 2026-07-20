---
title: Enroll and activate a Steward node
description: Configure a staged Steward node with operator-owned control-plane credentials, initialize anti-replay state, validate preflight, and start its services.
section: Getting started
---

# Enroll and activate a Steward node

Enrollment connects a staged node to Steward Control or a compatible controller.
The bundled controller issues the one-time enrollment and node transport
credential. `stewardctl control pki create` can create a private certificate
authority (CA) and server certificate, or the site can use its existing PKI.
Tenant and site private signing keys remain separate.

## Enrollment inputs and generated files

Supply the Executor credential and CA for every remote enrollment. The generic
supervisor credential is optional and is not used with bundled Steward Control:

| Installed path | Owner and mode | Supplied input |
| --- | --- | --- |
| `/etc/steward/uplink-credential.json` | `steward:steward`, `0600` | Optional compatible-controller supervisor uplink identity |
| `/etc/steward/executor-uplink.json` | `steward-executor:steward-executor`, `0600` | Executor tenant- or node-scoped uplink identity |
| `/etc/steward/control-plane-ca.pem` | `root:root`, `0644` | Control-plane CA bundle |

The installed CA bundle replaces the host's system root set for Steward uplink
connections. Use the private controller CA or the intended public root bundle; it
is not appended to the public Web PKI roots.

Signed multi-tenant admission also requires:

| Installed path | Owner and mode | Supplied input |
| --- | --- | --- |
| `/etc/steward/site-policy.dsse.json` | `root:steward-executor`, `0640` | Site-root-signed tenant, publisher, and command-key policy |
| `/etc/steward/site-root.public` | `root:root`, `0644` | Base64 Ed25519 site-root public key |
| `/etc/steward/node-receipts.private.pem` | `steward-executor:steward-executor`, `0600` | Receipt private key used to prove possession during node enrollment |
| `/etc/steward/node-receipts.public` | `root:root`, `0644` | Matching receipt public key |

The enrollment exchange also emits an owner-only evidence config. The installer
validates its controller ID, node ID, epoch, and public key, then stores the
controller identity and enablement in `/etc/steward/executor.env`; it does not keep
the handoff file. The installer generates the host-local Executor API token when it
is omitted. It generates a receipt key only for flows that did not prove a receipt
identity during control-plane enrollment.

Before invoking either configurator, copy every supplied input into a protected
root-owned directory. Each source must be a root-owned, single-link regular file
under a complete root-owned directory chain that is not group- or world-writable.
Credentials, the evidence config, receipt private key, and an explicit Executor
token must be owner-only. Steward snapshots each source before changing `/etc`;
limits are 64 KiB per uplink credential, 1 MiB for the CA or policy, 16 KiB for the
receipt private key, and 4 KiB for the evidence config, public keys, or Executor
token. Paths in
`/tmp`, user home directories, writable mounts, and removable media are rejected
even when the file itself has restrictive permissions.

## Preferred enrollment path

Run the installer again with the enrollment files. It applies the changes as one
transaction and restores the previous `/etc/steward` state if validation fails:

```console
sudo /bin/bash -p /root/steward-install/install-steward.sh \
  --non-interactive \
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

With no `--steward-credential`, the installer selects bundled-controller mode:
Executor polls remotely through protocol version 3, while the generic supervisor
remains loopback-only with process execution disabled. Supplying a supervisor
credential retains the compatible external-controller path.

The script generates an omitted host-admin Executor token and creates narrower
operator and observer tokens. For control-plane
enrollment it imports the exact receipt key that signed the enrollment proof;
changing that key is rejected. It initializes both anti-replay stores once,
validates policy before configuring the Gateway and relay, checks all seven
binaries and three node service identities, then starts the services. Executor
creates per-workload networks later during admission. Failure restores prior
configuration and removes only state created by this transaction; existing
generation fences, the operation journal, and evidence remain intact.

That rollback covers handled process errors. `SIGKILL` or power loss can interrupt
the node configurator between filesystem changes because this path has no durable
installer journal. Keep all three node services stopped and use an approved
whole-configuration recovery before retrying; rerunning does not automatically
restore the pre-change files. Never delete or recreate fencing, journal, or
evidence state to make preflight pass.

The path above is the protected copy created by the
[getting-started install flow]({{ '/getting-started/' | relative_url }}). If a
different system delivered the installer, authenticate it and copy it into an
equivalent root-owned `0700` directory before root executes it.

## Multi-tenant Executor enrollment

Use a node-scoped Executor credential for multiple tenants on one host:

```json
{"version":2,"scope":"node","node_id":"node-a","credential":"<opaque-bearer>"}
```

This credential authenticates the connection, not a tenant. Executor requires the
same signed-admission node ID, a verified policy with a site cleanup command key,
and verified HTTPS. Tenant keys sign normal remote commands as DSSE envelopes,
which wrap a typed JSON statement and its signature. A site cleanup key may
authorize only stop, destroy, purge, or snapshot deletion. Each statement binds tenant, node, instance,
runtime, generations, sequence, and a short validity window.

Pass the node-scoped credential, evidence config, receipt key pair, and all
signed-admission inputs to one installer or `configure-node` command. Tenant and
cleanup authority must be valid before the remote credential becomes active, and
the credential, evidence config, and admitted `node_id` must match. Executor then
publishes authenticated evidence checkpoints independently from command polling.
A controller outage does not stop local enforcement; the signed local chain remains
the durable outbox until delivery resumes. A legacy
tenant-scoped credential may omit signed admission but can act only for its tenant.
Node-scoped enrollment selects uplink protocol 4 automatically. Add
`--executor-uplink-protocol-version 3` to `configure-node` only for a controller
that has not implemented protocol 4's typed admission projection.

When the same node has the complete packaged Gateway and relay configuration,
protocol 4 also enables the closed release-selected agent activation canary. Executor advertises
that capability only when it can enforce the signed runtime, task permit, Gateway
receipt authority, and activation-checkpoint boundary locally.

## Verify the active node

```console
sudo /usr/local/libexec/steward/node-doctor
journalctl -u steward -u steward-executor -u steward-gateway --since -10m --no-pager
```

The doctor includes preflight validation, then checks the configured Docker target,
gVisor, active units, health and readiness, Gateway, durable-store utilization, and
filesystem headroom. Use `--json` for automation. The supervisor and Executor poll
outbound by default. Executor keeps its bearer-protected `127.0.0.1:8090` API for
`stewardctl` and Model Context Protocol (MCP) clients; Gateway remains host-local.

## Anti-replay state is identity state

Executor prevents replay by storing the highest accepted claim generation, instance
generation, and command sequence for each `(tenant_id, instance_id)` in
`/var/lib/steward-executor/uplink-state.json`. The installer initializes it exactly
once. Startup fails if it disappears; initialization will not overwrite it. Deleting
or restoring it during application rollback can invalidate command ordering.

A tenant-unaware legacy state file is not upgraded automatically. Stop Executor and
run the explicit migration:

```console
sudo -u steward-executor /usr/local/bin/steward-executor \
  -migrate-uplink-state-v1-tenant tenant-a \
  -uplink-state-file /var/lib/steward-executor/uplink-state.json
```

Verify and retain the resulting `.v1.bak` before restarting. The command will not
guess the tenant, overwrite the backup, or migrate a current-format file.

See [instance-generation fencing]({{ '/instance-generation-fencing/' | relative_url }})
for the complete protocol behavior.
