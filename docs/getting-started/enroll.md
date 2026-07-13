---
title: Enroll and activate a Steward node
description: Configure a staged Steward node with operator-owned control-plane credentials, initialize anti-replay state, validate preflight, and start its services.
section: Getting started
---

# Enroll and activate a Steward node

Enrollment connects a staged node to your control plane. Your control plane or
public key infrastructure (PKI) must issue the identities, trust roots, and
certificate authority (CA) bundle; Steward does not create them.

## Enrollment inputs and generated files

Supply these files for every remote enrollment. The installer copies them to the
paths shown with the listed ownership:

| Installed path | Owner and mode | Supplied input |
| --- | --- | --- |
| `/etc/steward/uplink-credential.json` | `steward:steward`, `0600` | Supervisor uplink identity |
| `/etc/steward/executor-uplink.json` | `steward-executor:steward-executor`, `0600` | Executor tenant- or node-scoped uplink identity |
| `/etc/steward/control-plane-ca.pem` | `root:root`, `0644` | Control-plane CA bundle |

Signed multi-tenant admission also requires:

| Installed path | Owner and mode | Supplied input |
| --- | --- | --- |
| `/etc/steward/site-policy.dsse.json` | `root:steward-executor`, `0640` | Site-root-signed tenant, publisher, and command-key policy |
| `/etc/steward/site-root.public` | `root:root`, `0644` | Base64 Ed25519 site-root public key |

The installer generates the host-local Executor API token when it is omitted. For
signed admission, it also generates the node receipt key. These are node-local
secrets, not control-plane enrollment inputs.

## Preferred enrollment path

Run the installer again with the enrollment files. It applies the changes as one
transaction and restores the previous `/etc/steward` state if validation fails:

```console
sudo bash install-steward.sh \
  --non-interactive \
  --control-plane-url https://control.customer.example \
  --steward-credential /secure/enrollment/steward.json \
  --executor-credential /secure/enrollment/executor-node.json \
  --ca-file /secure/enrollment/control-plane-ca.pem \
  --admission-policy /secure/enrollment/site-policy.dsse.json \
  --site-root-public-key /secure/enrollment/site-root.public \
  --site-root-key-id site-root-1 \
  --node-id node-a
```

The script generates an omitted host-local Executor token or receipt key. It
initializes both anti-replay stores once, validates policy before configuring the
Gateway and relay, checks all six binaries and three service identities, then starts
the services. Executor creates per-workload networks later during admission. Failure
restores prior configuration and removes only state created by this transaction;
existing generation fences, the operation journal, and evidence remain intact.

## Multi-tenant Executor enrollment

Use a node-scoped Executor credential for multiple tenants on one host:

```json
{"version":2,"scope":"node","node_id":"node-a","credential":"<opaque-bearer>"}
```

This credential authenticates the connection, not a tenant. Executor requires the
same signed-admission node ID, a verified policy with a site cleanup command key,
and verified HTTPS. Tenant keys sign normal remote commands as DSSE envelopes,
which wrap a typed JSON statement and its signature. A site cleanup key may
authorize only stop, destroy, or purge. Each statement binds tenant, node, instance,
runtime, generations, sequence, and a short validity window.

Pass the node-scoped credential and all signed-admission inputs to one installer or
`configure-node` command. Tenant and cleanup authority must be valid before the
remote credential becomes active, and `node_id` must match it. A legacy
tenant-scoped credential may omit signed admission but can act only for its tenant.

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
