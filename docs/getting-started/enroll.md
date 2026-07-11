---
title: Enroll and activate a Steward node
description: Configure a staged Steward node with operator-owned control-plane credentials, initialize anti-replay state, validate preflight, and start its services.
section: Getting started
---

# Enroll and activate a Steward node

Enrollment binds a staged node to an independently operated control plane. Steward
does not create identities or trust roots; your control plane or PKI workflow must
issue them.

## Required files

| Path | Owner and mode | Purpose |
| --- | --- | --- |
| `/etc/steward/uplink-credential.json` | `steward:steward`, `0600` | Supervisor uplink identity |
| `/etc/steward/executor-uplink.json` | `steward-executor:steward-executor`, `0600` | Executor uplink identity |
| `/etc/steward/executor-token` | `steward-executor:steward-executor`, `0600` | Host-local API bearer token |
| `/etc/steward/control-plane-ca.pem` | `root:root`, `0644` | Control-plane CA bundle |

## Preferred enrollment path

Run the release installer again and supply enrollment files. It stages changes
transactionally and restores the previous `/etc/steward` state if preflight fails:

```console
sudo bash install-steward.sh \
  --control-plane-url https://control.customer.example \
  --steward-credential /secure/enrollment/steward.json \
  --executor-credential /secure/enrollment/executor.json \
  --ca-file /secure/enrollment/control-plane-ca.pem
```

The script securely generates the host-local Executor token when omitted, initializes
the new Executor command fence once, validates both service identities and every
configuration file, then enables and starts both services.

## Verify the active node

```console
sudo /usr/local/libexec/steward/node-preflight
systemctl is-active steward steward-executor
journalctl -u steward -u steward-executor --since -10m --no-pager
```

Preflight checks the actual installed units, configuration, file ownership,
credentials, Docker socket access, and gVisor registration. The two services run in
outbound-only mode by default; an inactive local listener is not a failure.

## Anti-replay state is identity state

Executor records the highest accepted command generation and sequence in
`/var/lib/steward-executor/uplink-state.json`. The installer initializes it exactly
once. Normal startup fails if it disappears, and initialization refuses to overwrite
it. Do not delete or restore this file as part of an application rollback; doing so
can invalidate the node's command-ordering guarantee.

See [instance-generation fencing]({{ '/instance-generation-fencing/' | relative_url }})
for the complete protocol behavior.
