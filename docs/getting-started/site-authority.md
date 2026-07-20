---
title: Create a site authority
description: Generate and verify the signed policy, tenant keys, public node trust, and Control TLS material for a new Steward site without putting tenant private keys in Control.
section: Getting started
---

# Create a site authority

A Steward site needs several independent authorities. The site root signs policy.
A publisher signs workload capsules. A tenant command key authorizes lifecycle
changes, while a separate task key authorizes exact requests to an agent service.
An incident-response key can stop or remove workloads but cannot admit or start
them. Control uses a different TLS certificate and never receives those tenant
private keys.

Creating these files manually is error-prone. `stewardctl site init` generates a
valid initial policy and all required key pairs as one atomic, owner-only package.
It also signs an inventory that binds every generated file, SHA-256 digest,
classification, and expected mode.

## Create the package

Run this command on a trusted operator workstation, not on an agent node:

```console
stewardctl site init steward-site \
  -site-id site-a \
  -tenant-id tenant-a \
  -repository registry.internal/agents \
  -service-id agent-api \
  -control-server-names control.customer.example,10.40.0.10
```

The output is JSON so automation can retain the policy digest and site-root public
key digest. The directory is created only after all keys, certificates, policy,
and inventory have been generated successfully. An existing target is never
overwritten.

Use `-dry-run` to validate names and see the planned custody steps without writing
files:

```console
stewardctl site init steward-site \
  -site-id site-a \
  -tenant-id tenant-a \
  -control-server-names control.customer.example \
  -dry-run
```

The default repository is `steward.local/agents`, the default service is
`agent-api`, and the default TLS names are loopback-only. Supply the actual Control
hostname or IP address before a remote deployment. The generated resource ceiling
is 512 MiB, 1 CPU, and 128 processes. Review and replace the signed policy when the
site needs different limits or additional tenants.

## Separate custody before use

The package starts in one protected directory so it can be generated and verified
atomically. That is a handoff state, not the intended long-term custody model.

| File | Intended custody |
| --- | --- |
| `private/site-root.private.pem` | Offline site policy authority |
| `private/publisher.private.pem` | Offline or isolated release publisher |
| `private/site-cleanup.private.pem` | Separate incident-response system |
| `private/tenant-command.private.pem` | Tenant-owned lifecycle signing service |
| `private/tenant-task.private.pem` | Tenant-owned task signing service |
| `private/control-ca.private.pem` | Offline Control certificate authority |
| `private/control-server.private.pem` | Steward Control host only |
| `public/site-policy.dsse.json` and `public/site-root.public` | Every enrolled Executor node |
| `public/control-ca.pem` | Operators and nodes that connect to Control |

Do not copy the whole directory to Control or a node. Do not put private keys in
Terraform state, cloud-init, instance metadata, an agent image, the React console,
or a CLI context. A CLI context stores only a path to a key that the current user
is already allowed to read.

## Verify before distributing files

Verify the package in place:

```console
stewardctl site verify steward-site
```

Verification checks the signed inventory, every recorded digest and file mode,
the signed site policy, and the site and tenant identities. It also rejects files
that were added without being named in the signed inventory.

For a later verification, pin a site-root public key obtained through a separate
trusted channel:

```console
stewardctl site verify steward-site \
  -site-root-public-key /secure/checkpoints/site-a-root.public
```

Without that independent pin, verification proves internal consistency but cannot
detect replacement of the entire package by an attacker who also controls its
private site-root key. Retain the printed root digest in a separate system.

## Add a protected external action

To prepare one tenant-owned action key at creation time, name the connector:

```console
stewardctl site init steward-site \
  -site-id site-a \
  -tenant-id tenant-a \
  -connector-id github-issues \
  -control-server-names control.customer.example
```

The generated policy requires an exact signed action permit for that connector by
default. `-authorized-effects optional` permits each admitted instance to choose
standard or authorized mode; use it only when that downgrade is intentional. The
private action key belongs in the tenant approval system, not Gateway. Gateway
receives only `public/tenant-action.public` and the separately materialized
upstream API token.

Continue with [installing Steward Control]({{ '/guides/control-plane/' |
relative_url }}), [enrolling a node]({{ '/getting-started/enroll/' | relative_url
}}), and [building an agent application]({{ '/guides/build-agents/' |
relative_url }}).
