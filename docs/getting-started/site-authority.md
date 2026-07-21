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

The default repository is `steward.local/agents`. The initial policy admits the
qualified `hermes-api` and `openclaw-api` service identities, and the default TLS
names are loopback-only. Supply the actual Control hostname or IP address before a
remote deployment. The generated resource ceiling is 1 GiB, 1 CPU, and 256
processes, which matches the generated agent project. Review and replace the signed
policy when the site needs different limits, services, or tenants. Use
`-service-ids` to choose a comma-separated service set.

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
is already allowed to read. The composed publication and authorization commands
read the generated publisher and tenant-command keys from this protected handoff
package. Copy those roles into their intended long-term custody before deleting or
archiving the handoff; use the lower-level signing commands when the keys must stay
in a separate signing system.

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

## Prepare one node without assembling files by hand

After Control is installed and its initial site-administrator token is in an
owner-only file, use that broad credential once to establish the tenant's routine
operator context:

```console
stewardctl site connect steward-site \
  -control-url https://control.customer.example:8443 \
  -token-file /secure/control/site-admin.token \
  -site-root-public-key /secure/checkpoints/site-a-root.public
```

`site connect` verifies the complete signed package, checks the independent root
pin, creates the initial tenant if needed, and idempotently issues a
`tenant_operator` credential. It writes the new bearer to
`site-a-tenant-a-operator.token` beside the site directory by default, then saves
and selects the `site-a-tenant-a` CLI context. The context contains only file paths
and scoped defaults; neither bearer is printed, and the site-administrator bearer
is not retained in the new context.

An exact retry recovers the same Control credential. A different token already at
the output path or different Control authority already under the context name
causes a closed failure instead of replacement. Use `-operator-token-out` or
`-context` to choose explicit locations and names.

Then prepare a finite handoff for one node from that tenant-scoped context:

```console
stewardctl site node prepare steward-site node-a \
  -site-root-public-key /secure/checkpoints/site-a-root.public
```

This command verifies the complete site package, checks the independent root pin,
confirms the initial tenant in Control, and requests one short-lived node
enrollment. It publishes `steward-node-node-a` only after the complete output
passes verification.

The handoff contains:

- the original site-root-signed inventory;
- the exact signed policy, site-root public key, and Control CA named by that
  inventory;
- one owner-only enrollment capability; and
- a strict manifest binding the site, tenant, node, Control instance, expiry, and
  enrollment digest.

It does not contain any site, publisher, tenant, action, incident-response, or
Control private key. The enrollment capability is still a bearer secret until it
expires or is consumed. Transfer the whole owner-only directory through an
authenticated confidential channel.

On the destination node, verify it again. Use the same independently obtained root
pin when the transfer channel is not itself the trust root:

```console
stewardctl site node verify steward-node-node-a \
  -site-root-public-key /secure/checkpoints/site-a-root.public
```

Activate it before the printed expiry:

```console
stewardctl site node activate steward-node-node-a \
  -out /secure/enrollment/node-a
```

Activation creates the receipt key pair on the destination node, signs the Control
proof of possession, exchanges the one-time enrollment, and writes the exact files
accepted by the Linux installer. Its JSON output contains an
`installer_arguments` array rather than a shell string, so automation can pass
each value without reparsing or interpolation.

The activation directory is deliberately resumable. Steward commits its receipt
key and exchange identity before contacting Control. If Control consumes the
enrollment but the response is lost, rerun the identical command. The retry uses
the same key and request identity, and Control reproduces the same node credential.
Once `activation.json` exists, an exact rerun verifies the completed files and does
not contact Control again.

If the enrollment expires before activation, prepare a new package with a new
bounded request identity:

```console
stewardctl site node prepare steward-site node-a \
  -request-id node-a-enrollment-2 \
  -out steward-node-node-a-2
```

Neither command copies files to another machine, invokes the root installer, or
keeps the site-administrator token in the node package. Those remain explicit
trust-boundary operations.

## Connect the task authority after Gateway is ready

After the node operator activates an agent service and transfers its non-secret
service-trust inventory through an authenticated channel, join it to the existing
tenant operator context:

```console
stewardctl site task connect steward-site \
  -trust /secure/steward/service-trust.json \
  -gateway-token-file /secure/steward/gateway-service.token
```

The command verifies the complete site package, service inventory, tenant, node,
Gateway credential path, and task key before extending the context. It stores only
file paths, never bearer values or private-key bytes. An exact retry is safe; a
different authority already attached to the context fails closed.

The default task key is `private/tenant-task.private.pem` in the protected site
handoff. Use `-task-key` when that role has moved to a tenant signing workstation.
The service-trust inventory is not secret or independently signed, so authenticate
its transfer from the enrolled node. Higher-assurance installations can keep the
task private key off the node and use `task issue`, `task submit`, and `task wait`
as separate steps.
