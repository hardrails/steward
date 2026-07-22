---
title: Reconcile elastic node-pool capacity
description: Add and remove fleet capacity using short-lived independently signed membership, exact deficits, and drained-node removal.
section: How-to
---

# Reconcile elastic node-pool capacity

A Steward `NodePool` is the handoff between fleet operations and an external
infrastructure provider. You declare how many nodes you want. Steward reports the
exact creation deficit and, after a safe drain, the exact nodes a provider driver
may remove.

The pool does not create machines or authorize workloads. A cloud label,
Terraform record, provider identity, or compromised Control process must not be
able to expand a tenant's execution authority.

## What a node pool controls

| Field or result | Meaning | Authority it does not grant |
| --- | --- | --- |
| `min_nodes`, `desired_nodes`, `max_nodes` | Bounded infrastructure capacity intent | Permission to call a cloud API |
| `tenant_ids` | Tenant scopes a member must already carry | Permission to add those scopes |
| `architecture` | Optional exact scheduling architecture | Permission to change or trust a host |
| `membership_key_id`, `membership_public_key_base64` | Optional independent Ed25519 authority for short-lived membership | The private key or permission to mint a node credential |
| `scale_out_needed` | `desired_nodes - eligible_nodes`, never less than zero | Enrollment or placement authority |
| `scale_in_candidates` | At most the eligible surplus of exact nodes that completed a Steward drain and have no assigned deployment | Permission to choose or delete another node |

`registered_nodes` counts enrolled nodes that advertise the pool label.
`eligible_nodes` counts those with a current verified membership when the pool
requires one. Deleting a pool removes only its capacity record.

## Label enrolled nodes

Configure each Executor in the pool with the reserved label. Keep other placement
labels separate:

```console
steward-executor \
  -node-labels steward.io/node-pool=research-amd64,region=us-west \
  -node-boot-identity-sha256 sha256:BOOT_IDENTITY_HEX \
  ...
```

The node must be active, carry every declared tenant scope, report a matching
architecture, and publish fresh scheduling data. The label is useful for
discovery. When a pool has a membership authority, the label alone does not make
the node eligible.

## Create capacity intent

Use a site-administrator context. Keep the membership private key outside
Control and every fleet node:

```console
stewardctl control node-pool apply \
  -pool-id research-amd64 \
  -tenant-ids research \
  -architecture amd64 \
  -min-nodes 2 \
  -desired-nodes 4 \
  -max-nodes 20 \
  -membership-key-id pool-authority-1 \
  -membership-public-key /secure/pool-authority.public
```

Inspect all pools or one exact pool:

```console
stewardctl control node-pool list
stewardctl control node-pool status -pool-id research-amd64
```

Updates use optimistic concurrency. Pass the current revision so two operators
cannot silently overwrite each other:

```console
stewardctl control node-pool apply \
  -pool-id research-amd64 \
  -tenant-ids research \
  -architecture amd64 \
  -min-nodes 2 \
  -desired-nodes 8 \
  -max-nodes 20 \
  -membership-key-id pool-authority-1 \
  -membership-public-key /secure/pool-authority.public \
  -revision 1
```

The CLI prints JSON for provider automation. The HTTP resources are
`GET /v1/node-pools`, and `GET`, `PUT`, or `DELETE
/v1/node-pools/{pool_id}`.

## Make a node eligible

A membership statement is a short-lived DSSE-signed file. DSSE (Dead Simple
Signing Envelope) keeps the exact statement bytes and signature together. It
binds the exact Control instance, pool membership generation, node, tenant set,
architecture, boot identity, scheduling policy, and a validity window of no more
than 24 hours.

First, export a fresh, secret-free assurance report from Control. The command
recomputes the scheduling and runtime-assurance digests, checks the requested
profile, rejects stale observations, and produces the exact node measurements
the independent signer needs:

```console
umask 077
stewardctl control node assurance \
  -tenant-id research \
  -node-id research-0042 \
  -required-profile shared-host-hardened \
  > research-0042.assurance.json
```

An offline signer or separately protected identity adapter should issue the
statement only after it verifies the machine. `-node-assurance` replaces five
manual node and digest arguments:

```console
stewardctl control node-pool membership-issue \
  -private-key /secure/pool-authority.private.pem \
  -key-id pool-authority-1 \
  -controller-id CONTROL_INSTANCE_ID \
  -pool-id research-amd64 \
  -pool-membership-generation 1 \
  -pool-created-at 2026-07-22T09:00:00Z \
  -tenant-ids research \
  -node-assurance research-0042.assurance.json \
  -valid-for 1h \
  -out research-0042.membership.dsse.json
```

The pool status supplies `pool.created_at`; binding it prevents an old statement
from being replayed after a pool is deleted and recreated. `CONTROL_INSTANCE_ID`
appears in every finite enrollment package and response.
Configure Executor with `-node-boot-identity-sha256` using a digest from your
image pipeline, measured-boot verifier, or another trusted provisioning process.
Executor derives `scheduling_policy_sha256` from its effective scheduling limits
and `runtime_assurance_sha256` from its security-relevant startup configuration.
Control recomputes both digests before retaining the authenticated observation.
Read all three current values from the node's `scheduling.observation` projection and
give those exact values to the protected membership signer. Steward checks them
again when the statement is bound and whenever it calculates pool eligibility.
The assurance claim records Docker and gVisor use, isolated-bridge networking,
state isolation, the Gateway credential boundary, and whether host-admin intent
is enabled. It does not independently measure the host. The boot claim still
depends on the process that supplies the boot identity to Executor, and a valid
node signature does not prove that the node was uncompromised.

The report is bounded non-secret input, not signed evidence. Transfer it through
the same reviewed operator channel as other enrollment metadata and inspect it at
the membership-authority boundary. The issuer rejects a report whose freshness
window has elapsed, whose digests do not recompute, or whose verdict is not
`pass`. Expert workflows may supply the five raw fields directly.

Memberships issued before runtime assurance was added remain valid only until
their existing expiry, which is at most 24 hours. Renew them with the assurance
digest; new CLI-issued memberships require it.

Verify the file before transfer:

```console
stewardctl control node-pool membership-verify \
  -in research-0042.membership.dsse.json \
  -public-key /secure/pool-authority.public \
  -key-id pool-authority-1
```

After finite enrollment, bind it with the node's own Control credential:

```console
stewardctl control node-pool membership-bind \
  -in research-0042.membership.dsse.json \
  -control-url https://control.example.com:8443 \
  -credential /secure/enrollment/executor-node.json \
  -ca-file /etc/steward-control/ca.pem
```

Control accepts an exact retry. A renewal must have a later `issued_at` and
match the current pool membership generation. Renewal ordering is scoped to one
pool lineage, so a valid statement for a different pool can move the node even
when the two validity windows overlap. Capacity-only changes preserve
that generation. Changing tenant scope, architecture, or the membership key
increments it and invalidates prior statements. Expired, wrong-controller,
wrong-node, wrong-tenant, wrong-architecture, stale-generation, rollback, and
untrusted statements fail closed. Status retains the exact envelope and digest
for independent audit.

## Build a safe provider loop

Keep cloud, hypervisor, or bare-metal credentials in a separate provider driver:

1. Read the exact pool status.
2. Create no more than `scale_out_needed` machines and never exceed `max_nodes`.
3. Give each machine a unique node identity and complete finite enrollment.
4. Obtain and bind a node-specific membership from the protected authority.
5. Wait for the node doctor, verified eligibility, and fresh scheduling data.
6. For scale-in, request a Steward drain first.
7. Delete only an exact ID returned in `scale_in_candidates`.
8. Re-read status after every provider operation. Do not repeat an uncertain
   deletion against a different node.

Never infer a victim from CPU use or provider group order. Steward returns no
more candidates than `eligible_nodes - desired_nodes` and names them only after
the drain is durable and the node is empty.

## Current automation boundary

Capacity reconciliation and verified membership are available. Steward does not
ship a cloud-specific workload-identity adapter yet. A provider driver must
obtain each node-specific statement from a protected signer and complete finite
enrollment. Never put a reusable pool join token in metadata, Terraform state,
or an image.

Membership is eligibility, not workload authority. Tenant delegations still
name exact node IDs. Pool-scoped placement remains disabled until Executor can
verify the same independent statement within a finite tenant delegation.

Continue with [cloud node pools]({{ '/guides/cloud-fleets/' | relative_url }})
for AWS, Google Cloud, and Azure modules, or [Terraform and cloud]({{
'/guides/terraform/' | relative_url }}) for the lower-level bootstrap boundary.
