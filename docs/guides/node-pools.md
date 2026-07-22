---
title: Reconcile elastic node-pool capacity
description: Use Steward's provider-neutral NodePool API to add capacity and remove only drained, empty nodes without turning cloud metadata into workload authority.
section: How-to
---

# Reconcile elastic node-pool capacity

A Steward `NodePool` is the handoff between fleet operations and an external
infrastructure provider. You declare how many nodes you want. Steward reports the
exact creation deficit and, after a safe drain, the exact nodes an external driver
may remove.

This resource does **not** create machines or authorize workloads. A cloud label,
Terraform record, or compromised controller must not be able to expand a tenant's
execution authority.

## What a node pool controls

| Field or result | Meaning | Authority it does not grant |
| --- | --- | --- |
| `min_nodes`, `desired_nodes`, `max_nodes` | Bounded infrastructure capacity intent | Permission to call a cloud API |
| `tenant_ids` | Tenant scopes a registered node must already carry to count in the pool | Permission to add those scopes to a node |
| `architecture` | Optional exact scheduling architecture | Permission to change or trust a host |
| `scale_out_needed` | `desired_nodes - registered_nodes`, never less than zero | Enrollment or placement authority |
| `scale_in_candidates` | Exact nodes that completed a Steward drain and have no assigned deployment instance | Permission to choose or delete another node |

Deleting a pool removes only this intent record. It does not drain, revoke, or
destroy a node.

## Label enrolled nodes

Configure each Executor in the pool with the reserved label. Keep any additional
placement labels separate:

```console
steward-executor \
  -node-labels steward.io/node-pool=research-amd64,region=us-west \
  ...
```

The node must also be active, have every tenant scope declared by the pool, report
a matching architecture when one is required, and publish a fresh scheduling
observation. This self-reported label is useful for accounting. It is deliberately
not accepted as signed tenant authority.

## Create capacity intent

Use a site-administrator context:

```console
stewardctl control node-pool apply \
  -pool-id research-amd64 \
  -tenant-ids research \
  -architecture amd64 \
  -min-nodes 2 \
  -desired-nodes 4 \
  -max-nodes 20
```

Inspect all pools or one exact pool:

```console
stewardctl control node-pool list
stewardctl control node-pool status -pool-id research-amd64
```

Updates use optimistic concurrency. Pass the current retained revision so two
operators cannot silently overwrite each other:

```console
stewardctl control node-pool apply \
  -pool-id research-amd64 \
  -tenant-ids research \
  -architecture amd64 \
  -min-nodes 2 \
  -desired-nodes 8 \
  -max-nodes 20 \
  -revision 1
```

The CLI prints JSON so an infrastructure driver can consume the same stable
contract. The HTTP resources are `GET /v1/node-pools`, and `GET`, `PUT`, or
`DELETE /v1/node-pools/{pool_id}`.

## Build a safe provider loop

Keep cloud, hypervisor, or bare-metal credentials in a separate provider driver.
Do not place them in Steward Control.

The driver loop is intentionally small:

1. Read the exact pool status.
2. If `scale_out_needed` is positive, ask the provider to create no more than that
   many nodes and never exceed `max_nodes`.
3. Give each new machine a unique node identity and complete Steward enrollment.
4. Wait for the node doctor and a fresh scheduling observation.
5. For scale-in, request a Steward drain for a chosen node first.
6. Delete only an exact ID returned in `scale_in_candidates`.
7. Re-read status after every provider operation. Treat ambiguous provider results
   as uncertain; do not repeat a deletion against a different node.

The driver must never infer a scale-in victim from `registered_nodes`, CPU use, or
cloud group order. Steward names candidates only after the drain is durable and
the node has no assigned deployment instance.

## Current automation boundary

Capacity reconciliation is available now. Zero-touch authority expansion is not.
Tenant-signed controller delegations still contain a finite set of exact node IDs.
A newly created and enrolled node therefore needs a fresh finite delegation before
Control can place that tenant's workload on it.

This is a deliberate fail-closed boundary. If Steward treated a pool label as
authority, a compromised controller could enroll and label its own node, then run
a tenant workload there. The planned pool-membership credential will bind one node
ID and immutable boot identity to one pool, tenant scope, policy digest, and short
validity window. Both Control and Executor must verify it before pool-scoped
placement can be enabled.

For ready-to-use AWS, Google Cloud, and Azure infrastructure modules, continue with
[cloud node pools]({{ '/guides/cloud-fleets/' | relative_url }}). For the lower-level
bootstrap boundary, see [Terraform and cloud]({{ '/guides/terraform/' | relative_url }}).
