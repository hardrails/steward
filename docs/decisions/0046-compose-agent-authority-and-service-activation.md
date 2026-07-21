---
title: Compose agent authority and service activation from existing contracts
description: Why Steward joins image publication, finite lifecycle delegation, Gateway activation, and task context without adding a workflow engine, OCI SDK, or secret vault.
---

# Compose agent authority and service activation from existing contracts

## Context

Steward already enforced the necessary contracts: bounded OCI inspection,
publisher-signed capsules, site-root-signed policy, tenant-signed controller
delegation, closed Hermes and OpenClaw Gateway presets, task-key admission, and
owner-only CLI contexts. A new operator still had to translate one agent bundle
into several verbose JSON artifacts and commands. The individual primitives were
auditable, but their manual composition was a frequent source of identity,
resource, service, and node mismatch.

The composition must reduce those errors without making Steward an online signing
service, secret vault, remote shell, package transporter, or host service manager.

## Decision

Decision: use `native-platform`: Steward's existing canonical formats, standard
library archive readers, site package verifier, DSSE signing code, Gateway config
writer, and CLI context store. Tradeoff: the common path supports only Steward's
qualified Hermes and OpenClaw contracts and still exposes explicit trust-boundary
steps. Rejected: an OCI SDK, workflow engine, embedded vault, or remote execution
layer because each adds supply-chain and operational ownership without changing
the enforcement model. Revisit when another qualified runtime cannot be expressed
by the existing bounded contract or an external signer needs a stable provider
interface.

`agent publish` inspects one OCI or Docker archive, requires its manifest digest to
match the portable bundle, derives the fixed qualified runtime contract, signs it
with the site publisher key, and verifies the resulting capsule against signed site
policy before atomic publication.

`agent authorize` derives the exact admission and placement template from the
bundle, capsule, and site policy. It grants Control only `admit`, `renew`, `start`,
`stop`, and `destroy` for an exact node set, instance, lineage, generation,
resources, routes, connectors, and finite lifetime. It verifies the signed result
before publication.

`agent service activate` selects the closed Gateway preset for the bundle runtime,
adds a tenant receipt budget, and exports the exact non-secret service inventory.
`site task connect` verifies that inventory, the signed site package, the tenant
task key, and credential paths before extending an existing tenant-operator
context.

## Boundaries

- The composed signing commands read generated private keys from the protected site
  handoff. Sites with external key custody use the lower-level signing commands.
- Image build, archive transfer, and privileged image import remain separate.
- Control's public controller key must arrive through an authenticated channel.
- Gateway activation returns a `systemctl` action; it never executes host commands.
- Service trust is non-secret but unsigned and requires authenticated transfer.
- CLI contexts retain paths, not bearer values or private-key bytes.
- Exact retries either reproduce or verify the existing artifact; conflicting
  authority fails closed.

## Verification

Tests bind capsule output to the inspected archive identity and policy, verify that
delegation contains only the derived finite scope, require Gateway service and
receipt identities to match the enrolled node, and prove repeated activation or
context connection cannot replace an existing authority. The joined first-task
acceptance workflow exercises publication through task execution with no credential
inside the agent image or request.
