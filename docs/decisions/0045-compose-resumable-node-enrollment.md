---
title: Compose resumable node enrollment from existing trust primitives
description: Why Steward joins signed site trust, Control enrollment, and node-local receipt identity without adding a workflow engine or secret store.
---

# Compose resumable node enrollment from existing trust primitives

## Context

Steward already had the required enforcement pieces: a site-root-signed inventory,
an authenticated Control enrollment API, proof of possession for a node-held
receipt key, deterministic exchange retries, and a transactional Linux installer.
The normal operator path still required manually selecting, copying, and matching
those files. A mistake could bind the wrong policy, CA, node, tenant, or receipt
identity even though every individual command was correct.

Node onboarding is context rather than Steward's differentiating authority model.
The composition is still security-sensitive because it crosses the site, Control,
transfer, and destination-node trust boundaries.

## Decision

Decision: use `native-platform`: the existing Control API, signed site inventory,
`os.Root`, owner-only files, atomic directory publication, and deterministic
idempotency identities. Tradeoff: Steward removes manual artifact assembly while
adding no service, package, or private-key custody role. Rejected: an external
workflow engine or embedded secret store because either would add an online
dependency, increase the trusted computing base, and weaken disconnected
operation. Revisit if multiple independent enrollment systems require a stable
provider contract rather than the current finite Control exchange.

`site node prepare` verifies the complete site package, optionally checks an
independent root pin, idempotently creates the initial Control tenant, and creates
one short-lived enrollment. It copies only the signed public node trust, original
signed inventory, and enrollment capability into a strict owner-only package.

`site node activate` runs on the destination node. Before making a network request,
it durably creates the receipt key and exchange identity. An exact retry therefore
uses the same proof and receives the same deterministic credential after a lost
response. A completion marker is written last; later exact retries verify locally
and do not contact Control.

## Boundaries

- The prepared package contains a bearer secret and needs confidential transfer.
- The activation directory contains reusable node identity and remains owner-only.
- Tenant, publisher, action, incident-response, site-root, and Control private keys
  are never copied into either package.
- The Control URL is not new authority. TLS must authenticate through the Control
  CA whose exact bytes are bound by the signed site inventory.
- Steward does not implement remote copy, host attestation, or privileged installer
  execution in `stewardctl`.
- The original explicit enrollment commands remain the stable expert and
  third-party-automation surface.

## Verification

Tests require the prepared package to reject altered signed trust and unexpected
files. They also force the first enrollment exchange to fail, then prove the retry
uses the exact same receipt proof, produces one valid activation inventory, omits
bearer values from command output, and performs no further exchange after local
completion.
