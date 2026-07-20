---
title: Keep site bootstrap native and anchor connectors thin
---

# 0044. Keep site bootstrap native and anchor connectors thin

Status: accepted

## Context

Steward already had the enforcement primitives for site policy, tenant command
delegation, exact service tasks, Control TLS, and protected connector effects. A
new operator still had to create each key and policy field independently. The
generic connector was portable but left first-time users to translate a real API
into Steward's exact-operation contract before they could prove useful work.

The bootstrap path handles the most sensitive authority relationships in the
product. A hosted setup service would break disconnected operation and would see
customer key material. A new vault, PKI, or general connector SDK inside Steward
would duplicate established systems and expand the trusted code base.

## Decision

- Site-package composition is `in-house`. Steward owns its policy roles, key
  separation, signed inventory, and Executor trust contract. `stewardctl site
  init` uses Go's standard `crypto`, `x509`, filesystem, and JSON packages, writes
  an atomic owner-only package, and never transmits material.
- Cryptographic and filesystem primitives are `built-in`. We do not implement
  signature algorithms, certificate parsing, HTTP, or atomic file primitives.
- Secret storage remains `open-source` or operator-selected external
  infrastructure, such as OpenBao and SPIFFE/SPIRE. Steward validates the
  provider-neutral file handoff; it does not store or distribute secret values.
- The generic HTTPS connector remains `in-house` because exact operation binding,
  spend-before-network replay control, credential non-disclosure, and signed
  receipts are core enforcement semantics.
- Provider anchors are thin `in-house` configuration presets over that generic
  contract. The first preset fixes one GitHub issue-creation origin and path. It
  uses no provider SDK and adds no runtime dependency. More presets require a real
  acceptance workflow, minimal provider permissions, and reversible test effects.
- A connector marketplace is `do-nothing` until signing, conformance, maintenance
  ownership, and security response are defined.

## Consequences

Operators get one secure starting package and one recognizable real action without
making Steward a key escrow service or vendor-specific automation framework. The
generated directory is only a custody handoff; operators must separate private
keys before deployment. The GitHub preset reduces configuration ambiguity but does
not abstract GitHub's API or permission model. Generic connectors remain available
for sovereign and disconnected services.
