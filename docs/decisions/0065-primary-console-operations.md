---
title: Use the console as the primary fleet surface
description: Why Steward exposes scoped Control mutations in its embedded console while retaining private signing, cloud, and secret authority outside the browser.
section: Architecture decision
---

# Use the console as the primary fleet surface

- Status: Accepted
- Date: 2026-07-25
- Rung: installed dependency for the UI substrate; in-house for Steward's authority-aware workflow
- Supersedes: the observation-only mutation constraint in ADR 0020

## Context

Steward's Control API already owns bounded desired state for tenants, quotas,
freezes, access, enrollment, node placement, drains, node pools, deployments,
evidence capture, snapshot quarantine, Workrooms, tasks, schedules, and
interactions. Requiring an operator to leave the console and reconstruct those
calls in a terminal makes ordinary operations slower and more error-prone without
reducing the server-side bearer authority.

The browser must still not become a signing station, cloud-credential store, or
secret-retrieval service. A compromised Control plane must not be able to invent
tenant-signed agent authority.

## Decision

Make the embedded React console the primary day-to-day operating surface. Reuse
the existing same-origin Control API and its site-administrator and
tenant-operator scopes. Permit only an explicit, source-reviewed allowlist of
mutation method and path pairs. Keep the bearer in tab memory and keep request
bodies bounded by the existing server handlers.

Ordinary Control-owned changes use forms with optimistic revision fields and
explicit confirmation for destructive actions. Authority-bearing changes accept
public signed artifacts. Private signing keys never enter the browser. Node-pool
changes record provider-neutral desired capacity; cloud credentials remain in an
external fleet driver.

**Decision: extend the existing React/Vite console and Control API at the
installed-dependency rung. Tradeoff: this preserves Steward's air-gapped bundle,
one authorization model, and zero new services. Rejected: Kubernetes Dashboard,
Rancher, or another UI/state framework, because they cannot express Steward's
signed authority boundary without becoming a second control plane. Revisit if
Steward adopts an external scheduler as its authoritative desired-state source.**

## Consequences

An operator no longer needs a terminal for ordinary fleet management. Browser
extensions and the browser process can still read the active bearer and visible
metadata, so a dedicated hardened operator profile remains required.

The console can create one-time operator and enrollment capabilities. It must
label them clearly, retain them only in component memory, and let the operator
clear them immediately. It must never return private signing keys, cloud
credentials, or stored secret plaintext.

Control-owned operation does not include root service supervision, disaster
recovery, private-key signing, host-local secret materialization, or direct
provider API calls. Those remain separate trust domains so compromise of the
console or Control bearer cannot become host or cloud-account administration.

Agent computers are a projection over deployments and observations, not a new
mutable resource. ADR 0066 records that boundary.

Adding a new console mutation requires all of:

1. an existing bounded Control handler and documented OpenAPI contract;
2. an explicit method/path entry in the browser allowlist;
3. role-preserving server authorization;
4. a confirmation proportional to impact;
5. a source test that rejects adjacent and uplink routes; and
6. updated operator documentation.

ADR 0020 still governs the embedded, reproducible React build and ephemeral
session boundary. ADR 0023 still governs exact signed-command couriering.
