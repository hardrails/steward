---
title: Reuse cloud node pools behind a Steward lifecycle contract
description: Why Steward composes native cloud scaling with secure node bootstrap instead of owning cloud capacity.
---

# Reuse cloud node pools behind a Steward lifecycle contract

- Status: Accepted
- Date: 2026-07-21
- Rung: native-platform

## Context

A production Steward site needs repeatable private nodes, multi-zone placement,
failed-VM replacement, controlled image rollout, and elastic capacity. AWS Auto
Scaling Groups, Google Cloud regional Managed Instance Groups, and Azure Virtual
Machine Scale Sets already implement those infrastructure concerns. Rebuilding
them would add three provider APIs, three failure models, and a general autoscaler
to Steward without improving agent authority or isolation.

The cloud services do not know when a VM has become a correctly enrolled Steward
node, whether it is safe to terminate, or whether its replacement preserves
generation and evidence fences. Terraform and instance user data also retain
values, so they cannot safely carry reusable enrollment credentials or private
keys. A VM being healthy is therefore not the same as a Steward node being ready.

## Decision

Decision: use `native-platform` for VM pool capacity, zone distribution, VM health,
and rolling replacement. Steward supplies provider-neutral, checksum-pinned,
secret-free cloud-init plus supported Terraform modules for the three major cloud
node-pool services. Each module consumes an existing private network and hardened
machine image rather than creating an opinionated network or image factory.

Steward keeps the node enrollment, readiness, cordon, drain, placement, generation
fencing, and evidence contracts `in-house` because those semantics are the product.
Initial cloud pools stage exact release bytes and remain ineligible for Steward
placement until the existing finite enrollment workflow activates each node.

Attestation-backed elastic enrollment is deferred to an `open-source` SPIFFE/SPIRE
integration. A later integration may consume short-lived, independently attested
workload identity through a narrow certificate handoff; it must not introduce a
shared bootstrap bearer in metadata, Terraform state, or a scale-set model.

**Tradeoff:** native node pools provide mature capacity and rollout behavior with
little Steward-owned code, while the fail-closed enrollment boundary prevents an
easy-looking deployment from silently weakening site authority.

**Rejected:** a Steward cloud provider, a Steward autoscaler, Kubernetes as a
mandatory substrate, and reusable join tokens in user data because they duplicate
commodity infrastructure, add an unrelated control plane, or turn readable
deployment metadata into fleet enrollment authority.

## Consequences

- Operators can create or resize a private, multi-zone Steward node pool with one
  Terraform module call on AWS, Google Cloud, or Azure.
- A new VM is installed but unschedulable until its node-specific enrollment is
  completed. This is deliberate and must remain visible in documentation and
  outputs.
- Cloud replacement protects VM availability. Steward cordon and drain remain the
  required scale-in ceremony for active agent workloads.
- The first modules do not claim secure zero-touch scale-out, application-aware
  autohealing, controller high availability, or host protection from a cloud
  administrator.
- Revisit the enrollment boundary when the SPIFFE/SPIRE profile proves node
  identity, revocation, restart, disconnected operation, and compromised-node
  behavior end to end.
