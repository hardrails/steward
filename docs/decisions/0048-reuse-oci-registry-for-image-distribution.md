---
title: Reuse an OCI registry for fleet image distribution
description: Why Steward uses Docker and an operator-run registry for exact image delivery instead of building an artifact service.
---

# Reuse an OCI registry for fleet image distribution

- Status: Accepted
- Date: 2026-07-20
- Rung: open-source plus native-platform

## Context

Steward can authenticate and sanitize an offline OCI archive, but an operator must
copy that archive to every node before Control can converge a deployment. That is
appropriate for removable-media sites and poor ergonomics for a fleet. Building a
second blob store, resumable transfer protocol, registry credential system, and
garbage collector inside Steward would duplicate established infrastructure and
substantially expand the trusted code base.

The OCI Distribution Specification already defines portable content delivery, and
Docker already implements it. A site can run CNCF Distribution, Harbor, or another
vetted compatible registry without placing a hosted vendor in Steward's trust
root.

## Decision

Decision: use `open-source` for an operator-run OCI registry and
`native-platform` for Docker's exact image pull. Steward adds only the authority
join that those systems do not provide.

Each Executor may opt into one canonical registry authority. A missing image is
pulled only when the publisher-signed capsule and site policy already authorize an
exact repository and manifest digest under that registry. The pull has a bounded
timeout and bounded daemon response. Executor then inspects the exact manifest,
config digest, platform, and declared volumes before any workload mutation.

Registry authentication is an owner-only, registry-scoped secret rendered by an
external secret provider. Steward validates its finite format and holds the
Docker-encoded value only in Executor memory. It never enters the agent, Control,
scheduling data, receipts, or command bytes. Anonymous registries remain possible
for physically isolated sites, but production registry TLS and access control are
the operator's responsibility.

Rejected: an in-house artifact server, image bytes in Control's bounded store,
large image bodies on the Executor HTTP API, raw remote shell copy, and tag-based
pulls. These options either duplicate commodity infrastructure, violate existing
body limits, add remote execution authority, or weaken immutable identity.

## Consequences

- A normal fleet deployment can populate a missing node cache without manual
  archive transfer.
- Steward stays registry-vendor neutral and fully usable in an air gap.
- Registry compromise can deny service or serve malicious bytes, but digest and
  config substitution still fails before workload creation.
- Registry availability now affects a cold placement. Cached images and the
  offline policy-bound importer remain independent recovery paths.
- The first implementation serializes cache fills per Executor. It does not build
  peer-to-peer distribution, prefetch queues, registry replication, or cache
  garbage collection.
