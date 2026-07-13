---
title: Distribute agent adapters as pinned external builds
description: How Steward can qualify Hermes Agent and OpenClaw without importing either runtime into its trusted host software.
section: Architecture decision
---

# Distribute agent adapters as pinned external builds

## Status

Accepted.

## Context

Steward needs directly runnable paths for selected agent runtimes while keeping its
host processes small, dependency-free, and independent of agent implementation
code. Upstream agent images are not automatically suitable for a shared host. They
may start as root, download packages at startup, expose unmanaged services, write to
unexpected paths, or assume authentication and storage arrangements that conflict
with Steward's policy.

A signature proves who authorized bytes; it does not make those bytes trusted.
Agent source, images, adapters, skills, MCP servers, configuration, and output stay
outside Steward's host process and remain untrusted at runtime.

## Decision

Keep adapter definitions under `adapters/<agent>` as independent, pinned promotion
builds. Do not vendor an upstream checkout, add it as a submodule, import its code
into Go, or make `go build ./...` fetch or compile an agent runtime.

Each qualified adapter must bind and record:

- the exact upstream commit and supported platform;
- upstream, selected-component, base-image, and bundled-material license results;
- lockfile, build recipe, patch, shim, fixture, and generated-notice digests;
- the output OCI manifest and configuration digests; and
- the conformance evidence for the exact output image.

A promotion build may acquire locked inputs on a connected build system. The
resulting OCI archive and verification material must then build or import and run
without network access. No package, plugin, skill, browser, model, or configuration
download is permitted when the adapter starts or handles a task.

Steward-owned shims may translate the common management contract and replace a
privileged upstream initializer. A shim must stay thin and separately reviewed. If
qualification requires maintaining upstream core behavior, the adapter fails its
gate and the scope must be reconsidered.

Every runtime proof uses Docker with gVisor `runsc`, UID/GID `65532:65532`, a
read-only root filesystem, dropped Linux capabilities, `no-new-privileges`, bounded
writable state, and named Gateway grants. The adapter never receives the Docker
socket, host networking, or a caller-selected host path.

## Consequences

Steward remains buildable and auditable without Python, Node.js, an agent checkout,
or a public registry. Operators can mirror the pinned inputs and OCI archives into
an air-gapped environment. Adapter releases can stop independently when a license,
base image, lockfile, or upstream behavior changes.

This adds promotion and conformance work for each supported pin. Passing a fixture
proves only the declared contract and capabilities for that exact image. It does
not certify arbitrary upstream plugins, skills, MCP servers, channels, or future
commits.

## Rejected alternatives

- **Run official images unchanged.** Their defaults are not evidence that Steward's
  containment, storage, authentication, and offline requirements hold.
- **Load adapters into Executor or another host process.** That would move untrusted
  agent code into the Docker-authority boundary.
- **Maintain broad upstream forks.** Forked core behavior creates an unbounded
  security and compatibility obligation. Only the smallest reviewed shim or build
  adaptation is allowed.
- **Download adapters or dependencies at startup.** That breaks air-gapped operation
  and makes the executed bytes differ from the admitted evidence.
