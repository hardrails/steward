---
title: Frequently asked questions
description: Answers about Steward's purpose, control-plane neutrality, Docker and gVisor requirements, tenant isolation, air-gapped operation, agent support, and v0.1 scope.
section: Reference
---

# Frequently asked questions

## What is Steward?

Steward is open-source node software for remotely managing and isolating AI agent
workloads on operator-controlled Linux servers. It includes a generic lifecycle
supervisor and a separate Docker/gVisor Executor.

## Is Steward an agent framework?

No. Hermes Agent, OpenClaw, and other agent runtimes run as OCI workloads. Steward
provides the node lifecycle, isolation, and remote-control boundary beneath them.

## Does Steward require a particular control plane?

No. Any compatible control plane can provision and manage a fleet through Steward's
public contracts. Steward is an independent Apache-2.0 project with no private build
or runtime dependencies.

## Can another control plane use Steward?

Yes. Implement the public OpenAPI and outbound uplink contracts. No Hardrails SDK,
account, hosted endpoint, or private package is required.

## Why both Docker and gVisor?

Docker supplies image and container lifecycle. gVisor's `runsc` adds a userspace
kernel boundary between untrusted workload syscalls and the host kernel. Executor
refuses startup when Docker does not advertise `runsc`.

## Does Steward install Docker?

No. Docker is an operator-owned prerequisite. The guided installer can optionally
download, verify, and register official gVisor after asking for approval.

## Can multiple tenants share one host?

Yes, within the [documented shared-host threat model]({{ '/concepts/security-model/' | relative_url }}).
Each workload receives a separate gVisor sandbox, fixed least privilege, no host
mount or network, and tenant-scoped capacity accounting. Dedicated hardware may
still be required for threats such as microarchitectural side channels or stronger
failure-domain separation.

## Can v0.1 run Hermes Agent or OpenClaw?

It can test image admission and offline lifecycle behavior. It cannot yet run them
as connected persistent services because Executor v0.1 grants no egress, secrets,
durable storage, or published ports. See the [Hermes]({{ '/guides/hermes-agent/' | relative_url }})
and [OpenClaw]({{ '/guides/openclaw/' | relative_url }}) guides.

## Where do models run?

Outside Steward. An operator may provide local models through a separately managed
OpenAI-compatible gateway. Steward does not schedule inference or hold model policy.

## Does Steward work without internet access?

Yes. Release artifacts, the installer, gVisor, credentials, and approved OCI images
can be transferred into the facility. The `--offline-dir` installer mode fails
instead of using the network. See [air-gapped installation]({{ '/guides/air-gapped/' | relative_url }}).

## Why does Executor not pull images?

Image acquisition and verification are separate supply-chain decisions. Executor
only accepts a repository digest already present on the host, so a lifecycle command
cannot unexpectedly contact a registry or change bytes behind a tag.

## Is `steward -enable-process-exec` a tenant sandbox?

No. It launches a trusted operator-authored OS process with Steward's own Unix
identity and no container isolation. Keep it off for tenant workloads; use Executor.

## How are upgrades rolled back?

Releases are installed side by side and selected through an atomic symlink after
preflight. Rollback selects a prior release without reverting configuration,
durable lifecycle data, or anti-replay state. See [upgrade and rollback]({{ '/guides/upgrades/' | relative_url }}).

## What should I read first?

Operators should start with [Install Steward]({{ '/getting-started/' | relative_url }}).
Security reviewers should start with the [security model]({{ '/concepts/security-model/' | relative_url }}),
[architecture]({{ '/concepts/architecture/' | relative_url }}), and
[public API contracts]({{ '/reference/api/' | relative_url }}).
