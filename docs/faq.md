---
title: Frequently asked questions
description: Answers about Steward's purpose, control-plane neutrality, Docker and gVisor requirements, tenant isolation, air-gapped operation, agent support, and current scope.
section: Reference
---

# Frequently asked questions

## What is Steward?

Steward is open-source node software for remotely managing and isolating AI agent
workloads on operator-controlled Linux servers. It tracks workload lifecycle and
runs hardened Docker/gVisor workloads through a separate Executor.

## Is Steward an agent framework?

No. Agent runtimes are packaged as Open Container Initiative (OCI) images. Steward
provides lifecycle, isolation, and remote control beneath them. Steward includes one
qualified, exact-pinned Hermes Agent adapter definition. OpenClaw remains a layout
contract that requires a separately qualified adapter.

## Does Steward require a particular control plane?

No. Any compatible control plane can use Steward's public OpenAPI and outbound
uplink contracts. Steward is an independent Apache-2.0 project that requires no
Hardrails SDK, account, hosted endpoint, private package, or other private build or
runtime dependency.

## Why both Docker and gVisor?

Docker supplies image and container lifecycle. gVisor's `runsc` adds a userspace
kernel boundary between untrusted workload syscalls and the host kernel. Executor
refuses startup when Docker does not advertise `runsc`.

## Does Steward install Docker?

No. Docker is an operator-owned prerequisite. The guided installer can optionally
download, verify, and register official gVisor after asking for approval.

## Can multiple tenants share one host?

Yes, within the [shared-host threat model]({{ '/concepts/security-model/' | relative_url }}).
Each workload gets a separate gVisor sandbox, fixed least privilege, no host mount
or raw network access, plus tenant and host aggregate memory, CPU, PID, and
workload-count caps. A per-instance relay and the host Gateway mediate HTTP(S)
egress, and relay reservations count toward those totals. Steward does not cap
disk bytes, inodes, or I/O bandwidth. Persistent Docker state is disabled on
shared hosts because it has no portable hard byte or inode quota. Use dedicated
hardware when processor side channels, storage exhaustion, or separate hardware
failure domains are in scope.

## What does signed admission add beyond a sandbox?

It records why a workload was allowed. A profile capsule is a publisher-signed
description of an immutable image and its maximum capabilities. Executor verifies
that capsule, a policy signed by the operator's site root key, and an authenticated
intent bound to a tenant, node, instance, and generation. Executor journals host
changes and emits receipts that `stewardctl` can verify offline. This path is opt-in; see
[the how-to]({{ '/guides/signed-admission/' | relative_url }}).

## Do receipts prove everything an agent did?

No. Receipts bind Steward's admission and host-mutation records. They exclude
prompts, model responses, agent logs, and tool meaning. Compromised host root is
outside the node-local receipt trust boundary.

## Can Steward run Hermes Agent or OpenClaw?

Steward can run its qualified, source-built Hermes adapter for exact upstream commit
`095b9eed3801c251796df93f48a8f2a527ff6e70` on the qualified `linux/amd64` platform.
Other platforms require their own qualification run. The official Hermes image is still not
admissible because it starts as root and declares a volume. Steward includes an
interactive and non-interactive builder; it does not redistribute a prebuilt image
because dependency and base-image notices are incomplete.

The Hermes qualification ran a signed, network-free workspace-audit skill as a real
task under gVisor, changed persisted workspace state, and required a fresh changed
result after restart. It also required Hermes to discover and load the exact signed
connector skill before proving one authenticated upstream effect, replay and
undeclared-operation denial, and a separate signed Gateway receipt chain. The
service exposes negotiation, health, run submission, and run status on port `8766`,
but not run event streams. Inference is fixed through
`http://steward-relay:8080/v1`. Persistent state requires the explicit dedicated
single-tenant host mode and is not a shared-host claim.

OpenClaw has not completed this qualification and remains a layout contract. See the
[Hermes]({{ '/guides/hermes-agent/' | relative_url }}) and
[OpenClaw]({{ '/guides/openclaw/' | relative_url }}) guides before signing an exact
adapter archive.

## Can Terraform manage Steward?

The shipped module renders cloud-init designed for non-secret bootstrap. The Amazon
Web Services (AWS) example creates one Elastic Compute Cloud (EC2) instance and its
root disk while accepting existing security-group IDs. After enrollment, the node
stores credentials and keys outside Terraform state. Steward's generation fence
still rejects stale instance commands. A future provider needs a remote API protected
by mutual TLS (mTLS) or by identity bound to node attestation, which is cryptographic
evidence of node state. Steward will not expose its loopback host token for this
purpose. See
[Terraform bootstrap]({{ '/guides/terraform/' | relative_url }}).

## Where do models run?

Outside Steward. An operator provides local models through a separately managed,
OpenAI-compatible service. Steward brokers site-configured routes and credentials;
it does not schedule or serve models.

## How can an agent call an authenticated API without Steward directly giving it the secret?

Use a named connector. The publisher capsule permits the connector capability,
site policy permits connector IDs for one tenant, and instance intent selects a
subset. The node operator maps each ID to exact HTTP operations, an address policy,
an owner-only credential file, and finite concurrency, call, byte, and time limits.
Gateway spends a task claim before opening the upstream request, strips
agent-supplied credentials, and adds the configured credential at the last hop.
It is not a general secret injector or an HTTPS interception proxy. Gateway relays
bounded response bodies and non-Steward headers, so a malicious or misconfigured
upstream can still reflect authentication material. Use a narrow operation that
does not echo the credential or private origin. See
[authenticated API operations]({{ '/guides/connectors/' | relative_url }}).

## Does Steward work without public Internet access?

Yes. Transfer the release artifacts, installer, gVisor files, credentials, and OCI
images into the facility. `--offline-dir` fails rather than using the public
Internet. Enabled uplinks and model routes must still reach their configured
on-site endpoints. See
[air-gapped installation]({{ '/guides/air-gapped/' | relative_url }}).

## Why does Executor not pull images?

Image acquisition and verification are separate supply-chain decisions. Executor
accepts only immutable images already on the host, so lifecycle commands cannot
contact a registry or follow a changed tag. Signed admission matches the exact
local configuration digest to the capsule's signed manifest and platform.
The operator must authenticate repository provenance through a trusted build or
promotion record; Steward does not infer provenance from an archive.
`stewardctl image import` verifies the signed capsule and policy binding plus the
archive's exact manifest, config, and platform before Docker load. The unsigned
endpoint also requires an existing repository digest. See
[image and evidence tools]({{ '/reference/offline-tools/' | relative_url }}).

## Is `steward -enable-process-exec` a tenant sandbox?

No. It launches a trusted, operator-authored operating-system process with
Steward's Unix identity and no container isolation. Keep it disabled for tenant
workloads; use Executor.

## How are upgrades rolled back?

Upgrade and rollback require a drained node: no managed containers or capability
networks, live admission fences, pending journal entries, or retained Gateway
grants may remain. Activation stops previously active services, verifies that the
target can read every durable state file, and switches the complete release and its
relay image binding. It then restarts only the services that were active before the
transition. A rollback restores release files and the retained relay binding; it
does not restore configuration or durable data. A directory from an older installer
without `release.json` is not an eligible rollback target. See
[upgrade and rollback]({{ '/guides/upgrades/' | relative_url }}).

## What should I read first?

Operators should start with [Install Steward]({{ '/getting-started/' | relative_url }}).
Security reviewers should start with the
[security model]({{ '/concepts/security-model/' | relative_url }}),
[architecture]({{ '/concepts/architecture/' | relative_url }}), and
[public API contracts]({{ '/reference/api/' | relative_url }}).
