---
title: Frequently asked questions
description: Answers about Steward's purpose, control-plane neutrality, Docker and gVisor requirements, tenant isolation, air-gapped operation, agent support, and current scope.
section: Reference
---

# Frequently asked questions

## What is Steward?

Steward is open-source fleet and node software for managing and isolating AI agent
workloads on operator-controlled Linux servers. Its optional controller enrolls
nodes and delivers exact signed commands. Each node tracks workload lifecycle and
runs hardened Docker/gVisor workloads through a separate Executor.

## Is Steward an agent framework?

No. Agent runtimes are packaged as Open Container Initiative (OCI) images. Steward
provides lifecycle, isolation, and remote control beneath them. Steward includes
a qualified, exact-pinned adapter for a closed Hermes Agent surface. Broader agent
features require separate capability contracts and qualification.

## Does Steward require a particular control plane?

No. Any compatible control plane can use Steward's public OpenAPI and outbound
uplink contracts. Steward also ships the optional self-hosted `steward-control`
implementation, so a site does not need to build one. The project requires no
vendor SDK, account, hosted endpoint, private package, or other private build or
runtime dependency.

## Does Steward Control hold tenant signing keys?

No. It stores tenant bindings, credential verifiers, inventory, public signed
artifacts, desired deployments, command bytes, delivery leases, and terminal
reports. A trusted signing station or separate signing service holds tenant and
site private keys. For reconciliation, a tenant may delegate exact instances,
nodes, generations, lifecycle verbs, and admission fields to Control's short-lived
online authority. Executor verifies both signatures and local site policy. The
controller cannot turn its bearer or online key into a tenant signature or widen
the signed delegation.

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
egress, and relay reservations count toward those totals. Shared-host persistent
state requires the OpenZFS worker, which applies hard byte and object quotas per
lineage. Steward does not cap storage I/O bandwidth. Use dedicated hardware when
processor side channels or separate hardware failure domains are in scope.

Egress denials are limited to 30 per grant, 120 per tenant, and 480 per host per
minute to bound synchronous audit pressure. After a layer is exhausted, requests
that fail policy return `egress_rate_limited` without another denial write; allowed
traffic continues. Inactive and revoked grants retain their specific lifecycle
response even if the limiter suppresses the corresponding denial record. This does
not isolate shared CPU, memory, disk latency, or the host-wide audit filesystem.

## What does signed admission add beyond a sandbox?

Docker and gVisor limit where code runs; they do not identify the tenant that
authorized it or define one approved external effect. Signed admission records why
a workload was allowed. A profile capsule is a publisher-signed
description of an immutable image and its maximum capabilities. Executor verifies
that capsule, a policy signed by the operator's site root key, and an authenticated
intent bound to a tenant, node, instance, and generation. Executor journals host
changes and emits receipts that `stewardctl` can verify offline. This path is opt-in; see
[the how-to]({{ '/guides/signed-admission/' | relative_url }}).

## Does Steward prevent prompt injection?

No. Hostile instructions can arrive through a calendar invitation, email, web
page, document, tool response, or memory, and no model-level detector is a complete
security boundary. Authorized Effects instead assumes the agent is compromised and
limits what it can do through Steward-managed connectors. Signed tenant policy
pins action keys to connector IDs, intent explicitly selects the mode, generic
egress is prohibited, and Gateway spends one complete exact-request permit before
DNS while keeping the upstream credential outside the workload. Signed policy can
require distinct approvers over that same artifact.
For selected connectors, policy can also require
[context locking]({{ '/guides/context-locked-effects/' | relative_url }}), which
invalidates the permit after the grant receives another completed Steward
connector response. That control identifies the managed response history; it does
not decide whether the history is safe.

This does not cover unmanaged credentials or channels, inference confidentiality,
local filesystem or computer use, host root, a mistaken approver, or upstream
exactly-once behavior. See
[Authorize exact external effects]({{ '/guides/authorized-effects/' | relative_url }}).

## Do receipts prove everything an agent did?

No. Executor receipts bind Steward's admission and host-mutation records. Gateway
receipts can bind an exact tenant task permit, request digest, dispatch result,
agent-reported terminal status, result digest and length, and the run ID observed
from an agent service. Format-5 authorized connector records additionally bind the
explicit effect mode, operation policy, action key, permit, and exact request
digest. They exclude raw prompts, request bodies,
model responses, agent logs, workspace content, and tool meaning. The service
supplies its run ID, so the ID is not independent proof that useful work completed.
Compromised host root is outside the node-local receipt trust boundary.

## Which agent runtime does Steward support?

Steward can run its qualified, source-built Hermes adapter for exact upstream commit
`3ef6bbd201263d354fd83ec55b3c306ded2eb72a` on the qualified `linux/amd64` platform.
Other platforms require their own qualification run. The official Hermes image is still not
admissible because it starts as root and declares a volume. Steward includes an
interactive and non-interactive builder; it does not redistribute a prebuilt image
because dependency and base-image notices are incomplete.

The Hermes qualification runs a signed, network-free workspace-audit skill as a real
task under gVisor, changed persisted workspace state, and required a fresh changed
result after restart. It also required Hermes to discover and load the exact signed
connector skill before demonstrating one authenticated upstream effect, replay and
undeclared-operation denial, and a separate signed Gateway receipt chain. The
service exposes negotiation, health, run submission, and run status on port `8766`,
but not run event streams. Inference is fixed through
`http://steward-relay:8080/v1`. Persistent state requires the explicit dedicated
single-tenant host mode and is not a shared-host claim.

The tenant-signed service-task path scopes an off-node key to `hermes-api`, signs the
exact workspace-audit run request, dispatches it through the generic task lifecycle,
and audits receipt format 4. The connector portion still uses ordinary connector grant
and task authority; it does not exercise the optional connector action-permit path.

Active OpenClaw support has been retired. Steward rejects new definitions that
select `runtime.engine: openclaw`; it does not attempt an automatic conversion.
Use the [Hermes guide]({{ '/guides/hermes-agent/' | relative_url }}) before signing
an exact adapter archive, and see the
[OpenClaw migration note]({{ '/reference/openclaw-migration/' | relative_url }})
if you created an older OpenClaw definition.

## Can Terraform manage Steward?

Steward ships provider-neutral cloud-init modules for node staging and controller
bootstrap. The controller module pins the installer and exact release, starts only
on loopback, keeps the generated site-administrator bearer out of Terraform state
and process arguments, authenticates that on-host bearer before recording
completion, and safely re-enters installer recovery after an interrupted first
boot. The node module stages software without putting enrollment credentials in
user data. The Amazon Web Services (AWS) example creates one Elastic Compute Cloud
(EC2) instance and its root disk while accepting existing security-group IDs.

Steward does not ship a Terraform provider for dynamic fleet or workload
resources. A future provider needs a remote API protected by mutual TLS (mTLS) or
by identity bound to node attestation, which is cryptographic evidence of node
state. Steward will not expose its loopback host token for this purpose. See
[Terraform bootstrap]({{ '/guides/terraform/' | relative_url }}).

## Where do models run?

Outside Steward. An operator provides a separately managed local or hosted model
service. Gateway has presets for OpenAI, OpenRouter, Anthropic, Mistral, vLLM,
Ollama, llama.cpp, LocalAI, LiteLLM, LM Studio, SGLang, and TGI, plus a bounded
compatible-route form. Steward brokers site-configured routes and credentials; it
does not schedule or serve models. See
[inference providers]({{ '/guides/inference/' | relative_url }}).

## Does Steward store inference keys and connector tokens?

No. Gateway reads reusable credentials from owner-only files and adds them only at
an admitted upstream hop. The agent and React console never receive the values.
Use an operator-selected secret manager or offline process to materialize the files.
Steward validates a provider-neutral manifest, protected file identity, and expected
rotation epoch; it does not implement provider storage, unsealing, backup, recovery,
or audit. See [Gateway credentials]({{ '/guides/secrets/' | relative_url }}).

## How can an agent call an authenticated API without Steward directly giving it the secret?

Use a named connector. The publisher capsule permits the connector capability,
site policy permits connector IDs for one tenant, and instance intent selects a
subset. The node operator maps each ID to exact HTTP operations, an address policy,
an owner-only credential file, and finite concurrency, call, byte, and time limits.
Gateway spends a task claim before opening the upstream request, strips
agent-supplied credentials, and adds the configured credential at the last hop.
For operations that need independent approval, configure a tenant-scoped action
authority. Its private key stays off-node and signs a short-lived permit for the
exact admitted instance, operation, task, and request bytes. Gateway requires both
the workload grant and that permit, spends the call durably, and records the permit
and request digests in its signed connector chain.
It is not a general secret injector or an HTTPS interception proxy. Gateway relays
bounded responses but rejects any header or decoded body stream containing the
exact configured credential. A malicious or misconfigured upstream can still
encode or transform that value, disclose the private origin, or return another
application secret. Use a narrow trusted operation. See
[authenticated API operations]({{ '/guides/connectors/' | relative_url }}).

## How can a tenant authorize one exact agent task?

Add an Ed25519 public key to that tenant's signed-policy `task_keys` and scope it to
the exact service ID. Keep the private key off-node. Configure one exact Gateway
service operation with `stewardctl gateway service set`, export its unsigned
tenant-specific inventory with `gateway service trust`, and issue an owner-only
bundle with `stewardctl task issue`. Gateway requires both the active workload grant
and that short-lived permit before dispatch.

`stewardctl task submit` sends any current lifecycle bundle through a
literal-loopback Gateway origin. `task status` is passive; `task observe` makes one
bounded observation; and `task wait` polls and writes or explicitly discards the
verified terminal result. Run them locally or over SSH and do not expose Gateway
publicly. `task verify` checks the bundle offline, and `task audit` correlates it
with a copied format-4 Gateway receipt chain.

The replay guarantee is node-local at-most-once dispatch within one retained ledger
epoch. It is not fleet-wide or upstream exactly-once execution. Reusing the task ID
on another node, replacing the ledger, or advancing its epoch creates another replay
domain. An ambiguous outcome stays spent and is not retried automatically. See the
[Hermes task workflow]({{ '/guides/hermes-agent/' | relative_url }}#authorize-and-run-one-exact-hermes-task).

## Is the exported action-trust inventory an authorization document?

No. It is unsigned, non-secret operator input that summarizes one Gateway
configuration for one explicitly selected tenant's signing station. The required
tenant filter omits other tenants' action-authority and connector metadata.
Authenticate its transfer from the intended node. `stewardctl permit issue` uses it
to catch node, tenant, key, connector origin, exact operation, credential-epoch,
and lifetime mismatches before signing. Gateway's live validated configuration
remains the final enforcement authority.

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

## How do I diagnose a failed service task?

Read the structured error code before issuing another permit. Gateway keeps
upstream failures distinct: authentication (`service_task_upstream_unauthorized`),
authorization (`service_task_upstream_forbidden`), missing routes
(`service_task_upstream_not_found`), rate limits, other client errors, and server
errors have separate codes. The message includes the upstream HTTP status but
never copies its untrusted response body. A non-success response still spends the
one-use permit because the upstream may have performed work before responding.
`stewardctl task status` shows the durable terminal code, and
`stewardctl task audit` verifies it against the signed receipt chain.

Executor likewise distinguishes an unreachable Gateway from an invalid committed
route-policy binding and from a policy digest mismatch. A mismatch is durable
state drift, not a transient network failure. Inspect `/v1/readiness` and let
the periodic reconciler repair or contain it instead of repeatedly submitting
admission.

## What if Docker removed an admitted container outside Steward?

Executor reconciliation reports `workload_missing` and blocks ordinary mutation.
Run the same authorized `stewardctl node destroy RUNTIME_REF` operation after the
failure appears in readiness. Destroy has a narrow recovery path when there is
exactly one matching failure and no pending journal operation. It proves the
container remains absent, validates the deterministic Gateway, relay, and network
identities, removes that residual authority, writes a signed destroy receipt, and
commits a fence tombstone. Persistent state is retained for a later signed purge.
Any foreign identity or uncertain result remains fail closed. Do not purge and
reinstall the node to clear this condition.

## How are upgrades rolled back?

Upgrade and rollback require a drained node: no managed containers or capability
networks, live admission fences, pending journal entries, or retained Gateway
grants may remain. `stewardctl node maintenance drain` previews that inventory;
`-apply` persists a cordon before destroying the exact active signed runtimes and
leaves persistent state volumes in place. It does not migrate work or clear an
ambiguous journal. Maintenance remains enabled until the restarted Executor has
reconciled and an operator runs `stewardctl node maintenance exit`.

Activation stops previously active services, verifies that the target can read
every durable state file, and switches the complete release and its relay image
binding. It then restarts only the services that were active before the transition.
A rollback restores release files and the retained relay binding; it does not
restore configuration or durable data. A directory from an older installer without
`release.json` is not an eligible rollback target. See
[upgrade and rollback]({{ '/guides/upgrades/' | relative_url }}).

Normal Executor startup may migrate `uplink-delivery-state.json` from format 2 or 3
to format 4. After that migration, a prior release whose manifest stops at format 2
or 3 is not eligible for software rollback, even when the ledger is empty. Do not
restore that file independently; use a complete, matching backup only under an
approved recovery procedure that accounts for later commands and external effects.

## What should I read first?

Operators should start with [Install Steward]({{ '/getting-started/' | relative_url }}).
Security reviewers should start with the
[security model]({{ '/concepts/security-model/' | relative_url }}),
[architecture]({{ '/concepts/architecture/' | relative_url }}), and
[public API contracts]({{ '/reference/api/' | relative_url }}).
