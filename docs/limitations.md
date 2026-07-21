---
title: Capability boundaries and known limitations
description: What Steward protects, what remains trusted, and where operators must add another control.
section: Understand
---

# Capability boundaries and known limitations

Steward reduces the authority available to an untrusted agent. It does not make
the agent, host, model, or external service trustworthy. Use this page to decide
whether Steward's current boundaries match your risk model.

## Prompt injection is assumed, not solved

Web pages, mail, calendars, documents, memory, tool results, and user messages can
contain instructions that influence an agent. Steward does not reliably classify
that content as safe or malicious.

Authorized Effects instead constrains a managed action after the agent proposes it.
A permit can bind one tenant, instance generation, connector operation, task ID,
and exact request bytes. This helps only when the effect goes through the configured
Steward connector. It does not cover:

- an unmanaged browser session;
- computer-use or desktop automation;
- direct network access outside Gateway;
- credentials stored in an image, prompt, environment, or mounted file;
- local filesystem changes inside allowed state;
- inference confidentiality; or
- a human who approves a misleading but correctly displayed request.

Use origin isolation, content sanitization, model screening, information-flow
controls, human review, and application-native authorization as additional layers.

## A shared host is not separate hardware

gVisor reduces direct exposure to the host kernel. Docker, gVisor, Linux, host root,
and the physical machine remain trusted. Steward does not eliminate:

- kernel, hypervisor, firmware, or container-runtime vulnerabilities;
- CPU, memory-bus, cache, power, or other hardware side channels;
- denial of service against shared disk, network, or kernel resources;
- malicious host administrators;
- DMA or device attacks; or
- compromise of Docker's root-equivalent socket.

Use separate hardware or an independently isolated virtual machine when tenant
policy requires a stronger boundary. Steward still provides tenant and action
identity across those hosts.

## Shared-host state requires OpenZFS

Steward ships a separate OpenZFS worker that creates one dataset per tenant lineage
with hard byte and object quotas. Shared-host persistent state is rejected unless
Executor can negotiate the qualified storage contract. The worker is not portable
to a host without OpenZFS, and it adds trusted host authority: it runs as root, can
administer the selected ZFS subtree, and can reach Docker's root-equivalent socket.

Docker's portable local volume driver still has no reliable hard byte or object
quota. Steward exposes it only through the explicit dedicated-host compatibility
setting, and only when signed policy contains one tenant. That setting does not
create a shared-host storage-isolation claim. See
[Configure quota-enforced persistent state]({{ '/guides/persistent-state/' |
relative_url }}).

## Gateway is trusted

Gateway reads reusable inference and connector credentials, chooses configured
upstream origins, and enforces permits and spend state. A compromised Gateway or
host root can misuse those credentials.

Gateway strips agent-supplied authorization and rejects configured credential
values from returned headers and decoded response bodies. It cannot prove that an
upstream did not transform the secret, disclose another secret, encode private
origin information, or return harmful content. Configure only trusted upstreams
and minimize each credential's provider-side permissions.

## Secret storage is external

Steward validates a provider-neutral owner-only file handoff. It does not:

- encrypt or replicate a secret database;
- operate or unseal a vault;
- manage provider authentication or leases;
- recover provider state;
- attest that value and epoch files were rendered atomically; or
- erase plaintext from kernel buffers, crash dumps, backups, or Gateway memory.

If the materializer fails, the last file may remain. Monitor provider health and
rotation epochs, and disable affected routes when freshness is uncertain.

## The control plane is not a signing authority

Steward Control stores tenant-scoped inventory, enrollment state, command
envelopes, and witnessed evidence. It does not need tenant command, task, or action
private keys. Keep those keys on an operator workstation, hardware token, or
offline signing station.

`stewardctl site init` initially writes all new private roles into one owner-only
handoff directory so it can publish an internally consistent package atomically.
That directory is not a long-term key store. Separate site-root, publisher,
incident-response, tenant lifecycle, tenant task, action, Control CA, and Control
server keys according to the generated custody guidance before deployment. Package
verification without an independently pinned site-root public key proves internal
consistency, not the origin of the whole package.

The embedded console previews and transfers an already signed command. It does not
verify the command signature locally; Executor remains the signature enforcement
point. A compromised browser can misrepresent the preview or steal the operator
bearer. Compare the displayed file digest with the signing station and use a
hardened operator browser profile.

`site connect` uses a site-administrator bearer to create one tenant and issue a
tenant-scoped operator. Steward writes the new bearer to an owner-only file and
stores only its path in the selected CLI context. It is not a secret manager: it
does not rotate, escrow, remotely distribute, or revoke either credential. Move
long-lived credentials into the operator's chosen secret system and update the
context path when custody changes.

`site node prepare` creates an owner-only handoff containing a short-lived
enrollment bearer. Anyone who obtains it before activation can race the intended
node, although Control still requires a valid receipt-key proof and binds the
result to the named node and tenant. Transfer the handoff confidentially, keep the
independent site-root pin separate, use a short expiry, and revoke a node whose
handoff may have been exposed.

`site node activate` retains the reusable node credential and receipt private key
in its owner-only output directory so a lost response can be resumed safely. That
directory is sensitive node identity state. The command does not remotely copy
files, invoke the privileged installer, attest the host, or prove that the person
running it is on the intended physical machine.

## Composed setup commands stop at trust boundaries

`agent publish` and `agent authorize` make the common path shorter, but they are
not a key-management service. By default they read the publisher and tenant-command
private keys from the protected `site init` handoff directory. Move those roles to
their intended long-term custody before retiring the handoff and use the lower-level
signing commands when an offline or hardware-backed signer owns them.

`agent service activate` validates and writes Gateway configuration and exports a
new or byte-identical service-trust inventory. It prints the required `systemctl`
action but does not run it, import the image, or copy files to an operator machine.
An existing Gateway configured with a different receipt identity is not silently
relabeled or migrated; drain it and begin a deliberately new receipt chain.

The service-trust inventory contains no credential or private key, but it is not
independently signed. Authenticate its transfer from the enrolled node. `site task
connect` checks its structure and bindings against the signed site policy before
recording paths in the CLI context; that validation does not prove who transported
the file.

## MCP is privileged local automation

`steward-mcp` can expose node lifecycle and control operations to an MCP client.
Its token files determine its authority. MCP tool descriptions and confirmation
fields do not make an untrusted MCP client safe.

Run MCP as a separate local process with the least-privileged token that satisfies
the intended workflow. Do not expose an Executor operator or host-administrator
token to the agent being supervised. Pre-signed task tools still depend on the
scope and correctness of the supplied signed bundle.

## Network policy is application-layer mediation

Capability networks prevent a workload from using the Docker bridge gateway to
reach host services. Relay and Gateway enforce configured HTTP(S), service,
connector, and inference routes. Steward is not a general transparent firewall,
service mesh, DNS security product, or packet-inspection engine.

Images that require raw TCP or UDP, transparent interception, peer discovery,
arbitrary inbound ports, or a general proxy may not fit Steward's closed runtime.
Do not add broad host networking to make them fit.

## Exact permits have operational tradeoffs

A request-byte permit is intentionally brittle: any change to canonical bytes,
operation policy, instance generation, action context, or deadline invalidates it.
That prevents authority from silently drifting, but requires a new approval when
the request legitimately changes.

Spend-before-network durability prevents a retry from causing a second external
effect. A crash after dispatch but before a terminal observation can produce
`outcome_unknown`. Steward fails closed instead of guessing. Reconcile that task
with the external system and retained receipt identity before authorizing another
effect.

Multi-party approval proves that distinct configured keys signed the same bytes.
It does not prove signer independence, informed human review, or a valid business
reason.

## Evidence is enforcement evidence, not truth

Signed receipts establish that a Steward key signed a canonical event chain and
that later events link to earlier events. They do not establish:

- that host root and the signing key were uncompromised;
- that the agent's natural-language result is accurate;
- that an upstream completed its business operation;
- that wall-clock time from separate systems is mutually trustworthy;
- that omitted unmanaged activity did not occur; or
- hardware attestation.

Preserve trusted public-key fingerprints and last accepted sequence/hash
checkpoints outside the node. Without an external checkpoint, a valid older prefix
can look internally correct.

Receipts deliberately omit raw prompts, request bodies, response bodies, terminal
agent result text, and secret values. That protects content but can limit forensic
detail.

The incident timeline and support bundle follow the same metadata-only boundary
and also exclude command envelopes, credential values, private keys, and logs.
The timeline joins the latest retained controller facts; it is not an append-only
audit log and cannot reconstruct overwritten or removed transitions. The bundle
is a strict, owner-only snapshot of several controller reads, not an atomic
database snapshot or a signed attestation. Objects can change while collection
is in progress; repeated node records that disagree fail the collection instead
of being silently merged. Offline verification requires a SHA-256 digest retained
through a separate trusted channel. That detects changed bytes but does not prove
who created the bundle. Tenant-scoped bundles omit site-admin-only evidence
checkpoints and the site-wide freeze record.

## Air-gapped does not mean supply-chain verified

Steward can build and run without a hosted service and can import OCI archives
offline. Operators must still authenticate:

- Steward release artifacts and installer scripts;
- gVisor and Docker packages;
- agent source, dependencies, and base images;
- model files and inference servers;
- public keys and key IDs; and
- transferred configuration and evidence.

A SHA-256 checksum detects byte changes after a trusted digest is known. It does not
authenticate the party that supplied both the file and checksum.

## Agent qualification is narrow

The included Hermes and OpenClaw procedures cover exact pinned adapters, platforms,
skills, and bounded service APIs. They do not establish the safety of arbitrary
plugins, channels, browser tools, MCP servers, models, prompts, or future upstream
versions.

Re-run the documented feasibility and acceptance gates for every changed source
revision, adapter, base image, platform, or capability set. Qualification is test
evidence, not deployment authority; signed site policy and live admission remain
separate.

## Capacity and recovery are finite

Steward's journals, receipt stores, replay indexes, command inventory, evidence
captures, and request bodies have fixed caps. This prevents unauthenticated or
tenant-scoped growth from exhausting the host, but it means operators must monitor
capacity and preserve/delete records through documented procedures.

A full durable store fails closed. Do not delete replay or evidence state merely to
restore availability. First preserve the relevant evidence and understand which
replay or rollback guarantee the deletion would remove.

An operational freeze is not revocation or an instant stop. It prevents Control
from retaining and delivering new signed commands for one tenant or the whole
site, and pauses reconciliation before the next command boundary. A command
already leased to Executor may still complete, and a running workload keeps its
existing identity, lease, and authority. Responders must separately quarantine a
suspected node, revoke compromised credentials or delegations, and preserve
evidence as the incident requires. Heartbeats, reports, and evidence remain open
during a freeze so containment does not erase visibility.

## Desired-state reconciliation is intentionally narrow

`stewardctl agent plan` performs deterministic filtering and scoring over a bounded
node inventory. `stewardctl agent apply` can use that result to derive an exact
intent, submit it through signed admission, and start the workload on one node.
`stewardctl agent deploy` can sign the exact admit/start sequence locally, transfer
it through Control, and wait for authenticated node reports.

`stewardctl agent deployment apply` instead records durable desired state. The
single active controller chooses an active allowed node deterministically and
drives `admit`, `renew`, `start`, `stop`, and `destroy` through a tenant-signed
delegation.
It survives restart without duplicating a queued command. Executor independently
checks the tenant delegation and controller signature. A failed or
`outcome_unknown` command becomes `degraded` and is not silently retried.

A ready deployment can roll to a higher signed generation without discarding its
source authority. Rollout is restart-safe, limited by `max_unavailable`, and
switches each instance to target authority only after Executor proves the source
runtime was destroyed. It is an in-place replacement: there are no surge replicas,
automatic rollback, or rollout health probes beyond the authenticated lifecycle
result. Rollback requires a new higher generation and fresh signed delegation;
Steward never moves generation fences backward.

A ready deployment retains the exact verified instance intent and authenticated
Executor admission projection needed for task issuance. `agent deployment wait`
can export one instance, and `task run` joins deployment wait, task issuance,
dispatch, terminal observation, and result storage. It persists the signed task
bundle before dispatch so recovery reuses the same authority instead of risking a
duplicate effect.

New placement requires a recent authenticated node poll and scheduling
observation. A pending instance records `no_eligible_node` when none of its
delegated nodes is fresh and capable, or
`scheduling_observation_unavailable` when an otherwise eligible node has no
current resource profile. Architecture, signed labels, isolation, taints, and
tolerations are checked before placement.
Controller cordon excludes a node from new placement without disturbing its
current assignments. Quarantine also stops new command leases and treats the
node as unavailable for lease-fenced stateless recovery while preserving its
authenticated liveness and evidence channel. A planned controller drain first
cordons, then moves stateless instances only when another eligible node exists
and the deployment's maximum-unavailable budget has room. Each move has bounded
downtime because Steward destroys the source before admitting the replacement;
it does not create an unproven surge copy. Stateful instances report
`stateful_drain_unsupported`. None of these operations proves that a compromised
host is trustworthy or replaces Executor's node-local package-activation fence.
A lease-managed stateless instance can be replaced after node loss. Control
retains the latest signed expiry that Executor could have accepted and waits
through that time plus the two-minute command clock-skew allowance. Executor
locally deactivates Gateway authority and stops the trusted relay and agent at
expiry. Control then advances the instance generation within the tenant-signed
range before placing it again. A lost response can extend the wait but cannot
shorten it.

This is service fencing, not hardware fencing. Host root, Docker, gVisor, the
Executor supervisor, and the machine clock remain trusted. Stopping
`steward-executor` can delay local enforcement until the service restarts; the
package configures automatic restart and runs reconciliation before polling or
accepting mutations. A Control outage eventually stops lease-managed agents, so
the lease duration is also an availability bound.

An older delegation without `renew` reports `assigned_node_unavailable` and stays
assigned. A stateful instance reports `stateful_replacement_unsupported` because
local Docker state cannot be attached safely on another node. Exhausting the
tenant-signed generation range reports `replacement_generation_exhausted`.
Before a safe expiry, status reports `awaiting_lease_expiry`. These retryable
reason codes do not change the instance to a terminal phase, and repeated checks
do not append repeated durable records.

The reconciler durably reserves aggregate CPU, memory, process, tenant, and
workload-slot capacity with admission. A site-defined tenant resource quota can
also cap the raw signed requests across all nodes. That global ceiling does not
measure fixed runtime overhead, disk bytes, inodes, or I/O, and lowering it does
not evict existing agents. It enforces a per-deployment
maximum-unavailable budget for planned stateless node drains. It does not
schedule disk or persistent state bytes, preempt workloads, provide minimum
healthy duration or surge semantics, perform progressive rollouts, or autoscale.
Docker volumes do not provide a portable hard-quota contract, so stateful
capacity remains a documented gap. Executor revalidates admission and live
capacity, so unmanaged containers or a stale decision fail closed rather than
overruling the node.

An in-place rollout starts only from a `Ready` deployment, with every instance in
the `Running` phase. Steward retains both generations' signed authority and moves
instances within the deployment's maximum-unavailable budget. A deployment with
an instance in `Pending`, `Failing`, `Stopping`, or another non-running phase
cannot start a rollout; recover it to `Ready` or use an explicit remove, wait, and
apply sequence. Rollouts do not provide surge capacity or automatic rollback, so
a single-replica deployment is unavailable while its instance is replaced.

`task run` must execute where its Gateway service endpoint is reachable through a
literal loopback address, normally on the selected node or through an operator-
managed authenticated tunnel. Control does not relay prompts, task bodies, result
bytes, Gateway bearer tokens, or task private keys. Multi-instance deployments
require an explicit instance selection.

## Forks clone state, not a live agent

An agent fork plan binds a new instance and lineage to immutable snapshot
metadata. A forked deployment invokes the qualified OpenZFS worker through signed
Executor commands, admits the cloned state, and runs the normal agent lifecycle.
Temporary forks automatically stop, destroy, and purge at expiry. Steward does not
clone process memory or replicate snapshots between nodes. The source node must
remain available until every fork clone has been purged; Steward blocks rather than
moving node-local state without proof.

Never place credentials, task permits, receipt keys, live tokens, runtime IDs,
network sessions, or random-number-generator state in a snapshot. A fork receives
fresh authority through normal admission.

Snapshot quarantine prevents only new forks from one exact tenant, source node,
and snapshot identity. It does not scan the snapshot, prove contamination, delete
storage, revoke an already-created fork, stop a running workload, or contain the
source node. Cleared records remain and count toward the bounded per-tenant
retention limit so revision history cannot be reset by deleting a decision.

## Current product scope

Steward is not:

- an agent reasoning framework, prompt graph, or planner;
- a model scheduler or inference server;
- a general container orchestrator;
- a secret manager;
- an identity provider or single sign-on system;
- a software supply-chain provenance service;
- an endpoint detection and response product;
- a general policy engine;
- a general cluster scheduler or storage replication manager; or
- a hosted control plane.

It is the local enforcement plane between an untrusted containerized agent and
managed external authority. If an important effect cannot pass through Steward's
Executor, Relay, or Gateway boundary, Steward cannot constrain or prove it today.
