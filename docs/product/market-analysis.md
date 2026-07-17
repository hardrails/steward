---
title: Agent execution market analysis
description: A source-backed comparison of agent platforms with Steward's local signed admission, Authorized Effects, durable replay control, independent evidence witnessing, and offline verification.
section: Product
---

# Agent execution market analysis

> Source note: Reviewed 2026-07-17 using linked public primary sources. Product
> pages change, so recheck them for procurement. A documented feature is not a
> security certification, and an omitted feature is not proof that a vendor
> cannot provide it.

Several products offer hardened containers or microVMs—small virtual machines with
their own kernel—plus egress policy, lifecycle APIs, organization controls,
observability, audit logs, and self-hosted fleet controllers. These controls no
longer distinguish a runtime by themselves.

Steward focuses on a customer-owned controller and nodes. Enrollment binds one
node to a receipt-key identity through proof of possession. The controller
transports already signed commands without holding tenant signing keys and can
independently witness bounded, signed Executor evidence batches. A retained
checkpoint or sticky rollback or equivocation finding can be exported under a
separate controller witness key for offline verification. Evidence publication is
asynchronous and does not gate local enforcement.

Nodes verify local authorization and grant only approved state, inference,
service, and network operations. For configured agent-service operations, a
tenant-owned key can sign one exact request while remaining off-node; Gateway
records authorization before dispatch and retains node-local replay state. The
product boundary assumes the agent can be manipulated. For selected connectors,
signed tenant policy can require a connector-scoped action key, prohibit generic
egress, require one or more distinct tenant approvers, and make Gateway spend a
single-request or bounded exact-effect authority before DNS.
Enforcement remains outside the agent process.

Among the products reviewed below, none documents an equivalent combination of
customer-operated air-gapped fleet control and nodes, receipt-key proof during
enrollment, publisher-signed artifacts, site-root-signed policy, authenticated
tenant intent, controller-blind tenant signing keys, fenced exact-command delivery,
service-scoped off-node task keys,
exact-request service dispatch, connector-scoped Authorized Effects with
policy-enforced separation of duties and spend-before-DNS replay control, an independently retained receipt checkpoint with
rollback or fork findings, and offline-verifiable authorization-to-outcome
evidence. “Not documented” is not proof that a product lacks an internal or future
capability. This is not a first, only, or certification claim.

Self-hosting is not the differentiator. OpenClaw Machines, OpenSandbox, Kubernetes
Agent Sandbox, and other systems document customer-operated control components.
The comparison below evaluates the narrower authorization, replay, and evidence
boundary instead.

## Differentiation: signed separation of duties

The market increasingly treats a host prompt that says “approve this network
request” as human oversight. That is useful, but it leaves one operator session
able to widen network policy and usually authorizes a destination rather than one
immutable business action. Steward's stronger boundary is policy-enforced dual or
multi-party control: separate tenant keys sign the same exact request artifact or
the same bounded set of up to eight exact requests, and Gateway cannot resolve DNS
until the signed threshold is complete. A bundle reduces repeated approval without
letting the agent invent new requests during an approved session.

| System | Documented approval unit | Distinct approvers required by policy | Exact request and runtime binding | Portable offline proof |
| --- | --- | --- | --- | --- |
| Steward | One exact connector request, or an unordered set of up to eight exact requests | Yes; 1 through 8 tenant-scoped Ed25519 authorities, with omission preserving one approver | Tenant, node, instance generation, capsule, site policy, route policy, every operation policy, task and request, expiry, threshold, and signer set | Yes; the final artifact and format-5/6 authorization and terminal receipts bind each independently spent task to the same canonical authority |
| [NVIDIA NemoClaw / OpenShell](https://docs.nvidia.com/openshell/sandboxes/policy-advisor) | A blocked network operation can become a policy proposal; human or automatic approval adds the rule to the running sandbox policy and hot-reloads it | Not documented in the reviewed approval flow | The proposal widens session policy for matching future operations; an equivalent multi-signature exact-request artifact was not found | OCSF policy events are documented; an equivalent signed multi-approver permit-to-terminal proof was not found |
| [Docker AI Governance](https://docs.docker.com/ai/sandboxes/governance/) | A policy decision under organization governance | Not found in the reviewed sources | Decision policy is documented; an off-workload multi-signature exact-request artifact was not found | Decision logs are documented; an equivalent customer-verifiable signed chain was not found |
| [Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/what-is-bedrock-agentcore.html) | Managed runtime, identity, gateway, and tool policy | Not found in the reviewed sources | Managed authorization is documented; an equivalent customer-held threshold artifact was not found | OpenTelemetry observability is documented; an equivalent offline signed chain was not found |

This is a documented-feature comparison, not a claim that another system cannot
implement dual control. Steward's moat is the continuity of the threshold across
signed local policy, offline keys, immutable runtime labels, Gateway enforcement,
durable replay state, upgrade fencing, and offline receipts.

## High-level capability matrix

| System | Customer-operated or disconnected boundary | Fleet coordination boundary | Exact operation policy | Separately signed exact request or effect | Durable one-use and replay state | Independent evidence checkpoint and offline verification |
| --- | --- | --- | --- | --- | --- | --- |
| Steward | Documented for a self-hosted controller and customer-owned Linux nodes, including air-gapped transfer | Bounded single-writer controller: scoped operators, one-time multi-tenant node enrollment with receipt-key proof, inventory, and fenced delivery of exact signed commands; tenant signing keys stay outside it | Documented for agent-service POSTs and connector methods/paths; Authorized Effects prohibits generic egress for the grant | Documented tenant keys scoped by signed policy to service IDs or connector IDs; policy can require distinct approvers over one exact request or a bounded exact set | Documented controller delivery fencing plus durable one-use connector spend before DNS and node-local task spend within one retained ledger epoch | Documented node-signed hash chain, format-5/6 authorized-effect evidence, independently retained controller checkpoint, sticky rollback/equivocation finding, controller-signed offline export, and offline task/permit correlation |
| [OpenClaw Machines](https://github.com/mathaix/OpenClawMachines) | Apache-2.0 customer-operated control plane and KVM hosts are documented. Its production-shaped deployment uses Cloudflare DNS, Tunnel, Worker, and KV; local evaluation can omit Cloudflare | Postgres-backed accounts and teams, host enrollment, placement, machine lifecycle, durable workflows, backups, and Firecracker workers are documented | Native MCP and workspace integrations are documented; an equivalent site-root-signed exact-operation fence was not found in the reviewed sources | Not found in the reviewed sources | Durable workflows are documented; an equivalent tenant-signed exact-task spend ledger was not found | Backups and OpenTelemetry/Opik observability are documented; the reviewed sources did not document an offline signed authorization-to-terminal chain |
| [NVIDIA NemoClaw / OpenShell](https://github.com/NVIDIA/NemoClaw) | OpenShell documents local and cluster drivers; deployment scope varies by driver | Local and cluster sandbox providers are documented; the reviewed sources did not document Steward's separate tenant-signed command queue and node verification boundary | Documented REST, GraphQL, MCP, JSON-RPC, and WebSocket policy | Endpoint-scoped identity tokens are documented; an off-node signature over one exact task request was not found in the reviewed sources | An equivalent exact-task spend ledger was not found in the reviewed sources | Logs and OCSF JSON export are documented; the reviewed sources did not document Steward's offline signed permit-to-terminal chain |
| [Docker Sandboxes / Governance](https://docs.docker.com/ai/sandboxes/governance/) | Local microVM sandboxes are documented; organization governance depends on Docker sign-in | Organization governance is documented through Docker's service rather than a fully disconnected bundled controller | Network, filesystem, credential, and decision policy are documented | Not found in the reviewed sources | Not found in the reviewed sources | Decision logs are documented; the reviewed sources did not document offline permit-to-terminal signature verification |
| [OpenSandbox](https://github.com/alibaba/OpenSandbox) | Self-hosted Docker and Kubernetes backends are documented | A distributed sandbox API and runtime lifecycle are documented | Sandbox lifecycle and runtime isolation are documented | Not found in the reviewed sources | Not found in the reviewed sources | Not found in the reviewed sources |
| [Kubernetes Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) | Customer-operated Kubernetes is supported | Kubernetes supplies the cluster control plane; Sandbox claims and pools coordinate runtime capacity | Templates, claims, lifecycle, and isolation are documented | Not found in the reviewed sources | Not found in the reviewed sources | Not found in the reviewed sources |
| [Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/what-is-bedrock-agentcore.html) | AWS-managed service with VPC integration | AWS-managed runtime and identity control | Managed identity, gateway, tools, and observability are documented | Not found in the reviewed sources | Managed runtime semantics differ; an equivalent customer-held exact-task spend ledger was not found | OpenTelemetry observability is documented; the reviewed sources did not document a customer-verifiable offline signed chain |

## Comparison

| System | Documented focus | Where Steward's focus differs |
| --- | --- | --- |
| [OpenClaw Machines](https://github.com/mathaix/OpenClawMachines) | Its Apache-2.0 public core documents a Go and Postgres control plane with accounts, teams, placement, durable workflows, host enrollment, lifecycle, and backups; one Firecracker microVM per OpenClaw agent; per-host LiteLLM; browser VMs; native MCP integrations; and a Cloudflare data plane. The production-shaped self-hosting guide requires Cloudflare DNS, Tunnel, Worker, and KV, while local evaluation does not. The controller still needs private or firewall-restricted access to each host agent's authenticated API on port `9090`. | Steward does not match its accounts, placement, browser, Firecracker, or integration breadth. Steward's narrower boundary is portable Docker and gVisor nodes plus an optional controller that needs no Postgres or Cloudflare: tenant keys remain outside the controller, nodes verify publisher-signed artifacts and site-root-signed tenant policy, delivery and local task replay are durable, and a node's next report can expose rollback or a fork relative to an independently retained checkpoint before a controller-signed export is checked offline. |
| [NVIDIA NemoClaw](https://github.com/NVIDIA/NemoClaw) / [OpenShell](https://github.com/NVIDIA/OpenShell) | NemoClaw packages Hermes, OpenClaw, and LangChain Deep Agents around OpenShell. OpenShell documents Docker, rootless Podman, microVM, and Kubernetes drivers; exact REST method, path, and query rules; provider-owned network layers; credential placeholders and rewrites; endpoint-scoped token grants using SPIFFE JWT-SVID; and inspection for REST, GraphQL, MCP, and JSON-RPC. Its [Policy Advisor](https://docs.nvidia.com/openshell/sandboxes/policy-advisor) can turn denied operations into human- or automatically approved rules that hot-reload into the running sandbox policy. Both current READMEs label the projects alpha; OpenShell describes its current mode as one developer, one environment, and one gateway, and marks Kubernetes deployment experimental. See the current [policy schema](https://docs.nvidia.com/openshell/reference/policy-schema) and [provider architecture](https://docs.nvidia.com/openshell/sandboxes/providers-v2). | Steward does not claim sandboxing, method/path policy, credential injection, or Hermes packaging as unique, and OpenShell documents broader application-protocol inspection. Steward's narrower difference is Authorized Effects on a disconnected, vendor-independent node: site-root-signed tenant policy pins connector/action-key scope and can require separate approvers over one exact request or one bounded exact set; Gateway durably spends each selected task before DNS; credentials stay outside the workload; tenant evidence capacity does not borrow; and an auditor can verify the signer threshold and partial execution offline. Steward's browser courier likewise transports one immutable command signed elsewhere instead of turning a browser or agent proposal into new policy authority. Maturity labels can change and should be rechecked. |
| [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) / [AI Governance](https://docs.docker.com/ai/sandboxes/governance/) | Docker documents microVMs, filesystem and network policy, organization sign-in, decision logs, credential injection, DNS policy, and workspace sharing. Linux installation requires Kernel-based Virtual Machine (KVM) support and Docker sign-in; organization governance is a paid capability. | Steward uses Docker and gVisor on an operator-owned node without requiring a vendor login or hosted policy service. It does not claim isolation, egress policy, DNS gating, credential injection, or JSON audit as unique. |
| [OpenSandbox](https://github.com/alibaba/OpenSandbox) | OpenSandbox documents a sandbox API, Docker and Kubernetes backends, lifecycle control, and [gVisor, Kata, and Firecracker runtimes](https://open-sandbox.ai/guides/secure-container). | Steward adds site-owned admission, tenant/instance replay protection, and operator-verifiable receipts. The projects could complement each other; Steward does not depend on OpenSandbox. |
| [Kubernetes Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) | The Kubernetes SIG project documents `Sandbox` Custom Resource Definitions (CRDs), templates, claims, warm pools, state, and optional gVisor or Kata isolation. Kubernetes itself [does not define a first-class tenant object](https://kubernetes.io/docs/concepts/security/multi-tenancy/); operators must assemble the isolation policy. | Steward provides one opinionated tenant and evidence contract on a Linux node without making Kubernetes a prerequisite. A future backend could preserve that contract on Kubernetes. |
| [E2B](https://github.com/e2b-dev/infra) | E2B provides a Firecracker sandbox platform. Its [self-host guide](https://github.com/e2b-dev/infra/blob/main/self-host.md) combines Terraform, Packer, PostgreSQL, DNS, and cloud-specific infrastructure; that is a capable platform, not a one-node offline package. | Steward does not recreate a microVM platform. It provides an offline, site-policy-controlled deployment and evidence boundary for long-lived agents on Docker/gVisor. |
| [Daytona](https://github.com/daytonaio/daytona) | The public repository contains a broad sandbox API, but its README says public core development stopped and moved to a private codebase. The frozen public source remains under the [GNU Affero General Public License](https://github.com/daytonaio/daytona/blob/main/LICENSE). | Steward's open repository remains the complete node enforcement product. Independent rebuildability and offline maintainability are part of the boundary, not an installation option around a private core. |
| [OpenClaw](https://github.com/openclaw/openclaw/security) | OpenClaw provides agents, tools, skills, memory, and optional Docker sandboxing. Its security documentation says one gateway is not an adversarial multi-tenant boundary and that session or memory scoping does not create per-user authorization. | Steward treats the OpenClaw image, tools, memory, and configuration as untrusted workload content. Its exact-release adapter qualifies only a one-shot API and one real custom skill with `read` and `exec` inside the outer gVisor capsule. OpenClaw supplies agent behavior; Steward supplies the external tenant, network, credential, resource, admission, and evidence boundary. |
| [Hermes Agent](https://github.com/NousResearch/hermes-agent/security) | Hermes provides skills, plugins, subagents, scheduled work, and several execution backends. Its security documentation describes a single-user personal-agent model and warns that skills and plugins run with the agent's authority. | Steward qualifies one exact Hermes build and places policy, credentials, resource controls, and evidence outside Hermes. It does not rely on the agent's own permission model for tenant isolation. |
| [Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/what-is-bedrock-agentcore.html) | AgentCore documents managed runtime, identity, memory, MCP gateway, code interpreter, browser, and OpenTelemetry observability. Its [Virtual Private Cloud (VPC) guide](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html) describes AWS-managed network interfaces and Identity and Access Management (IAM) service roles. | Steward serves operators who require local keys, artifacts, infrastructure, and operation without a vendor control plane or public Internet. It does not claim an equivalent managed-service portfolio. |

## Adjacent operator-experience signal: WorkFlux

[WorkFlux](https://www.workflux.ai/docs) is a hosted vertical-automation product,
whose public materials do not document a customer-operated runtime or disconnected
fleet controller. Its
[system requirements](https://www.workflux.ai/docs/system-requirements) describe a
cloud-based platform that requires Internet connectivity and customer integration
credentials. Its [privacy policy](https://www.workflux.ai/privacy) says the service
collects configuration, API credential, integration, usage, and third-party
integration data. WorkFlux therefore belongs outside the security capability
matrix above.

Its public product flow provides useful operator-experience lessons:

- the [agent catalog](https://www.workflux.ai/docs/agents-overview) starts with
  recognizable outcomes, integrations, suitability, and metrics instead of an
  abstract orchestration primitive;
- the [quick start](https://www.workflux.ai/docs/quick-start) leads the operator
  through choose, configure, test, activate, and monitor;
- [escalation rules](https://www.workflux.ai/docs/escalation-rules) and
  [webhook events](https://www.workflux.ai/docs/webhooks) make human-attention
  states explicit, including escalation and integration errors; and
- the [metrics guide](https://www.workflux.ai/docs/key-metrics) connects activity,
  latency, resolution, and efficiency measures to operational review.

The public pages are not fully consistent. The
[catalog documentation](https://www.workflux.ai/docs/agents-overview) describes
12 agents, while the [catalog page](https://www.workflux.ai/agents) and current
[pricing page](https://www.workflux.ai/pricing) describe 16. The
[quick start](https://www.workflux.ai/docs/quick-start) describes a Professional
bundle of 3–5 agents for $1,299 per month, while the pricing page describes five
agents for $999 per month. Individual prices also differ between pages. These
sources are useful evidence of product patterns, not validated procurement,
availability, or performance data.

WorkFlux also describes its agents as production-ready and advertises rapid
deployment, uptime, return on investment, savings, and outcome measures. This
analysis found those statements on WorkFlux's own pages; it did not independently
test or validate them.

### Borrow the journey; own the proof

Steward should reuse the understandable progression from useful outcome to
configuration, activation, and monitoring. It should not reuse hosted credential
custody, vendor-controlled evidence, or Internet-dependent operation.

The first four rows describe bounded Steward contracts. They do not imply a broad
hosted catalog, semantic workflow engine, or automatic remediation system. A
durable notification outbox remains future work.

| WorkFlux pattern | Steward translation | Boundary |
| --- | --- | --- |
| Outcome-led release artifact | A publisher-signed agent release names the useful outcome and binds the exact workload capsule, offline archive, deterministic canary, qualification-evidence digest, and known limitations. A separately curator-signed offline catalog can group exact releases and expose their signed capabilities, resources, service shape, validity, and artifact identities for local search and comparison. | Publisher and curator text is descriptive metadata. Neither signature authorizes a tenant, node, image import, capability, or task, and neither proves that the outcome occurred. Catalog revision monotonicity remains an operator distribution responsibility. |
| Guided activation | Use one local choose/configure/preflight/activate/canary/prove/monitor journey. Bind exact inputs in an unsigned plan, retain sequential state in an owner-only append-only workspace, derive the canary challenge from real admission, keep the default task-signing key off-node, verify one deterministic Hermes result, and correlate signed evidence for offline review. | The state machine accepts no arbitrary hooks or workflow code. Invalid canary authority, terminal canary failure, retained-evidence conflict, and expiry of the absolute canary deadline become sticky `action_required`; other transient local, network, and incomplete evidence-source errors remain retryable while their applicable deadline is open. Replacement requires a new activation ID and higher instance generation after the failed workload is stopped and destroyed. The initial recipe is only the closed node-local Hermes workspace audit and requires a dedicated host with exactly one policy tenant because its persistent volume has no hard storage quota. |
| Action-required lifecycle | Derive one tenant-projected fleet view for never-seen or stale nodes, missing or stale evidence, rollback or equivocation findings, overdue or expired command delivery, failed or unknown command outcomes, and retained-state capacity pressure. | Findings are deterministic observations, not mutable tickets. Steward does not let a model acknowledge, dismiss, retry, or clear them, and it does not infer approval from operational state. |
| Operational metrics | Expose opt-in authenticated controller metrics for retained-state capacity, command state and terminal outcome, evidence state, and attention reason and severity. | Metrics use fixed bounded labels and exclude tenant, node, credential, and command identifiers, prompts, bodies, results, credentials, and vendor-defined return-on-investment claims. Evidence-report freshness becomes conservatively unknown after a controller restart until the node reports again. |
| Event notifications | Build any notification surface on a bounded durable local outbox that can be polled or exported. | Outbound webhooks remain optional adapters; Internet delivery cannot become part of enforcement or recovery. |

### What Steward should reject

Steward should not copy WorkFlux's cloud credential and data model. The WorkFlux
flow expects customer API credentials, dashboard accounts,
[OAuth client credentials and bearer access tokens](https://www.workflux.ai/docs/api-authentication), and
business-system data. Steward's core should continue to keep tenant signing keys
outside the controller, add operator-owned connector credentials only at the
local Gateway's last hop, exclude prompts and bodies from receipts, and operate
without a vendor account or public API.

Vertical conversation behavior, customer records, business return-on-investment
calculations, and human case routing belong in independently qualified agents,
skills, or customer systems. WorkFlux's marketing, compliance, uptime, and outcome
claims were not independently verified for this analysis.

## Common platform capabilities

These capabilities remain useful but do not distinguish Steward:

- isolated execution with a container, gVisor, Kata, Firecracker, or microVM;
- a self-hosted fleet controller, host enrollment, placement, or lifecycle API;
- sandbox creation, pause/resume, snapshots, templates, or pools;
- network allowlists and default-deny rules;
- filesystem restrictions and secret injection;
- organization roles, quotas, OpenTelemetry, dashboards, or JSON audit logs;
- a generic code-execution, browser, or agent SDK.

These controls remain useful. Docker and gVisor are Steward's required host
foundation, not its primary differentiator.

## Durable differentiation

Steward is open source, so its defensibility cannot depend on hiding an API or
forcing an operator through a hosted service. It comes from an accumulated public
assurance contract:

- the same signed artifact, site policy, tenant intent, runtime grant, and receipt
  identities remain bound across admission, Docker, Gateway, and offline tools;
- the bundled controller enrolls multi-tenant nodes and durably transports exact
  signed commands while tenant keys, approval decisions, and Docker authority stay
  outside its process;
- enrollment binds the control-node identity to a node-held receipt key through a
  signed proof of possession, and rejects reuse of that receipt identity across
  nodes;
- Executor can publish signed, bounded evidence deltas independently from command
  polling; the controller reports `unwitnessed`, `current`,
  `rollback_detected`, or `equivocation_detected`, retaining one last-good
  coordinate and one sticky finding instead of becoming a receipt warehouse;
- a purpose-separated controller witness key signs portable evidence exports, while
  local admission and agent operation continue when the evidence uplink is
  unavailable;
- selected service and connector effects can require tenant-scoped off-node
  signatures over exact request bytes, with permit and request digests retained
  beside stable task identity and terminal observations in Gateway's signed chain;
- hostile-path tests exercise replay, state rollback, credential substitution,
  address rebinding, partial writes, process restart, and ambiguous external
  effects;
- qualified adapter fixtures prove useful work by an exact agent build instead of
  treating container startup as successful integration;
- release manifests declare every durable state format so an upgrade cannot
  silently install a reader or writer that corrupts existing authority; and
- the complete fleet and node enforcement path builds and operates without a private
  package, vendor account, or public control plane.

A competing product can add any one of these features. Matching Steward's claim
requires keeping the whole chain coherent as formats, adapters, runtime behavior,
and upgrade paths evolve. That compounding verification work is the intended
differentiator; it is not a claim that the implementation is immune to defects.

## Adversarial and Pareto selection

Work is compared on operator value, differentiation, risk reduction, delivery cost,
and whether a hostile-path test can prove the claim. Pareto selection keeps work
for which no alternative is better on every material dimension. The adversarial
pass starts with a separate question: *how could a manipulated agent turn this
feature into another tenant's incident or an unverifiable external effect?*

### Independent evidence witnessing increment

The selected design extends the node-held signed receipt chain without moving raw
receipts into the controller. Enrollment pins the node's receipt public key through
proof of possession. Executor then publishes bounded contiguous batches on an
independent loop. The controller verifies every frame, retains the last-good head,
and makes the first authenticated rollback or equivocation finding sticky. A
separate controller witness key signs an export that an offline verifier can check
against an out-of-band pinned public key.

| Candidate | Adversarial failure considered | Operator value | Assurance and ownership cost | Pareto decision |
| --- | --- | --- | --- | --- |
| Native bounded controller witness | A compromised or restored node removes a witnessed suffix, reports a lower head, presents a conflicting branch, strips frames from a report, or races two valid branches. | High: when the node next reports, a customer-owned management host can detect divergence relative to its retained checkpoint without receiving prompts or a full receipt archive. | Medium: enrollment identity, signed batch binding, durable compare-and-swap, sticky findings, witness-key continuity, export verification, and upgrade behavior must remain one contract. It does not attest a hostile host, prove freshness when publication stops, or compare split views across controllers. | **Implemented.** It materially improves rollback detection while preserving air-gapped operation, bounded storage, zero dependencies, and local-enforcement independence. |
| Full receipt replication | A controller loses the context needed for later audit because it retained only a head. | Medium: central search becomes easier. | High: duplicates potentially sensitive per-node history, creates an evidence warehouse, expands storage and retention policy, and is unnecessary for rollback detection. | Reject from the controller. Keep full records on the node and export only when an operator chooses. |
| Hosted transparency or SCITT service | A controller and node collude or present different views to different auditors. | High for public or cross-organization transparency. | High for sovereign sites: adds another availability, identity, data-governance, and synchronization authority. It does not replace node enrollment or receipt validation. | Reject as a requirement. Revisit as an optional export sink when a customer explicitly needs public inclusion and consistency proofs. |
| Hardware-backed attestation | A hostile host signs fabricated records with a software-held key. | High in selected threat models. | Very high and platform-specific; hardware identity, measured boot, key lifecycle, verifier policy, and recovery are separate systems. | Defer. The controller witness detects a lower or conflicting head when the node next reports relative to what it observed; it does not prove the node was trustworthy when a record was created. |

The native witness remains on the Pareto frontier because it closes the common
suffix-removal and fork-detection gap with bounded standard-library code and no new
service. Full replication costs more data authority, while public transparency and
hardware attestation address stronger but different threat models.

### Exact service-task dispatch increment

The selected design lets signed site policy assign an off-node tenant key to exact
service IDs. That key authorizes one exact JSON request. Gateway verifies the permit
against the live workload and operation, records authorization before dispatch, and
retains the observed run ID or explicit ambiguity. The agent never receives the
private key, and the signed receipt never contains the raw prompt.

This choice responds to converging primary-source signals. NIST's February 2026
[agent identity and authorization concept paper](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd)
frames identification, authorization, access delegation, logging, accountability,
and provenance as open agent-infrastructure problems. The NSA's May 2026
[MCP security guidance](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/nsa-releases-security-design-considerations-for-ai-driven-automation-leveraging/)
warns that dynamic tool invocation, implicit trust, and context sharing create risks
that cannot be fixed at one interface in isolation. Microsoft's March 2026
[PAuth preprint](https://www.microsoft.com/en-us/research/publication/pauth-precise-task-scoped-authorization-for-agents/)
argues that operator-scoped authorization overprivileges agents and evaluates a
more precise task-scoped design. These sources motivate the boundary; none evaluates
or certifies Steward.

| Candidate | Adversarial failure considered | Operator value | Assurance and ownership cost | Pareto decision |
| --- | --- | --- | --- | --- |
| Tenant-signed exact service task | A manipulated agent changes prompt bytes, reuses a valid broad service grant, races a duplicate, or retries after an ambiguous response. | High: a tenant can approve useful agent work without giving the agent reusable signing authority or exposing a new tenant listener. | Medium: Steward must keep statement, grant, operation, ledger, restart, and offline-audit semantics coherent. The run ID remains untrusted and replay scope remains node-local. | **Implemented as opt-in.** It directly reduces external-effect authority while extending the existing signed admission and evidence chain. |
| Generic JWT bearer | A bearer is copied, replayed, or interpreted with different claims by another component. | Medium: familiar transport and tooling. | Medium to high: a token format does not supply Steward's exact request, runtime, route-policy, spend, unknown-outcome, or receipt semantics; a library would also break the zero-dependency contract. | Reject for this boundary. DSSE signs the existing exact statement without creating ambient bearer authority. |
| Open Policy Agent sidecar | Policy evaluates correctly but its availability, policy language, bundle provenance, or upgrade state diverges from Steward's durable replay ledger. | Medium for organizations already using Rego. | High for disconnected nodes: another binary, policy language, state boundary, recovery path, and dependency still does not record dispatch outcome. | Reject as a required component. External systems may make approvals, but Gateway owns final exact enforcement and evidence. |
| Generic reverse proxy | A caller selects headers, paths, redirects, response semantics, or an operation outside the intended agent adapter. | Medium: broad protocol reuse. | High risk: broad flexibility expands the trusted parser and still leaves task identity and replay behavior unspecified. | Reject. Configure only exact JSON POST operations and return one canonical run-ID response. |
| Approval inside the agent | Prompt injection or a malicious skill approves its own request or reads the signing key. | Low operational friction. | Unacceptable trust inversion: the untrusted workload becomes its own authorizer. | Reject. Keep the task private key and decision outside the sandbox. |

The exact service-task path remains on the Pareto frontier because the alternatives
either leave reusable authority inside the agent, introduce a larger mandatory
dependency without solving replay and evidence, or broaden the protocol surface.
The bounded design does not dominate every future option: fleet-wide replay control,
hardware-backed signing, and cross-controller or public evidence anchoring solve
different threats and remain separate potential layers.

### Multi-party and bundled Authorized Effects increment

The selected design is Authorized Effects: site-root-signed tenant policy can make
the mode optional or required, pins action keys to connector IDs, and can require
multiple distinct approvals. Authenticated intent explicitly selects the mode.
Authorized grants prohibit generic egress and accept either one exact request or a
version-4 unordered set of up to eight exact requests. The policy threshold signs
the complete unchanged artifact. Gateway checks every signer against every bundle
connector, validates every operation against current trusted configuration, and
durably spends each selected task before DNS. “Exact” describes request bytes and
metadata, not exactly-once upstream delivery or an ordered workflow. Existing
connectors retain their broader grant-and-task behavior until the operator opts
into this policy.

The selection assumes that an agent may be manipulated. That assumption is
supported by [NIST's large-scale agent red-team](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition),
which found at least one successful hijacking attack against every tested frontier
model, and by the [OWASP agentic-application risk list](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/),
which includes goal hijack, tool misuse, and identity or privilege abuse. The
[PAuth preprint](https://www.microsoft.com/en-us/research/publication/pauth-precise-task-scoped-authorization-for-agents/)
and [Five Eyes adoption guidance](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services)
are design signals for precise, runtime authorization and integrity-protected
tasks; neither evaluates or certifies Steward.

The [OWASP AI Agent Security Cheat
Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html#high-impact-action-integrity-controls)
specifically recommends separating decisions from execution, binding approval to
the exact action, using short-lived replay-resistant artifacts, and failing closed.
[NIST SP 800-171r3 separation of
duties](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/800-171r3/NIST.SP.800-171r3.html)
addresses abuse of authorized privilege without collusion. OpenShell's documented
[Policy Advisor](https://docs.nvidia.com/openshell/sandboxes/policy-advisor)
shows that operator and automatic proposal approval are becoming standard sandbox
features; its approval unit is a hot-reloaded session policy rule, not a threshold
signature over one exact request. These sources motivate Steward's narrower
control and do not certify it.

| Candidate | Adversarial failure considered | Operator value | Differentiating assurance | Delivery and residual risk | Pareto decision |
| --- | --- | --- | --- | --- | --- |
| Multi-party Authorized Effects | A manipulated workload uses a valid broad grant for different request content, compromises one operator or key, substitutes a same-tenant key, strips one signature, lowers the threshold, downgrades to generic egress or a legacy permit, races the same authority, or retries after an ambiguous result. | High: authorizes useful external work without giving the workload reusable signing or credential authority, and removes one operator as a sufficient cause for selected effects. | High: signed tenant policy pins distinct action keys and a threshold to connectors; intent explicitly selects the mode; generic egress is prohibited; version-3 authority binds node, tenant, instance generation, admitted artifact and policies, exact origin, method, path, credential injection mode and epoch, task, request digest and length, content type, validity window, threshold, and canonical signer set to spend-before-DNS and format-6 evidence. | Medium: requires one coherent policy, intent, statement, handoff, signing, Gateway, ledger, restart, and verification contract. It cannot prevent collusion, prove task meaning or approver understanding, attest operator endpoints, prove upstream behavior, or provide exactly-once delivery. | **Implemented as opt-in or signed-policy-required.** Omission stays one-approver compatible; selected tenants can require separation of duties without a hosted workflow or browser signing surface. |
| Exact-effect bundle | A broad session lets a manipulated agent invent request bytes, while repeated single-request approval creates fatigue and encourages careless review. A mixed-scope bundle could also hide a connector outside one signer's authority. | High: one review and signature handoff covers up to eight concrete effects while retaining per-effect replay fences. | High: every signer must cover every connector; every step binds current operation policy and exact bytes; the shortest connector lifetime applies; Gateway validates the full set before accepting one step and spends each task separately. | Medium: the set is deliberately unordered. A compromised agent may execute any subset in any order, so data-dependent sequencing and rollback semantics remain outside the contract. | **Implemented.** Prefer single-request permits when every subset and ordering would not be acceptable; use a separate signed workflow design if ordered state transitions become a requirement. |
| Exact signed-command browser courier | A generic web console becomes a signing or mutation authority; a compromised browser edits a command, retains a key, silently switches tenant or node, or presents a signature as verified. | High: operators can complete the existing offline-signing workflow from the fleet console without reconstructing an API request. | Medium to high: the SPA preserves exact file bytes, shows their SHA-256 digest and signed route, requires tenant projection, typed confirmation, five-minute review freshness, and bearer re-entry, then calls only the existing bounded command endpoint. Private keys and command construction remain outside the browser; Executor still verifies authority. | Medium: a compromised browser can display one digest while submitting another valid signed command it already possesses, or steal the operator bearer. Digest review is not remote attestation or signature verification. | **Implemented as the console's only mutation.** Keep every other controller mutation and all signing outside the browser; use a hardened operator profile. |
| Closed OpenClaw adapter | A health check passes while the agent never loads a skill; the full Gateway quietly exposes channels, browser, plugins, or administration; a mutable upstream tag changes behavior; a valid result leaks prompts, sessions, or filesystem paths; persisted skill bytes drift after restart. | High: OpenClaw becomes useful inside Steward without asking operators to invent and secure their own adapter. | Medium to high: the exact official release index and source revision are pinned; build assembly has no network; OCI manifest, config, and runtime identities are verified separately; the adapter exposes four bounded operations and only `read` plus `exec`; qualification requires a real custom-skill tool call, deterministic result, restart reuse, and fail-closed tamper detection under gVisor. | Medium: Steward trusts the official OCI release instead of reproducing it from source. `exec` remains powerful inside the capsule, and broader OpenClaw features are unavailable until separately qualified. | **Implemented as a narrow adapter.** Reuse upstream agent behavior; keep tenant and capability enforcement outside it and reject the broad Gateway surface. |
| Quota-backed shared persistent state | A workload exhausts bytes or inodes, or a quota disappears after reboot and silently weakens tenant isolation. | High for long-lived shared-host workloads. | Medium: portable reconciliation evidence would be valuable, but the enforcement is substrate-specific. | High: Docker has no portable hard volume quota that satisfies Steward's restart and reconciliation contract. | Defer. Keep shared-host persistent-state admission closed until a qualified backend exists; this does not reduce the authority of an external connector call. |
| MicroVM or Kubernetes backend | A container-runtime escape or host-orchestration failure crosses a tenant boundary. | Medium to high for some sites. | Low: [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/), [OpenSandbox](https://open-sandbox.ai/guides/secure-container), and [Kubernetes Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) already document these substrate choices. | Very high: adds packaging, lifecycle, state, network, and upgrade surfaces while host administration remains trusted. | Defer. Preserve Steward's enforcement contract and consider another backend only when a concrete operator requirement cannot use Docker and gVisor. |
| Generic workflow engine | A manipulated plan gains another in-process execution path, or Steward duplicates agent behavior and expands its trusted core. | Medium: could simplify one product surface. | Low: Hermes, OpenClaw, and other agent frameworks already own planning, skills, and tool behavior. | Very high: broad semantics and integrations are difficult to bound or prove at the node boundary. | Reject from the Steward process. Keep qualifying external agents and enforce their authority outside them. |
| Broad Layer 7 (application-protocol) inspection | An allowed encrypted channel carries a semantically dangerous request or covert exfiltration. | High in selected environments. | Low to medium: OpenShell already documents broader REST, GraphQL, MCP, and JSON-RPC inspection. | Very high: TLS interception, protocol parsers, schemas, and content classification materially expand the trusted core and still cannot prove model intent. | Defer. Prefer exact named connector operations and request-bound permits; keep generic `CONNECT` opaque and credential-free. |

Action permits remained on the Pareto frontier because no deferred candidate provided
greater immediate reduction of external-effect authority at equal or lower
assurance cost. Quota-backed state addresses a different trust failure and remains
plausible later work. Stronger cross-controller transparency and hardware
attestation remain optional future layers around the implemented bounded witness;
substrate breadth, workflow behavior, and general protocol inspection are better
supplied outside Steward's narrow trusted core.

### Existing implementation choices

| Candidate | Adversarial failure considered | Value and assurance evidence | Decision |
| --- | --- | --- | --- |
| Receipt-key enrollment and controller witness | A node substitutes a receipt identity, reuses it across nodes, removes an already witnessed suffix, reports a lower checkpoint, forks at one sequence, or amplifies controller storage with full logs or repeated findings. | Enrollment requires receipt-key proof of possession bound to controller, enrollment, and node. The asynchronous publisher signs the exact polled base, reported head, frame count, and canonical frame digest. The controller verifies bounded deltas, retains one checkpoint and sticky finding, and signs offline exports with a separate stable key. | Build the thin native witness. Keep it off the enforcement availability path and claim detection only relative to the retained controller view, not hostile-host attestation or cross-controller consistency. |
| Tenant-signed service task | A broad host service bearer or manipulated agent submits different task bytes, a concurrent duplicate reaches Hermes twice, or restart hides an ambiguous submission. | Site policy scopes the public key to one tenant and service; Gateway binds one exact request to live admission, records before dispatch, reconstructs spend after restart, and exposes offline correlation. The qualified Hermes workflow separately proves real custom-skill work. | Build the narrow service-operation path in Gateway and an owner-only signing bundle. Claim node-local at-most-once dispatch only; keep run-ID trust and semantic-work limits explicit. |
| Named, credential-brokered operations | The workload steals a standing credential, changes the destination or operation, replays a task after failure, or obtains a second effect after restart. | Enables useful authenticated work while exact origin, method, path, DNS answers, credential digest, per-grant calls, and tenant-scoped task spend remain outside the agent. Signed authorization and terminal records make crash ambiguity explicit. | Build the narrow connector contract in Gateway. This is on the Pareto frontier for immediate utility, security, and differentiation. |
| External secret storage with a compiled Gateway handoff | A custom partial vault loses keys or recovery state; a broad provider token crosses tenants; permissive template defaults create group-readable or backup copies; a rotated value silently diverges from the operator's expected version; or a secret reaches the agent or browser. | OpenBao already owns encrypted storage, ACLs, AppRole, KV versioning, audit, and recovery. Steward compiles exact read-only paths, fail-closed templates, a sandboxed unit, and secret-free expected/observed version readiness while Gateway retains plaintext mediation outside workloads. A digest-pinned live smoke proves TLS AppRole render, SecretID removal, and check-and-set rotation. | Reuse the external open-source service behind Steward's existing owner-only filesystem contract. Do not embed a provider client or build a vault. This integration is not unique secret storage; the differentiating continuity is provider lifecycle to Gateway-only capability delivery without adding secret plaintext to agent, controller, evidence, MCP, or React surfaces. |
| Exact signed-command browser courier | A convenient console accumulates command creation, signing keys, policy edits, and broad mutation authority, or claims that parsing a DSSE envelope verified its signature. | Operators load one local envelope, compare the exact digest and bounded signed metadata, re-enter the current bearer, and submit unchanged bytes. A guarded same-origin client permits only the existing command route; the controller binds transport and route while Executor remains signature authority. | Build the thin React integration from browser-native file, UTF-8, Base64, and digest primitives. Do not add a browser key store, signer, generic mutation client, or approval service. |
| Non-borrowing connector evidence quotas | One noisy tenant fills the shared signed ledger and prevents every other tenant from recording safe terminal outcomes. | Exact per-tenant signed-line accounting reserves worst-case terminal capacity before an effect. An unbudgeted or exhausted tenant fails before upstream work and cannot borrow another tenant's allocation. | Build explicit tenant allocations and restart validation. Keep the shared-disk and shared-`fsync` residual risk visible. |
| Layered egress-denial limiter | A workload turns deny-by-default policy into synchronous audit amplification, resets its identity to escape a local counter, or uses a wall-clock rollback to reopen spent capacity. | Fixed 30/grant, 120/tenant, and 480/host one-minute limits reserve capacity before a denial-audit write. After exhaustion, policy and resource denials return `egress_rate_limited` without another write while allowed traffic continues; inactive and revoked grants retain their specific status, tenant and host windows survive grant churn, and backward clock movement does not reopen capacity. | Build the small limiter at the existing enforcement point. Keep shared host CPU, memory, disk latency, and the global cap visible as residual risks. |
| A real Hermes custom-skill effect | A health check or hard-coded fixture passes even though Hermes never discovers, loads, or follows the skill; a stale result is reused after restart. | Qualification requires Hermes's native system-prompt index, `skill_view` load of the exact signed `SKILL.md`, prescribed terminal call, one authenticated upstream effect, replay and forbidden-operation denial, changed persisted state after restart, secret-absence scans, and offline receipt verification. | Build and package the end-to-end proof. Treat retained evidence as release input, not a marketing assertion. |
| A real OpenClaw custom-skill run | A derived image starts, but upstream OpenClaw never invokes the allowed tool; result normalization accepts an unbound provider or silently exports upstream metadata; restart reuses changed skill bytes. | The exact official release called `exec` once to run the fixed workspace-audit skill under gVisor, returned a deterministic file result, survived restart, and then refused startup after skill tamper. The service returns only bounded payload text and authority metadata. | Reuse the official OCI substrate and build the smallest closed adapter. Keep Gateway, UI, channels, browser, cron, plugins, nodes, discovery, arbitrary skills, and nested sandboxes outside the qualified surface. |
| Key, file, controller, and upgrade ergonomics | A public/private key mismatch, mutable path alias, lost enrollment response, stale delivery, or undeclared durable format turns routine setup or upgrade into an outage or authority change. | CLI key-pair and PKI tooling, identity-locked file reads, one-time idempotent enrollment, exact signed-command retention, fenced delivery, preflight checks, declared format compatibility, and transactional release activation turn common mistakes into explicit states. | Ship a narrow self-hosted controller and packaging while keeping tenant signing, approval, scheduling, and node enforcement in separate boundaries. |
| Shared-host persistent state quotas | An agent exhausts bytes or inodes, or a quota disappears after reboot and silently weakens isolation. | Hard quotas would make long-lived agents safer on shared hosts, but no portable Docker volume mechanism currently satisfies reconciliation and failure tests. | Keep shared-host state admission closed until a qualified backend exists. |
| Generic workflow, browser, or computer-use engine | New in-process execution code expands the trusted core and duplicates the agent framework. | Broad capability is useful, but it scores worse on assurance cost and separation of concerns than qualifying out-of-process agents and skills. | Keep agent behavior out of the Steward process. |
| Automatic ambiguity clearing | Recovery marks an uncertain external effect safe without enough evidence and permits a duplicate. | Automation would reduce operator work, but a false resolution is worse than visible degraded containment. | Preserve the ambiguous state unless observations prove one outcome. |

The selected connector is intentionally narrower than generic egress. A workload
names an operation; the operator maps it to one exact upstream method and path.
Gateway adds an operator-owned credential only after the signed workload grant,
destination, address, concurrency, call, byte, and time checks agree. The workload
is not configured with the upstream origin or credential. Gateway rejects the exact
credential in response headers and the decoded body stream, including across body
chunks. A malicious upstream can still encode or transform that value, disclose the
private origin, or return another application secret, so the operator must choose a
narrow trusted operation. Generic `CONNECT` remains opaque and receives no injected
secret.

## Steward's specific focus

An **authorization-to-enforcement receipt chain** links the signed decision to run
an agent with the controls the node records:

1. a publisher-signed, immutable profile capsule defines the workload's maximum
   capabilities;
2. a site-root-signed policy scopes publishers, tenant authority, profiles,
   repositories or exact image manifests, resource ceilings, inference route
   IDs, service IDs, connector IDs, egress route IDs, and revocation;
3. an authenticated instance intent binds a tenant, node, instance, state lineage,
   and generation;
4. the local executor admits only the intersection, creates the constrained
   gVisor workload, and rejects replay, policy rollback, and observed drift;
5. selected service tasks additionally require a service-scoped off-node tenant key
   to sign exact request bytes, which Gateway records before dispatch;
6. selected connector effects can separately require one or more off-node action
   keys to sign the exact request, which Gateway checks and spends before DNS; and
7. the node emits signed, hash-linked receipts and can publish bounded signed
   deltas to the customer-owned controller independently of command polling; and
8. the controller retains one witnessed checkpoint or sticky divergence finding
   and can sign a portable export with a separate witness key.

Gateway brokers inference, authenticated service ingress, named connector
operations, and HTTP(S) routes without raw network access. Connector credentials
are added at the last hop and are bound by digest to the retained grant. Optional
action permits bind one request and its authority key or canonical signer set to the signed connector
receipt without placing the private signing key or upstream credential in the
workload. Persistent
state is scoped to one tenant and workload history and requires explicit purge, but
its local Docker volume has no enforced byte or inode quota and is limited to the
dedicated-host compatibility mode. Signed receipts record admission and lifecycle
events; network admissions include the effective route-policy digest. Individual
traffic records have the narrower guarantees documented in the capability guide.

The controller witness stores no prompts or full receipt archive. It detects a
lower or conflicting head when the node next reports relative to the exact head it
retained. Evidence publication can stop without stopping local admission or agent
work; the current evidence status does not by itself prove freshness. The witness
does not prove that the node was uncompromised when it signed a record and does not
detect different views presented to independent controllers unless their exports
are compared.

For tenant-signed service tasks, Gateway returns a stored successful run ID on an
exact replay and refuses to redispatch an ambiguous result. The spend is local to
one node, receipt file, and epoch. The service supplies the run ID; neither that ID
nor the receipt proves useful work. The Hermes qualification adds a separate
custom-skill result check so container readiness is not mistaken for functionality.

A receipt records runtime inputs and observed enforcement decisions. It does not
reconstruct prompt meaning, prove agent intent, or certify upstream behavior.

## Standards and research signals

The following current standards and publications focus on identity,
authorization, and separating trusted instructions from untrusted data.

- OpenClaw's official [`2026.7.1` release notes](https://docs.openclaw.ai/releases/2026.7.1)
  describe simultaneous Control UI, onboarding, mobile, model-provider, and coding-
  agent changes. Community conversations include both
  [improved onboarding reports](https://www.reddit.com/r/openclaw/comments/1uu2rt9/this_is_the_month_that_it_all_changes/)
  and [broken-install reports](https://www.reddit.com/r/openclaw/comments/1uwdr2z/in_yet_another_surprise_202671_broke_my_install/).
  Reddit posts are anecdotes, not reliability measurements. Together with the broad
  official change set, they support exact release pins and fresh qualification
  instead of assuming compatibility from a product name or mutable tag.
- Microsoft's May 2026
  [Prompts Become Shells](https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/)
  analysis documents remote-code-execution paths in agent frameworks where
  untrusted input reaches powerful execution features. Its
  [security-and-autonomy planning research](https://www.microsoft.com/en-us/research/publication/optimizing-agent-planning-for-security-and-autonomy/)
  treats security constraints and task utility as a joint planning problem. These
  sources do not evaluate Steward; they reinforce keeping a deterministic outer
  capability boundary even when a framework exposes an `exec` tool.
- A 2026 [calendar-invite attack report](https://labs.zenity.io/p/perplexedbrowser-how-attackers-can-weaponize-comet-to-takeover-your-1password-vault)
  demonstrates stored prompt injection driving an authenticated browser through
  secret access, account mutation, and exfiltration. The corresponding
  [1Password advisory](https://1password.com/blog/security-advisory-for-ai-assisted-browsing-with-the-1password-browser)
  calls this an ecosystem risk and recommends deterministic product boundaries.
- [Google Agent Origin Sets](https://blog.google/security/architecting-security-for-agentic/)
  distinguish read-only and read-write browser origins, reducing unrelated
  cross-origin access for a participating browser. This complements rather than
  replaces exact connector authority on a Steward node.
- [CaMeL](https://arxiv.org/abs/2503.18813) extracts trusted control/data flow and
  applies capabilities at tool calls; [Fides](https://arxiv.org/abs/2505.23643)
  uses deterministic confidentiality and integrity labels in an integrated
  planner. These designs provide stronger semantic flow controls when an agent
  framework adopts them. Steward instead mediates unmodified agent containers.
- The contextual-integrity preprint
  [AI Agents May Always Fall for Prompt Injections](https://arxiv.org/abs/2605.17634)
  describes attacks that make prohibited flows appear legitimate and the utility
  cost of tighter contextual rules. It supports treating model screening as a
  complementary signal, not final action authority.
- [Open Agent Passport](https://arxiv.org/abs/2603.20953) proposes deterministic
  pre-tool policy and signed audit. [NVIDIA OpenShell's policy schema](https://docs.nvidia.com/openshell/reference/policy-schema)
  documents broad sandbox and application-protocol enforcement. Steward's narrower
  moat is signed tenant-key continuity through exact single-request or bounded-set
  authority, durable per-task spend before DNS, credential isolation, and portable offline evidence
  without requiring planner hooks or a hosted service.
- NIST's 2026 [software-agent identity and authorization concept
  paper](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf)
  calls for explicit agent identification and authorization, auditability,
  non-repudiation, and prompt-injection mitigation. Steward's courier keeps the
  browser a transport for already signed authority rather than an identity that
  can mint new command authority.
- The [Model Context Protocol authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  defines transport authorization using OAuth 2.1, while its
  [security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
  cover confused-deputy attacks, token handling, session hijacking, and local
  server compromise. A tool protocol does not replace local workload admission.
- The NSA's May 2026
  [MCP security design guidance](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/nsa-releases-security-design-considerations-for-ai-driven-automation-leveraging/)
  identifies dynamic tool invocation, implicit trust relationships, context sharing,
  serialization, and agent misuse as system-level concerns. Steward therefore keeps
  MCP as a bounded local adapter and makes final workload and task authorization at
  Executor and Gateway, not inside the protocol client.
- The stable [Agent2Agent (A2A) Protocol specification](https://a2a-protocol.org/latest/specification/) is
  an open interoperability protocol for independent agents. It does not decide which
  tenant may run a workload on a host.
- [NIST's large-scale agent red-team report](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition)
  reports that every tested frontier model was hijacked at least once across more
  than 250,000 attempts. The result supports designing for a manipulated agent,
  not claiming that a prompt can eliminate prompt injection. NIST's May 2026
  [analysis of AI-agent security RFI responses](https://www.nist.gov/publications/summary-analysis-responses-request-information-regarding-security-considerations-ai)
  reports broad agreement among commenters that agent security creates novel
  threats and an adoption barrier, that established cybersecurity practices need
  adaptation, and that implementation guidance, information sharing, and standards
  have roles to play. This is a summary of submitted views, not a Steward
  evaluation. NIST's
  [agent identity and authorization concept paper](https://www.nccoe.nist.gov/publications/other/accelerating-adoption-software-and-ai-agent-identity-and-authorization-concept)
  identifies agent identification, authorization, user-to-agent delegation,
  accountability, logging and transparency, and data provenance as areas for
  standards-based work. It is an initial public draft, not a normative standard.
- The [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  includes goal hijack, tool misuse, identity and privilege abuse, supply-chain
  vulnerabilities, unexpected code execution, and memory/context poisoning.
  Steward's narrow grants and artifact/policy binding address only part of that
  risk set; they do not make prompts or agents intrinsically safe.
- The 2026 [Skill-Inject preprint](https://arxiv.org/abs/2602.20156) reports high
  attack success from malicious instructions embedded in agent skill files and
  argues that simple filtering or model scaling is insufficient. The
  [BadSkill preprint](https://arxiv.org/abs/2604.09378) demonstrates a separate
  risk from backdoored model artifacts bundled inside skills. These are recent,
  non-peer-reviewed studies, but they support treating skill instructions, code,
  and embedded artifacts as one untrusted supply-chain unit rather than trusting
  a familiar skill name.
- The 2026 [MalSkillBench preprint](https://arxiv.org/abs/2606.07131) reports that
  code scanners and prompt-injection defenses each miss parts of the combined
  code-and-instruction threat. Steward therefore binds exact skill and
  qualification-evidence digests in a release and catalog, while leaving semantic
  malware detection and behavioral safety claims outside the catalog signature.
  Exact-byte provenance reduces substitution risk; it does not prove that a skill
  is benign.
- A 2026 [sandbox-assurance research framework](https://arxiv.org/abs/2606.18532)
  argues that sandbox assurance depends on controllability, observability,
  containment, reproducibility, and governance artifacts. This research does not
  certify Steward or any other product.
- Current [Docker network governance](https://docs.docker.com/ai/sandboxes/governance/local/)
  routes HTTP(S) through a host proxy, and its release notes explicitly call out
  DNS-policy gating and structured newline-delimited JSON (JSONL) decisions. Current
  [NemoClaw policy guidance](https://docs.nvidia.com/nemoclaw/latest/user-guide/openclaw/network-policy/customize-network-policy)
  adds protocol and path matchers and restricts user-authored IP widening to reduce
  server-side request forgery (SSRF). A hostname allowlist alone is therefore
  insufficient. Steward pins verified DNS answers, requires explicit private
  Classless Inter-Domain Routing (CIDR) ranges, disables agent DNS, bounds streams,
  requires a persisted audit record before allowing a route, and attempts
  best-effort denial and terminal records. It cannot
  inspect paths inside TLS without intercepting TLS, which it does not do.
- The Five Eyes joint
  [secure agent adoption guidance](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services)
  recommends distinct agent identities, runtime authorization for privileged
  requests, integrity-protected tasks, resource limits, and records the agent
  cannot rewrite. Steward's connector design applies those principles at the
  node boundary; the publication does not certify Steward.
- Microsoft's May 2026
  [analysis of privileged tool-enabled agents](https://www.microsoft.com/en-us/research/publication/security-risks-in-tool-enabled-ai-agents-a-systematic-analysis-of-privileged-execution-environments/)
  identifies overprivileged tools, capability-intent mismatches, and ambient
  authority leakage as recurring cloud-agent risks. Steward's service-task path
  narrows one request and keeps the signing key outside the execution environment;
  it does not remove host or model risk.
- Microsoft's 2026 [PAuth preprint](https://www.microsoft.com/en-us/research/publication/pauth-precise-task-scoped-authorization-for-agents/)
  proposes authorization that is both task-scoped and precise at the tool-call
  boundary. It supports Steward's choice to bind one tenant-approved request at the
  enforcement point, but it has not been peer reviewed and does not evaluate
  Steward.
- The 2026 [Open Agent Passport preprint](https://arxiv.org/abs/2603.20953)
  proposes deterministic authorization before a tool call and a signed audit
  record. It is a recent, non-peer-reviewed design signal. Steward's accepted
  permit design remains local because it must bind the existing runtime grant,
  exact connector request, durable offline spend, and terminal receipt without
  adding another enforcement service.
- The 2026 [AIRGuard preprint](https://arxiv.org/abs/2605.28914) evaluates runtime,
  action-time authorization for agent tool use. It is recent, non-peer-reviewed
  research, so Steward treats it as a design signal rather than proof of efficacy.
- An emerging [IETF individual Internet-Draft on authorization evidence chains](https://www.ietf.org/archive/id/draft-schrock-ep-authorization-evidence-chain-00.html)
  discusses carrying verifiable authorization evidence across delegated actions.
  It is not an IETF standard, does not imply endorsement, and is cited only as a
  signal that portable authorization provenance is becoming an active design area.
- The 2026 *Silent Egress* [preprint](https://arxiv.org/abs/2602.22450) reports
  high data-exfiltration success that was usually invisible to output-only checks.
  This is recent, non-peer-reviewed evidence, so the exact rate should not be
  generalized. The architectural implication is stronger: credentials, network
  paths, and transfer budgets must be enforced outside the model.

## Claim limits

- **Not physical isolation.** Docker and gVisor reduce the workload's authority,
  but shared hardware and host root remain trusted.
- **Not a proof against host compromise.** Without hardware-backed keys or an
  attested execution boundary, node receipts and controller checkpoints do not
  prove to an independent party that the host was uncompromised when it signed.
  The controller witness can detect a lower or conflicting head when the node next
  reports relative to what that controller already retained; it cannot validate
  the original event's truth or prove freshness when publication stops.
- **Not universal air-gap certification.** Steward supports disconnected
  installation and operation after the Docker/gVisor host, approved local image,
  signed policy, and keys are prepared. It does not bootstrap a bare operating
  system, operate a model service, or provide formal accreditation.
- **Not semantic observability.** The receipt does not include or validate
  prompts, request bodies, model output, agent explanations, or semantic tool
  actions. An agent-service run ID is untrusted observed output.
- **Not exactly once.** Exact service tasks provide node-local at-most-once
  dispatch only within one retained Gateway ledger epoch. Another node, a replaced
  ledger, or an external service remains a separate replay domain.
- **Not a public access layer.** Steward service ingress is authenticated and
  loopback-only. It does not replace tenant end-user authentication,
  reverse-proxy design, or operator decisions about public exposure.

Operators should be able to identify exactly what Steward enforces, what a receipt
proves, and where they still need additional controls.
