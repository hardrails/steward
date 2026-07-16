---
title: Agent execution market analysis
description: A dated comparison of agent platforms with Steward's local signed admission, exact tenant task dispatch, durable replay control, and offline-verifiable receipts.
section: Product
---

# Agent execution market analysis

> Market snapshot: 2026-07-15. This analysis uses the linked primary sources.
> A vendor's documented feature is not a security certification, and an omitted
> feature is not proof that the vendor can never provide it.

Several products offer hardened containers or microVMs—small virtual machines with
their own kernel—plus egress policy, lifecycle APIs, organization controls,
observability, audit logs, and self-hosted fleet controllers. These controls no
longer distinguish a runtime by themselves.

Steward focuses on a customer-owned controller and nodes. The controller enrolls
nodes and transports already signed commands without holding tenant signing keys.
Nodes verify local authorization, grant only approved state, inference, service,
and network operations, and export receipts for offline verification. For
configured agent-service operations, a tenant-owned key
can sign one exact request while remaining off-node; Gateway records authorization
before dispatch and retains node-local replay state. Its product boundary assumes
the agent can be manipulated; enforcement therefore sits outside the agent process.

Among the products reviewed below, none documents an equivalent combination of
customer-operated air-gapped fleet control and nodes, site-signed artifact and tenant admission,
controller-blind tenant signing keys, fenced exact-command delivery,
service-scoped off-node task keys, exact-request service dispatch, durable node-local
at-most-once replay control, and offline-verifiable authorization-to-outcome
receipts. “Not documented” is not proof that a product lacks an internal or future
capability. This is not a first, only, or certification claim.

Self-hosting is not the differentiator. OpenClaw Machines, OpenSandbox, Kubernetes
Agent Sandbox, and other systems document customer-operated control components.
The comparison below evaluates the narrower authorization, replay, and evidence
boundary instead.

## High-level capability matrix

| System | Customer-operated or disconnected boundary | Fleet coordination boundary | Exact operation policy | Separately signed exact task | Durable dispatch replay state | Offline signed authorization-to-outcome evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Steward | Documented for a self-hosted controller and customer-owned Linux nodes, including air-gapped transfer | Bounded single-writer controller: scoped operators, one-time multi-tenant node enrollment, inventory, and fenced delivery of exact signed commands; tenant signing keys stay outside it | Documented for agent-service POSTs and connector methods/paths | Documented tenant key scoped by signed policy to service IDs; exact request digest and length | Documented controller delivery fencing plus node-local at-most-once task spend within one retained ledger epoch | Documented hash-linked Ed25519 chain with offline task/permit correlation |
| [OpenClaw Machines](https://github.com/mathaix/OpenClawMachines) | Apache-2.0 customer-operated control plane and KVM hosts are documented. Its production-shaped deployment uses Cloudflare DNS, Tunnel, Worker, and KV; local evaluation can omit Cloudflare | Postgres-backed accounts and teams, host enrollment, placement, machine lifecycle, durable workflows, backups, and Firecracker workers are documented | Native MCP and workspace integrations are documented; an equivalent site-signed exact-operation fence was not found in the reviewed sources | Not found in the reviewed sources | Durable workflows are documented; an equivalent tenant-signed exact-task spend ledger was not found | Backups and OpenTelemetry/Opik observability are documented; the reviewed sources did not document an offline signed authorization-to-terminal chain |
| [NVIDIA NemoClaw / OpenShell](https://github.com/NVIDIA/NemoClaw) | OpenShell documents local and cluster drivers; deployment scope varies by driver | Local and cluster sandbox providers are documented; the reviewed sources did not document Steward's separate tenant-signed command queue and node verification boundary | Documented REST, GraphQL, MCP, JSON-RPC, and WebSocket policy | Endpoint-scoped identity tokens are documented; an off-node signature over one exact task request was not found in the reviewed sources | An equivalent exact-task spend ledger was not found in the reviewed sources | Logs and OCSF JSON export are documented; the reviewed sources did not document Steward's offline signed permit-to-terminal chain |
| [Docker Sandboxes / Governance](https://docs.docker.com/ai/sandboxes/governance/) | Local microVM sandboxes are documented; organization governance depends on Docker sign-in | Organization governance is documented through Docker's service rather than a fully disconnected bundled controller | Network, filesystem, credential, and decision policy are documented | Not found in the reviewed sources | Not found in the reviewed sources | Decision logs are documented; the reviewed sources did not document offline permit-to-terminal signature verification |
| [OpenSandbox](https://github.com/alibaba/OpenSandbox) | Self-hosted Docker and Kubernetes backends are documented | A distributed sandbox API and runtime lifecycle are documented | Sandbox lifecycle and runtime isolation are documented | Not found in the reviewed sources | Not found in the reviewed sources | Not found in the reviewed sources |
| [Kubernetes Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) | Customer-operated Kubernetes is supported | Kubernetes supplies the cluster control plane; Sandbox claims and pools coordinate runtime capacity | Templates, claims, lifecycle, and isolation are documented | Not found in the reviewed sources | Not found in the reviewed sources | Not found in the reviewed sources |
| [Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/what-is-bedrock-agentcore.html) | AWS-managed service with VPC integration | AWS-managed runtime and identity control | Managed identity, gateway, tools, and observability are documented | Not found in the reviewed sources | Managed runtime semantics differ; an equivalent customer-held exact-task spend ledger was not found | OpenTelemetry observability is documented; the reviewed sources did not document a customer-verifiable offline signed chain |

## Comparison

| System | Documented focus as of the snapshot | Where Steward's focus differs |
| --- | --- | --- |
| [OpenClaw Machines](https://github.com/mathaix/OpenClawMachines) | Its Apache-2.0 public core documents a Go and Postgres control plane with accounts, teams, placement, durable workflows, host enrollment, lifecycle, and backups; one Firecracker microVM per OpenClaw agent; per-host LiteLLM; browser VMs; native MCP integrations; and a Cloudflare data plane. The production-shaped self-hosting guide requires Cloudflare DNS, Tunnel, Worker, and KV, while local evaluation does not. The controller still needs private or firewall-restricted access to each host agent's authenticated API on port `9090`. The [release page](https://github.com/mathaix/OpenClawMachines/releases) contained no published release at the snapshot date. | Steward does not match its accounts, placement, browser, Firecracker, or integration breadth. Steward's narrower boundary is portable Docker and gVisor nodes plus an optional controller that needs no Postgres or Cloudflare: tenant keys remain outside the controller, nodes verify site-signed artifact and tenant policy, delivery and local task replay are durable, and signed authorization-to-outcome evidence can be checked offline. |
| [NVIDIA NemoClaw](https://github.com/NVIDIA/NemoClaw) / [OpenShell](https://github.com/NVIDIA/OpenShell) | NemoClaw packages Hermes, OpenClaw, and LangChain Deep Agents around OpenShell. OpenShell documents Docker, rootless Podman, microVM, and Kubernetes drivers; exact REST method, path, and query rules; provider-owned network layers; credential placeholders and rewrites; endpoint-scoped token grants using SPIFFE JWT-SVID; and inspection for REST, GraphQL, MCP, and JSON-RPC. Both current READMEs label the projects alpha; OpenShell describes its current mode as one developer, one environment, and one gateway, and marks Kubernetes deployment experimental. See the current [policy schema](https://docs.nvidia.com/openshell/reference/policy-schema) and [provider architecture](https://docs.nvidia.com/openshell/sandboxes/providers-v2). | Steward does not claim method/path policy, credential injection, or Hermes packaging as unique, and OpenShell documents broader application-protocol inspection. Steward's narrower difference is a disconnected, vendor-independent node that binds site-signed tenant, instance, and artifact admission to a service-scoped tenant signature over one exact request, durable node-local task spend, non-borrowing tenant evidence quotas, and Gateway-signed terminal receipts that can be correlated offline. Maturity labels are dated observations, not permanent comparisons. |
| [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) / [AI Governance](https://docs.docker.com/ai/sandboxes/governance/) | Docker documents microVMs, filesystem and network policy, organization sign-in, decision logs, credential injection, DNS policy, and workspace sharing. Linux installation requires Kernel-based Virtual Machine (KVM) support and Docker sign-in; organization governance is a paid capability. | Steward uses Docker and gVisor on an operator-owned node without requiring a vendor login or hosted policy service. It does not claim isolation, egress policy, DNS gating, credential injection, or JSON audit as unique. |
| [OpenSandbox](https://github.com/alibaba/OpenSandbox) | OpenSandbox documents a sandbox API, Docker and Kubernetes backends, lifecycle control, and [gVisor, Kata, and Firecracker runtimes](https://open-sandbox.ai/guides/secure-container). | Steward adds site-owned admission, tenant/instance replay protection, and operator-verifiable receipts. The projects could complement each other; Steward does not depend on OpenSandbox. |
| [Kubernetes Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) | The Kubernetes SIG project documents `Sandbox` Custom Resource Definitions (CRDs), templates, claims, warm pools, state, and optional gVisor or Kata isolation. Kubernetes itself [does not define a first-class tenant object](https://kubernetes.io/docs/concepts/security/multi-tenancy/); operators must assemble the isolation policy. | Steward provides one opinionated tenant and evidence contract on a Linux node without making Kubernetes a prerequisite. A future backend could preserve that contract on Kubernetes. |
| [E2B](https://github.com/e2b-dev/infra) | E2B provides a Firecracker sandbox platform. Its [self-host guide](https://github.com/e2b-dev/infra/blob/main/self-host.md) combines Terraform, Packer, PostgreSQL, DNS, and cloud-specific infrastructure; that is a capable platform, not a one-node offline package. | Steward does not recreate a microVM platform. It provides an offline, site-policy-controlled deployment and evidence boundary for long-lived agents on Docker/gVisor. |
| [Daytona](https://github.com/daytonaio/daytona) | The public repository contains a broad sandbox API, but its README says public core development stopped after June 2026 and moved to a private codebase. The frozen public source remains under the [GNU Affero General Public License](https://github.com/daytonaio/daytona/blob/main/LICENSE). | Steward's open repository remains the complete node enforcement product. Independent rebuildability and offline maintainability are part of the boundary, not an installation option around a private core. |
| [OpenClaw](https://github.com/openclaw/openclaw/security) | OpenClaw provides agents, tools, skills, memory, and optional Docker sandboxing. Its security documentation says one gateway is not an adversarial multi-tenant boundary and that session or memory scoping does not create per-user authorization. | Steward treats the OpenClaw image, tools, memory, and configuration as untrusted workload content. OpenClaw can supply agent behavior; Steward supplies the external tenant boundary. |
| [Hermes Agent](https://github.com/NousResearch/hermes-agent/security) | Hermes provides skills, plugins, subagents, scheduled work, and several execution backends. Its security documentation describes a single-user personal-agent model and warns that skills and plugins run with the agent's authority. | Steward qualifies one exact Hermes build and places policy, credentials, resource controls, and evidence outside Hermes. It does not rely on the agent's own permission model for tenant isolation. |
| [Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/what-is-bedrock-agentcore.html) | AgentCore documents managed runtime, identity, memory, MCP gateway, code interpreter, browser, and OpenTelemetry observability. Its [Virtual Private Cloud (VPC) guide](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html) describes AWS-managed network interfaces and Identity and Access Management (IAM) service roles. | Steward serves operators who require local keys, artifacts, infrastructure, and operation without a vendor control plane or public Internet. It does not claim an equivalent managed-service portfolio. |

## Adjacent operator-experience signal: WorkFlux

[WorkFlux](https://www.workflux.ai/docs) is a hosted vertical-automation product,
not a hardened agent runtime or disconnected fleet controller. Its documentation
assumes a vendor dashboard, public API, and Internet connectivity. It is therefore
not included in the security capability matrix above. Its onboarding model still
provides useful product lessons:

- its [agent catalog](https://www.workflux.ai/docs/agents-overview) describes
  concrete use cases, integrations, and expected outcomes instead of asking a new
  operator to assemble an abstract platform;
- its [quick start](https://www.workflux.ai/docs/quick-start) presents a coherent
  choose, configure, test, activate, and monitor path;
- its API documentation exposes [scoped credentials](https://www.workflux.ai/docs/api-authentication),
  [event notifications](https://www.workflux.ai/docs/webhooks), and
  [operational metrics](https://www.workflux.ai/docs/key-metrics).

Steward should translate those patterns without copying the hosted trust model.
Qualified Hermes and OpenClaw packages should read like an offline catalog entry:
exact source revision, required capabilities, integration contract, acceptance
evidence, and a useful-work example. Activation should join the existing preflight,
signed canary, transactional installation, doctor, and rollback controls into one
obvious operator journey. Future controller events should use a bounded durable
local outbox that can be polled or exported; outbound webhook delivery must not
become an availability or Internet dependency. Fleet metrics should describe
controller and node health, queue state, delivery latency, failures, ambiguity, and
capacity without collecting prompts or claiming business outcomes.

Steward should not absorb vertical conversation behavior, customer records,
business return-on-investment calculations, or human-escalation workflows. Those
belong in independently qualified agents, skills, and customer systems. WorkFlux's
marketing, compliance, uptime, and outcome claims were not independently verified
for this analysis.

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
hardware-backed signing, and external evidence anchoring solve different threats and
remain separate potential layers.

### Exact-effect authorization increment

The selected design is now an opt-in signed action permit: a tenant-scoped action
authority authorizes one exact connector request, Gateway durably spends that
authorization before attempting the request, and subsequent evidence carries the
same authority key, permit, request, and task-call linkage. “Exact” describes the
authorized request bytes and metadata, not exactly-once delivery by the upstream
service. Existing connectors retain their broader grant-and-task behavior until an
operator configures action authority for them.

The selection assumes that an agent may be manipulated. That assumption is
supported by [NIST's large-scale agent red-team](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition),
which found at least one successful hijacking attack against every tested frontier
model, and by the [OWASP agentic-application risk list](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/),
which includes goal hijack, tool misuse, and identity or privilege abuse. The
[PAuth preprint](https://www.microsoft.com/en-us/research/publication/pauth-precise-task-scoped-authorization-for-agents/)
and [Five Eyes adoption guidance](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services)
are design signals for precise, runtime authorization and integrity-protected
tasks; neither evaluates or certifies Steward.

| Candidate | Adversarial failure considered | Operator value | Differentiating assurance | Delivery and residual risk | Pareto decision |
| --- | --- | --- | --- | --- | --- |
| Signed exact-effect action permits | A manipulated workload uses a valid broad grant for different request content, races the same authority, or retries after an ambiguous result. | High: authorizes useful external work without giving the workload reusable signing or credential authority. | High: binds node, tenant, instance generation, admitted artifact and policies, exact origin, method, path, credential injection mode and epoch, task, request digest and length, method-derived content type, and validity window to durable spend and later evidence. | Medium: requires one coherent statement, signing, Gateway, ledger, restart, and verification contract. It cannot prove task meaning, upstream behavior, or exactly-once delivery. | **Implemented as opt-in.** It directly narrows an admitted agent from a bounded operation to one authority-signed request while extending the existing offline grant-and-receipt chain. |
| Quota-backed shared persistent state | A workload exhausts bytes or inodes, or a quota disappears after reboot and silently weakens tenant isolation. | High for long-lived shared-host workloads. | Medium: portable reconciliation evidence would be valuable, but the enforcement is substrate-specific. | High: Docker has no portable hard volume quota that satisfies Steward's restart and reconciliation contract. | Defer. Keep shared-host persistent-state admission closed until a qualified backend exists; this does not reduce the authority of an external connector call. |
| MicroVM or Kubernetes backend | A container-runtime escape or host-orchestration failure crosses a tenant boundary. | Medium to high for some sites. | Low: [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/), [OpenSandbox](https://open-sandbox.ai/guides/secure-container), and [Kubernetes Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) already document these substrate choices. | Very high: adds packaging, lifecycle, state, network, and upgrade surfaces while host administration remains trusted. | Defer. Preserve Steward's enforcement contract and consider another backend only when a concrete operator requirement cannot use Docker and gVisor. |
| Generic workflow engine | A manipulated plan gains another in-process execution path, or Steward duplicates agent behavior and expands its trusted core. | Medium: could simplify one product surface. | Low: Hermes, OpenClaw, and other agent frameworks already own planning, skills, and tool behavior. | Very high: broad semantics and integrations are difficult to bound or prove at the node boundary. | Reject from the Steward process. Keep qualifying external agents and enforce their authority outside them. |
| External evidence witness | A compromised host key holder rewrites or withholds a purely node-local evidence history. | Medium: improves independent proof for connected deployments. | Medium to high, but it changes the trust model rather than preventing the manipulated agent's exact unauthorized request. | High for disconnected sites: introduces another key, service, availability dependency, synchronization protocol, and recovery path. | Defer. Keep the current host-compromise limitation explicit and revisit a witness as an optional complement, not a prerequisite for local enforcement. |
| Broad Layer 7 (application-protocol) inspection | An allowed encrypted channel carries a semantically dangerous request or covert exfiltration. | High in selected environments. | Low to medium: OpenShell already documents broader REST, GraphQL, MCP, and JSON-RPC inspection. | Very high: TLS interception, protocol parsers, schemas, and content classification materially expand the trusted core and still cannot prove model intent. | Defer. Prefer exact named connector operations and request-bound permits; keep generic `CONNECT` opaque and credential-free. |

Action permits remained on the Pareto frontier because no deferred candidate provided
greater immediate reduction of external-effect authority at equal or lower
assurance cost. Quota-backed state and an optional witness address different trust
failures and remain plausible later work; substrate breadth, workflow behavior, and
general protocol inspection are better supplied outside Steward's narrow trusted
core.

### Existing implementation choices

| Candidate | Adversarial failure considered | Value and assurance evidence | Decision |
| --- | --- | --- | --- |
| Tenant-signed service task | A broad host service bearer or manipulated agent submits different task bytes, a concurrent duplicate reaches Hermes twice, or restart hides an ambiguous submission. | Site policy scopes the public key to one tenant and service; Gateway binds one exact request to live admission, records before dispatch, reconstructs spend after restart, and exposes offline correlation. The qualified Hermes workflow separately proves real custom-skill work. | Build the narrow service-operation path in Gateway and an owner-only signing bundle. Claim node-local at-most-once dispatch only; keep run-ID trust and semantic-work limits explicit. |
| Named, credential-brokered operations | The workload steals a standing credential, changes the destination or operation, replays a task after failure, or obtains a second effect after restart. | Enables useful authenticated work while exact origin, method, path, DNS answers, credential digest, per-grant calls, and tenant-scoped task spend remain outside the agent. Signed authorization and terminal records make crash ambiguity explicit. | Build the narrow connector contract in Gateway. This is on the Pareto frontier for immediate utility, security, and differentiation. |
| Non-borrowing connector evidence quotas | One noisy tenant fills the shared signed ledger and prevents every other tenant from recording safe terminal outcomes. | Exact per-tenant signed-line accounting reserves worst-case terminal capacity before an effect. An unbudgeted or exhausted tenant fails before upstream work and cannot borrow another tenant's allocation. | Build explicit tenant allocations and restart validation. Keep the shared-disk and shared-`fsync` residual risk visible. |
| Layered egress-denial limiter | A workload turns deny-by-default policy into synchronous audit amplification, resets its identity to escape a local counter, or uses a wall-clock rollback to reopen spent capacity. | Fixed 30/grant, 120/tenant, and 480/host one-minute limits reserve capacity before a denial-audit write. After exhaustion, policy and resource denials return `egress_rate_limited` without another write while allowed traffic continues; inactive and revoked grants retain their specific status, tenant and host windows survive grant churn, and backward clock movement does not reopen capacity. | Build the small limiter at the existing enforcement point. Keep shared host CPU, memory, disk latency, and the global cap visible as residual risks. |
| A real Hermes custom-skill effect | A health check or hard-coded fixture passes even though Hermes never discovers, loads, or follows the skill; a stale result is reused after restart. | Qualification requires Hermes's native system-prompt index, `skill_view` load of the exact signed `SKILL.md`, prescribed terminal call, one authenticated upstream effect, replay and forbidden-operation denial, changed persisted state after restart, secret-absence scans, and offline receipt verification. | Build and package the end-to-end proof. Treat retained evidence as release input, not a marketing assertion. |
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
6. selected connector effects can separately require an off-node action key to sign
   the exact request, which Gateway checks and spends before DNS; and
7. the node emits signed, hash-linked receipts that an operator can verify
   offline.

Gateway brokers inference, authenticated service ingress, named connector
operations, and HTTP(S) routes without raw network access. Connector credentials
are added at the last hop and are bound by digest to the retained grant. Optional
action permits bind one request and its authority key to the signed connector
receipt without placing the private signing key or upstream credential in the
workload. Persistent
state is scoped to one tenant and workload history and requires explicit purge, but
its local Docker volume has no enforced byte or inode quota and is limited to the
dedicated-host compatibility mode. Signed receipts record admission and lifecycle
events; network admissions include the effective route-policy digest. Individual
traffic records have the narrower guarantees documented in the capability guide.

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
  external evidence anchor, node-local receipts are tamper-evident within the
  stated trust boundary. They do not prove to an independent party that the host
  was uncompromised.
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
