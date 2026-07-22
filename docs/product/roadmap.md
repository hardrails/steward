---
title: Product roadmap
description: Steward's product direction, delivery order, dependency choices, acceptance gates, and deliberate exclusions.
section: Product
---

# Product roadmap

> Research note: Reviewed 2026-07-21 against the linked public primary sources.
> Project capabilities and maturity can change. This roadmap describes direction,
> not a support commitment for unfinished work. See the
> [market analysis]({{ '/product/market-analysis/' | relative_url }}) for the
> current documented-feature comparison.

## Product decision

Steward is being built as the **sovereign authority and operations platform for AI
agents**.

It should let an operator package Hermes, or another future qualified agent, as
one portable application; run it on infrastructure the operator controls; keep
reusable authority outside the agent; continuously reconcile its lifecycle; and
produce enforcement evidence that an auditor can verify without contacting a
vendor.

Steward uses Kubernetes-style desired state, placement, reconciliation, drain, and
rollout concepts where they fit agent workloads. It is not a general replacement
for Kubernetes or Nomad. "Kubernetes for agents" is a useful explanation of the
operating model, not the product's differentiator.

Steward should not compete with agent projects on reasoning, memory, personalities,
or prompt workflows. It should make those projects safe and operable enough to use
for real work.

The durable promise is:

> Even if an agent is manipulated by hostile content, its code, identity, network,
> credentials, state, actions, and evidence remain bounded by controls outside the
> agent process.

This is the differentiator. Docker isolation, network allowlists, dashboards, and
an MCP server are necessary, but they are no longer sufficient by themselves.
The platform must also be straightforward enough that operators do not bypass its
authority boundary to get useful work done.

## Why this direction fits the market

The market is converging on five useful but incomplete product categories:

1. Agent frameworks provide reasoning, tools, skills, and memory, but normally run
   with the authority available to their process.
2. Sandbox platforms isolate code and expose lifecycle APIs, but usually stop at
   process, filesystem, and network policy.
3. Orchestrators place and recover workloads, but do not understand agent intent,
   one-use action authority, or prompt-injection-driven effects.
4. Governance proxies protect credentials or inspect tool calls, but often do not
   own workload generation, state lineage, node enforcement, and offline evidence.
5. Managed agent platforms combine runtime, identity, tools, observability, and
   elastic scale, but place the vendor and its cloud inside the operating trust
   boundary.

Steward should connect those boundaries. Recent work supports that choice:

- [NIST's agent identity concept paper](https://www.nist.gov/news-events/news/2026/02/new-concept-paper-identity-and-authority-software-agents)
  treats identification, authorization, auditing, non-repudiation, delegation,
  and prompt-injection mitigation as connected problems.
- [NIST's large-scale agent red-team analysis](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition)
  identifies hostile external content as an ongoing agent-hijacking risk.
- [Research on overeager coding agents](https://arxiv.org/abs/2605.18583)
  measures harmful scope expansion even on benign tasks, showing that the boundary
  is authorization, not only prompt injection or sandbox escape.
- [Research on agent data injection](https://arxiv.org/abs/2607.05120) reports
  attacks that corrupt security-relevant data and tool context, reinforcing the
  need for deterministic checks outside the model.
- [Kubernetes Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox)
  treats isolated, stateful, singleton workloads, claims, snapshots, and warm pools
  as a distinct infrastructure shape.

The missing record is the connection among one user's intent, one application
digest, one instance generation, one state lineage, one external action, and one
verifiable outcome.

Sandboxing, credential injection, provider routing, snapshots, warm pools,
Kubernetes scheduling, Terraform, MCP, and dashboards are now table stakes. They
must work well, but they are not a moat. Steward's defensible position is the
customer-held authority chain across those capabilities, including when Control,
a node, or an agent is compromised.

## Primary users

- **Platform operators** install sites, enroll nodes, deploy applications, manage
  capacity, recover failures, and perform upgrades.
- **Security operators** define capability policy, bind secret providers, approve
  high-risk effects, revoke authority, and investigate incidents.
- **Agent builders** package a runtime, skills, model route, state contract, health
  contract, and required tools without writing orchestration code.
- **Auditors** verify the artifact, policy, delegation, dispatch, and outcome chain
  on a disconnected workstation.

The initial production customer is an enterprise, government, regulated,
critical-infrastructure, or sovereign operator that requires customer-controlled
Linux and cannot place a hosted service in the trust root.

macOS is a first-class authoring, evaluation, and administration surface. It is not
presented as equivalent to the hardened multi-tenant Linux execution boundary.

## The complete product workflow

Steward is a complete product when a new operator can follow this path without
manually transferring protocol artifacts:

```text
install site
  -> connect a model endpoint and secret provider
  -> enroll one or more nodes
  -> create or import an agent application
  -> preview placement and authority
  -> apply desired state
  -> schedule and start a healthy instance
  -> submit a real task or chat request
  -> receive progress, findings, results, and artifacts
  -> mediate tools, MCP, inference, and external effects
  -> observe, approve, revoke, snapshot, fork, upgrade, or destroy
  -> export and verify evidence offline
```

The normal command surface should be small:

```console
stewardctl agent create analyst -runtime hermes
stewardctl agent apply analyst
stewardctl task run analyst "Review the repository and propose one issue"
```

CUE, OPA, signed envelopes, placement scores, receipt chains, and provider details
remain available through `--explain`, `--output json`, and reference documentation.
They should not be prerequisites for the first useful task.

## What Steward should borrow

| Project | Strong pattern to adopt or reuse | Boundary Steward must preserve |
| --- | --- | --- |
| [NVIDIA NemoClaw](https://github.com/NVIDIA/NemoClaw) and [OpenShell](https://github.com/NVIDIA/OpenShell) | Guided onboarding, runtime profiles, policy explanation, hot network policy, provider abstraction, credential-isolating inference, and Docker, Podman, microVM, and Kubernetes compute drivers | Treat OpenShell as an optional compatibility substrate rather than a second authority plane; preserve disconnected operation, tenant-signed delegation, exact effect authority, and independently verifiable evidence |
| [Agyn](https://github.com/agynio/platform) | Terraform-defined agents, Kubernetes-native scale-to-zero execution, separately isolated MCP tools, zero-trust service access, and per-organization observability | Steward must remain useful without Kubernetes and must prevent Control from inventing authority rather than relying only on central policy and telemetry |
| [OpenClaw Machines](https://github.com/mathaix/OpenClawMachines) | A self-hosted mini-cloud experience: host enrollment, placement, machine lifecycle, backups, separate browser machines, chat, terminal, and workspace MCP integration | No mandatory Cloudflare data plane, no OpenClaw-only contract, no KVM-only installation, and no ambient workspace credential authority |
| [Kubernetes Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox) | `Sandbox`, `Template`, `Claim`, snapshot, stable identity, persistent storage, scheduled shutdown, and warm-pool semantics | Steward remains useful on one ordinary Linux host and carries its authority and evidence contract across the Kubernetes substrate |
| [Sandbox0](https://github.com/sandbox0-ai/sandbox0) and [OpenSandbox](https://github.com/opensandbox-group/OpenSandbox) | Clear backend protocols, SDK and CLI ergonomics, Docker and Kubernetes execution, snapshots, forks, warm pools, credential projection, MCP access, and multiple isolation technologies | Steward is an agent authority product, not a generic remote shell, file API, code interpreter, desktop, or training service |
| [Google AX](https://github.com/google/ax) | Durable event logging, isolated actors, recovery, and resumable distributed agent execution | Steward needs an equally credible task, event, result, and recovery contract while keeping external effects under customer-held authority |
| [WSO2 Agent Manager](https://wso2.github.io/agent-manager/docs/cloud/overview/what-is-amp/) | Enterprise lifecycle, identity, governance, evaluation, and OpenTelemetry observability for internal and external agents | Central governance and telemetry do not replace node-local enforcement, replay protection, or portable signed authorization-to-outcome evidence |
| [AWS AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/what-is-bedrock-agentcore.html) and [Microsoft Foundry](https://azure.microsoft.com/en-us/products/ai-foundry/agent-service/) | Managed scale, identity, private networking, tools, browser and code execution, and broad enterprise integration | No mandatory hosted trust root, regional dependency, cloud identity, or Internet control path |
| Hosted sandbox platforms | Fast create, pause, resume, snapshot, fork, TTL, idle timeout, and developer-friendly task APIs | Customer-owned, air-gapped operation; new authority on every restore or fork; no hosted control-plane dependency |
| WorkFlux | Outcome-first onboarding, explicit action-required states, progressive disclosure, and useful operational metrics | No hosted credential custody, business-agent catalog, or Internet-dependent control path |
| Kubernetes and Nomad | Mature placement concepts, leases, taints, drain, disruption budgets, rollout, and recovery | Do not recreate a general cluster scheduler or require either platform for a secure single-server deployment |

## Product architecture

### Agent Application Contract

One versioned, portable definition should describe:

- immutable runtime image and qualified adapter;
- Hermes, or another future supported engine;
- a logical model route, not a provider credential;
- skills and MCP dependencies pinned by digest;
- CPU, memory, process, storage, and lifetime limits;
- state classes, snapshot policy, and fork eligibility;
- placement and isolation requirements;
- health, readiness, task, chat, log, and result contracts;
- requested capabilities, never raw credentials; and
- expected evidence and retention policy.

CUE is the human-facing authoring and validation surface. Bounded canonical JSON is
the stored and signed form. An application bundle contains no secret, live permit,
runtime identity, or private signing key.

### Desired-state control plane

Steward Control owns bounded desired deployment state, observes nodes and
instances, computes deterministic placement, and drives finite lifecycle
operations. The implemented foundation retains public signed artifacts, performs
resource-aware placement across the exact delegated node set, and reconciles
`admit`, generation-bound `renew`, `start`, `stop`, and `destroy` without storing
tenant private keys. Executor enforces lease expiry locally, and Control can
replace a stateless instance after the conservative expiry and clock-skew window.

Executor now publishes its enforced workload, host, and tenant limits plus
architecture, gVisor isolation, labels, and taints. Control atomically reserves
CPU, memory, process, tenant, and workload-slot capacity with admission and
enforces tenant-signed label and toleration constraints. Controller-owned
cordon and quarantine now provide durable placement and command-delivery gates
without replacing Executor's node-local maintenance fence. Signed soft label
preferences, one-key topology spreading, retained placement explanations, and
restart-safe stateless node drains with maximum-unavailable budgets are also
implemented. Executor also publishes a bounded set of exact local image config
digests. Control uses that observation only as a soft scheduling preference and
retains it in the placement explanation; Executor still inspects the exact signed
image before changing runtime state. Forks remain pinned to the node that owns
their snapshot. The next scheduling layer should add portable state locality,
rollback, quota-capable portable state, and backend conformance. Instance counts,
singleton identity, restart recovery, lease-fenced stateless replacement, bounded
renewal retention, and an explanation for placement and replacement blockers are
already part of the narrow scheduler.

The controller may request authority but may not invent it. Automated operation
uses a tenant-signed, time-bounded delegation that limits application, version,
node set, lifecycle verbs, generations, and expiry. Executor independently verifies
the delegation and the controller-signed command. Tenant root keys can remain
offline or in an external signing system.

Steward must publish two explicit control-compromise profiles:

- **strict sovereign**: Control proposes changes but every mutation requires an
  external tenant signature. Control compromise can deny service or hide recent
  observations, but cannot mint new workload or effect authority; and
- **bounded autonomous**: Control may reconcile within a signed, expiring
  delegation. Compromise can exercise only that delegation's applications, nodes,
  verbs, generations, quotas, and lifetime.

Neither profile can promise availability after Control compromise. Executor must
reject every transition that falls outside the signed desired state and active
delegation.

### Task, event, result, and artifact plane

Agent work must be a durable product primitive rather than a synchronous request
to a container. The common contract should provide:

- asynchronous, idempotent task submission with deadlines, cancellation,
  priorities, bounded retries, and explicit uncertain outcomes;
- instance leases, progress events, findings, terminal results, and
  content-addressed artifacts;
- a durable instance-to-controller outbox with bounded retention, replay, and
  backpressure;
- per-tenant and per-application concurrency, fairness, and result-retention
  limits; and
- retry policy derived from effect safety, never from transport status alone.

The task plane has two authorization tiers. Read-only or otherwise non-consequential
work can run under a signed, bounded capability with destination, data-transfer,
time, concurrency, and call limits. Consequential actions require exact normalized
authority and retain the current spend-before-network and uncertain-outcome rules.
This keeps parallel research practical without weakening write, message, payment,
administrative, or other material effects.

Agents communicate through mediated `AgentService` and `ServiceBinding` resources,
not direct east-west network access. A binding authenticates the caller, tenant,
service, operation, generation, quota, and task/result correlation at Gateway.
Steward should not add a general workflow or directed-acyclic-graph engine.

### Execution backends

Steward should own one small backend contract and a conformance suite:

- Docker plus gVisor remains the default qualified Linux backend.
- A Kubernetes Agent Sandbox adapter should be the preferred cluster backend for
  operators who already run Kubernetes.
- Incus virtual machines should be qualified as the initial candidate for a
  separate-kernel, non-Kubernetes backend because it already owns VM lifecycle,
  storage, networking, snapshots, migration, and a stable API.
- OpenShell should be evaluated as an optional compatibility backend. Its own
  gateway, credential, policy, and inference features must not become a competing
  source of authority or silently weaken Steward enforcement.
- Kata Containers or Firecracker can be added through a backend only when a
  supported deployment needs a separate guest kernel.
- macOS uses a development backend and reports which Linux controls are absent.

Every backend must pass the same lifecycle, identity, capacity, network-closure,
credential-exclusion, crash-recovery, and evidence tests. A backend cannot weaken
Steward's native admission floor or silently downgrade a requested assurance
profile. The public application and evidence contracts must not contain
Docker-specific identifiers.

### Elastic fleet and node trust

`NodePool` should describe an elastic capacity class rather than one cloud
implementation. It includes accepted enrollment identities, required assurance
profile and attestation, architecture, labels, taints, capacity bounds, disruption
policy, image or node-release pin, and provider-neutral scale limits.

Joining a node should require one command, a one-use short-lived claim, an approved
cloud workload identity, or a finite offline enrollment bundle. The node generates
its identity locally and never receives a site root, tenant signing key, reusable
sibling-enrollment credential, or provider-wide credential. A node cannot address
another node directly.

Node reports are authenticated but remain untrusted observations. Root compromise
of one node means every workload on that node might be compromised. Steward's
promise is containment: quarantine, revoke, fence, preserve evidence, and replace
the node without granting a path to other nodes, Control authority, tenant roots,
or reusable provider credentials.

### Capability and secret broker

Gateway should evolve from an egress gateway into a finite capability broker for:

- inference routes;
- approved HTTP and service routes;
- typed connectors;
- agent-facing MCP tools and remote MCP servers; and
- separately isolated browser or computer-use workers.

Each capability has one of four modes:

- `deny`;
- `observe`, which records a shadow decision without granting authority;
- `allow`, under bounded pre-authorized policy; or
- `approve`, which requires one or more signatures over the exact normalized
  action.

OPA may deny or narrow policy. It may not weaken Steward's native safety floor.

Gateway acquires reusable credentials from an external provider and uses them only
at dispatch. A secret binding names a purpose, provider reference, scope, rotation
epoch, and maximum lease lifetime. The agent, console, Control, MCP adapter, and
receipts never receive secret plaintext.

Gateway should run off-node for the strict sovereign profile, with per-tenant trust
domains, short-lived dynamic credentials where supported, and a network boundary
independent of the workload node. A compromised Gateway can still misuse authority
and credentials available to it during their active scope. Short lifetimes,
purpose separation, exact effects, revocation, and external network policy bound
that residual risk; documentation must not claim it is eliminated.

The first supported profiles should be protected file materialization for minimal
offline sites, OpenBao for stored or dynamic secrets, and SPIFFE/SPIRE for
workload identity. Steward should not implement a vault, certificate authority, or
identity provider.

### State, snapshots, and forks

State should be a typed product primitive:

- ephemeral scratch;
- durable agent state;
- immutable input and output artifacts; and
- disposable cache.

A durable backend must enforce tenant ownership, byte and inode quotas, snapshots,
clones, retention, and deletion evidence. The first production backend should use
a quota-capable filesystem such as ZFS; Kubernetes deployments should use CSI
storage. Unquotaed Docker volumes remain dedicated-host only.

Task results and immutable artifacts should use a content-addressed catalog with
tenant-scoped encryption, quotas, retention, and deletion evidence. An
S3-compatible object store should be the production reference while a bounded
local backend preserves single-host and disconnected use. Control stores metadata
and integrity references, not unbounded result bodies.

Initial snapshots should be cold filesystem snapshots. Hot memory cloning is
deferred because it can copy credentials, permits, network sessions, random state,
and compromised in-memory instructions.

A fork must quiesce the adapter, snapshot declared state, record immutable lineage,
start a new instance generation, issue fresh identity and authority, and apply a
TTL, idle policy, or indefinite retention policy. Warm pools contain clean
application bases, not live authorized agents.

### Evidence and operations

Steward should preserve signed enforcement evidence and make it operationally
useful:

- extend the current retained Control incident timeline with verified Executor,
  Gateway, connector, and state evidence;
- offline verification of artifact, policy, delegation, permit, dispatch, and
  outcome linkage;
- external witness checkpoints for rollback or fork detection;
- OpenTelemetry GenAI and MCP export for operational telemetry;
- OCSF-compatible security export;
- content capture off by default, with explicit redaction and retention controls;
- first-class `freeze`, `revoke`, `quarantine`, and `explain` operations; and
- support bundles that exclude secret plaintext.

Telemetry is operational data. Signed receipts are enforcement evidence. The UI
and documentation must not blur them.

Evidence is also subject to the weakest trusted boundary. A valid node signature
does not prove that the node was uncompromised when it signed a record. Every
assurance profile must state the trusted components, enforced controls, freshness,
rollback detection, known bypasses, and residual risks that bound each claim.

## Ownership decisions

| Capability | Decision | Reason |
| --- | --- | --- |
| Application contract and adapter conformance | `in-house` | This portable contract is core differentiation and must remain independently auditable. |
| Policy language | `open-source`: OPA | Policy evaluation is established infrastructure. Native safety floors remain code; OPA may only deny or narrow. |
| Human-facing schema | `open-source`: CUE | CUE provides constraints, defaults, and explanation without becoming the signed runtime format. |
| Default Linux isolation | `native-platform`: Docker, gVisor, Linux, systemd | These primitives meet the ordinary-server profile without introducing another control plane. |
| Stronger or cluster isolation | `open-source`: Kubernetes Agent Sandbox and Incus; optional OpenShell, Kata, or Firecracker backends | Steward should test and adapt mature substrates instead of writing a container runtime or VMM. OpenShell's overlapping authority surfaces require additional scrutiny. |
| Agent-specific reconciliation | `in-house` | Deployment generations, delegation, placement explanation, state lineage, capability binding, and evidence are the product. |
| Durable task, event, result, and service semantics | `in-house` | Effect-aware recovery, instance outbox, mediated agent services, and authority linkage are agent-specific product behavior. |
| General scheduling and consensus | `do-nothing` | Use a narrow single-controller scheduler, Kubernetes, or a future backend. Do not build Raft or a general orchestrator. |
| Secret storage and workload identity | `open-source`: OpenBao and SPIFFE/SPIRE | Mature projects own storage, rotation, leases, attestation, and federation. Steward binds their output to its instance identity. |
| Artifact provenance | `open-source`: Cosign/Sigstore and in-toto/SLSA | Steward should verify and enforce provenance, not issue a new provenance format. |
| Offline update security | `open-source`: TUF-compatible metadata | Threshold and offline signing are established update-security problems. |
| State, artifact bytes, and snapshots | `native-platform` and `open-source`: ZFS, CSI, and S3-compatible storage | Steward owns catalogs, lineage, authority, quotas, and retention semantics; storage systems own bytes, snapshots, clones, and durability. |
| Observability | `open-source`: OpenTelemetry and OCSF-compatible export | Do not build a tracing or security-data ecosystem. Keep signed receipts separate. |
| Capability permits, replay, and evidence | `in-house` | Exact action authority, spend-before-network replay control, generation binding, and offline evidence are core differentiation. |
| Browser and computer use | `open-source`, separate worker | Never embed arbitrary desktop automation or command execution in a Steward authority process. |
| Hardened node appliance | `open-source` immutable Linux base plus Steward packaging | Ship a reproducible, API-managed appliance profile without owning a kernel, general-purpose distribution, or interactive host-management stack. |

Decision: use `in-house` for the application identity, connected authority
semantics, task and effect recovery rules, generation fencing, and narrow
reconciler.
Why: these are the reasons to choose Steward and must remain portable and
independently auditable.
Rejected: another agent control plane because its authority, recovery, and evidence
semantics would become Steward's trust root.
Revisit if: an open standard provides equivalent disconnected, customer-held
authorization and evidence semantics.

Decision: use `open-source` for isolation, policy evaluation, secret storage,
workload identity, persistence, provenance, observability, and update security.
Why: mature projects cover these commodity capabilities with less trusted code and
lower operating ownership.
Rejected: implementing a vault, PKI, VMM, database, policy language, telemetry
stack, or Linux distribution inside Steward.
Revisit if: a supported sovereign profile cannot satisfy one enforcement
requirement through a narrow, replaceable external contract.

Decision: use `do-nothing` for general workflow graphs, model serving, broad
computer-use infrastructure, and a public connector marketplace.
Why: these features do not strengthen the authority boundary and would delay the
complete operator workflow.
Rejected: feature-parity development because established agent frameworks,
sandbox platforms, and managed services already own those categories.
Revisit if: a measured customer workflow cannot be completed through a qualified
external agent, worker, or connector.

## Delivery roadmap

Treat the following sections as outcome horizons, not a promise that every item
lands in one release. Development should use small, reviewable changes, while each
published capability must prove its complete operate, contain, recover, and verify
workflow. A schema, plan command, integration example, or UI page alone does not
complete an outcome; its failure behavior, documentation, upgrade path, and
hostile-path tests must ship with it.

### Implemented foundation

The roadmap starts from working primitives rather than a blank design:

- portable Hermes application bundles with CUE authoring and offline
  OPA policy evidence;
- strict signed capsule admission, default-deny capabilities, Docker and gVisor
  execution, Gateway mediation, task permits, and signed receipts;
- an outbound node uplink and bounded single-writer fleet store;
- Executor-verifiable tenant delegation to a purpose-separated online controller
  key;
- durable deployment generations and optimistic revisions;
- atomic deployment-transition and command enqueue, deterministic command IDs,
  restart-safe progress, and explicit degraded outcomes;
- health-aware placement that rejects stale nodes, durable bounded blocked reasons,
  and deliberate refusal to replace an assigned node without fencing proof;
- public HTTP, client, OpenAPI, and context-aware CLI operations for applying,
  inspecting, listing, waiting for, and removing desired deployments;
- task-ready desired state that retains the exact verified intent and authenticated
  admission projection without retaining private keys;
- a bounded, durable instance-to-controller event outbox with stable sequence,
  replay, backpressure, retention, authenticated uplink, Control API, CLI, MCP,
  and console projections;
- a recovery-safe `task run` workflow that writes signed authority before dispatch,
  joins deployment wait, task issuance, Gateway submission, terminal observation,
  and result storage, and can derive the qualified Hermes request from
  one prompt into a private recoverable run directory;
- concise `agent create` and durable `agent apply NAME` commands that reuse the
  exact application-init and deployment reconciliation implementations;
- an atomic `site init` package that generates the initial signed policy,
  separated authority roles, public node trust, and Control TLS material, plus
  signed inventory verification against an independently pinned site root;
- a thin protected GitHub issue preset over the generic exact-operation connector,
  with bounded calls and no provider SDK or agent-visible upstream credential;
- a finite node enrollment handoff that verifies signed site trust, creates the
  Control tenant, generates the receipt identity on the destination node, and
  safely resumes a lost enrollment response without changing node authority;
- a recoverable site connection that spends the initial administrator authority
  once, retains a tenant-scoped operator in an owner-only file, and selects a
  least-privilege CLI context without storing bearer values in context metadata;
- composed agent publication that inspects the exact OCI archive, fixes the
  qualified Hermes runtime contract, signs it with the site publisher,
  and verifies the result against signed site policy before writing it;
- composed finite deployment authorization that derives the exact admission and
  placement template, binds the eligible node set and five required lifecycle
  operations, signs with the tenant command authority, and verifies the result;
- composed Gateway service activation and task-context connection that install a
  closed service preset, export bounded service trust, validate tenant and task-key
  bindings, and record only credential paths in the operator context;
- authority-preserving in-place rollouts that retain source and target signed
  delegations, spend disruption budget atomically, and switch each instance only
  after a proven destroy;
- durable fleet-wide tenant CPU, memory, process, and workload quotas reserved
  atomically with admission, with CLI, API, attention, and console visibility;
- bounded exact-image locality reporting and deterministic cache-aware placement,
  with the optimization kept separate from signed admission authority;
- opt-in image retrieval from one operator-approved OCI registry, with protected
  registry authentication, exact signed-digest pulls, and mandatory post-pull
  image inspection;
- a strict, owner-only incident support bundle that joins non-secret controller
  inventory and node evidence checkpoints for offline inspection without exporting
  prompts, bodies, command envelopes, credentials, private keys, result text, or
  logs;
- supported private AWS Auto Scaling Group, Google Cloud regional Managed Instance
  Group, and Azure Virtual Machine Scale Set modules that reuse native fleet
  resources, pin non-secret first boot, keep node enrollment out of Terraform
  state, and refuse automatic replacement or scale-in before a Steward drain; and
- explicit `strict-sovereign` and `bounded-autonomous` Control authority modes;
  strict mode refuses accessible controller signing-key files, never starts the
  reconciler, and rejects desired-state mutations, while bounded mode preserves
  tenant-delegated reconciliation.

This foundation is not yet the complete product workflow above. The normal site,
node, publication, finite authorization, service activation, durable apply, and
prompt path now has composed commands. Explicit human or automation steps still
cross the boundaries where a privileged installer runs, an approved registry is
populated or an offline image is imported, Control's public controller key is
authenticated, Gateway is restarted, or non-secret service trust moves between
machines. The controller also
does not yet join continuous health recovery, snapshots, protected-secret
providers, and one offline evidence bundle into one first-time-user operation.

### Remaining product outcomes

The outcomes below extend the working foundation without implying that unshipped
items are present. Work may move between horizons as operator evidence changes.
A capability becomes supported only when its user workflow, failure behavior,
documentation, upgrade path, and evidence are joined.

#### Working runtime foundation

Outcome: `agent deployment apply` converges one application to a healthy agent,
and `task run` performs useful work through the enforced boundary.

- Consolidate common operations behind one `steward` command while retaining
  expert commands and stable JSON output.
- Extend the shipped bounded, read-only task projection into canonical submitted
  task, result, and condition models. The current projection groups retained
  untrusted instance events by workload lineage; it is not yet a dispatcher or
  result authority.
- Make Control-level task submission asynchronous and idempotent, with progress,
  cancellation, deadlines, bounded retention, and content-addressed result
  metadata. Reuse the shipped instance outbox instead of creating another event
  channel.
- Implement a crash-safe, idempotent desired-state loop with generations, bounded
  retry, garbage collection, and explicit degraded states.
- Join bundle build, placement, signed admission, start, health, task, result,
  egress, secrets, and evidence into one operation.
- Join the implemented Executor-verifiable, time-bounded controller delegation to
  task and health recovery without placing tenant root keys in Control.
- Keep one pinned Hermes adapter qualified through the task, health, and result
  contract. Add another runtime only after a concrete user need justifies its
  security and maintenance surface.
- Qualify the shipped protected GitHub issue preset through the release acceptance
  workflow, and add one generic read-only OpenAPI example that uses bounded
  pre-authorized research capability rather than one human signature per read.

Acceptance gates:

- A fresh operator completes a useful task in under 15 minutes with no manual
  protocol artifact transfer.
- Restarting Control, Executor, Gateway, or the host converges without duplicate
  external effects.
- A running instance can publish progress and findings, disconnect, reconnect, and
  resume the controller outbox without losing, duplicating, or reordering a
  terminal result.
- The agent never receives an inference or connector API key.
- DNS, IPv4, IPv6, redirects, proxy headers, rebinding, and alternate routes cannot
  bypass default-deny egress in the supported topology.
- A manipulated agent can request a forbidden action but cannot make Gateway
  dispatch it.
- One offline bundle links application, instance, task, permit, dispatch, and
  outcome.

#### Production platform delivery

Outcome: the same application can run across nodes, recover from failure, create
safe temporary or durable forks, use governed tool ecosystems, and remain
supportable through one coherent operational surface.

- Extend the implemented node leases, resources, reservations, labels, taints and
  tolerations, isolation classes, topology, and image locality with portable state
  locality.
- Add the `NodePool` resource, provider-neutral capacity signals, short-lived
  node-specific enrollment, cloud workload identity, exact-node lifecycle notices,
  and post-drain scale-in approval for elastic fleets.
- Make placement an actual controller decision with stale-plan detection and
  Executor revalidation.
- Extend implemented lease-fenced replacement, rescheduling, topology placement,
  cordon, quarantine, budgeted stateless drain, fleet-wide tenant quotas, and
  durable rollout pause/resume with health-gated canaries and mixed-generation
  rollback.
- Add the storage backend contract and one quota-capable local backend.
- Add quiesce, snapshot, clone, archive, restore, TTL, idle expiry, and garbage
  collection state machines.
- Add `agent fork`, fork-on-task, descendant and retained-byte limits, lineage, and
  clean warm pools.
- Qualify an Incus virtual-machine backend and a Kubernetes Agent Sandbox backend
  after the local backend contract passes conformance; reject silent assurance
  downgrade across all three profiles.
- Add an agent-facing MCP broker distinct from the operator MCP server.
- Pin MCP server identity, tool schema, version, and requested capabilities; run
  untrusted MCP servers as separately admitted workloads.
- Support deny, observe, allow, and approve modes; shadow decisions; exact approval;
  multi-party thresholds; expiry; revocation; and explicit uncertain outcomes.
- Add OpenBao and SPIFFE/SPIRE reference integrations with rotation and freshness
  policy while retaining protected-file materialization.
- Bind SPIFFE/SPIRE-attested cloud instance identity to short-lived, node-specific
  enrollment so elastic pools can add capacity without shared bootstrap tokens.
- Add a connector conformance kit and two or three anchor connectors.
- Add mediated `AgentService` and `ServiceBinding` resources with authenticated
  task/result correlation, quotas, and no direct workload-to-workload network.
- Add an S3-compatible artifact backend plus bounded local storage, tenant
  encryption, quotas, retention, and deletion evidence.
- Complete the strict-sovereign external proposal/signature workflow and prove
  both shipped Control profiles' distinct compromise claims through hostile-path
  tests.
- Extend the implemented site and tenant freeze, node quarantine, snapshot
  quarantine, retained Control incident timeline, and metadata-only support
  bundle with capability revocation and cross-plane verified evidence.
- Finish the React console, concise CLI, autocomplete, SDK/API examples, Terraform
  modules, progressive documentation, packaging, migrations, upgrade tests, and
  release evidence.

Acceptance gates:

- Concurrent reconciliation cannot oversubscribe capacity or double-place an
  instance.
- Concurrent task submission cannot bypass tenant fairness or dispatch one
  idempotency key twice.
- Node loss produces a visible lease expiry and a fenced replacement; late commands
  cannot resurrect the old generation.
- A rollout can be interrupted at every transition and safely resumed or rolled
  back.
- Tenant A cannot observe, address, schedule onto, or consume Tenant B's reserved
  capacity or state.
- A fork contains declared durable state but no credential, task permit, runtime
  reference, evidence key, or live session from its parent.
- TTL cleanup survives restart and never deletes a referenced parent snapshot.
- A seven-day mixed-workload soak and documented chaos suite pass.
- A malicious skill or MCP server cannot choose its upstream origin, receive the
  reusable credential, widen policy, or replay spent authority.
- A compromised Control cannot mint work in strict-sovereign mode and cannot act
  outside or after its signed delegation in bounded-autonomous mode.
- A compromised node cannot enroll another node, reach another workload directly,
  obtain tenant signing material, or use a provider-wide credential.
- Secret rotation takes effect without redeploying the agent; stale epochs fail
  according to policy.
- An uncertain external outcome is never silently retried with new authority.
- Shadow decisions can be compared with enforced decisions before promotion.
- A support bundle contains no prompt, body, credential, or private key by default.

#### Disconnected and stable operations

Outcome: disconnected installation, update, recovery, identity, and compatibility
contracts are reproducible and independently verifiable as one supported system.

- Add a signed offline site repository using TUF-compatible expiration, threshold
  keys, offline roots, mirrors, and removable-media import and export.
- Enforce image signatures, provenance, SBOM intake, revocation, and site approval
  using Cosign/Sigstore and in-toto/SLSA-compatible evidence.
- Add backup, restore, and disaster-recovery drills for Control, identities,
  evidence checkpoints, policy, application bundles, state catalogs, and state.
- Add an optional external PostgreSQL control-store process and leader election for
  sites that require control-plane high availability. Do not implement consensus.
- Add OIDC/SSO and group mapping while preserving local break-glass and fully
  offline identity profiles.
- Add optional TPM, measured-boot, or confidential-computing evidence through
  SPIRE or platform attestors. Report it as evidence, not proof that the host is
  trustworthy.
- Publish a reproducible hardened node appliance on an immutable Linux base with
  no SSH by default, declarative configuration, signed A/B updates, recovery,
  amd64 and arm64 images, cloud and bare-metal formats, and offline installation.
- Freeze the application, backend, capability, storage, receipt, and control
  contracts with a compatibility policy and migration tools.
- Remove the legacy compatibility supervisor and transitional command surfaces.
- Publish runtime, backend, connector, and storage conformance suites and a
  machine-readable support matrix.
- Complete an external security assessment focused on tenant escape, Docker
  authority, egress bypass, secret disclosure, permit replay, controller
  compromise, snapshot authority cloning, and evidence rollback.
- Publish capacity limits, performance envelopes, fault-injection results, recovery
  objectives, supported topologies, and known limitations.
- Maintain one deeply qualified Hermes engine, at least two isolation backends,
  two secret or identity profiles, and one complete disconnected reference
  deployment. Add another agent engine only after a concrete supported use case
  justifies its security, qualification, and maintenance cost.

Acceptance gates:

- A clean site installs and completes the first task with all Internet interfaces
  disconnected.
- Expired, rolled-back, unsigned, revoked, or wrong-site update metadata is
  rejected.
- A full restore meets published recovery targets and preserves replay and
  generation fences.
- The control plane can fail over without two controllers exercising the same
  delegated authority concurrently.
- An independent operator can reproduce the build and verify release, image,
  policy, action, and evidence artifacts from published material.
- Every supported migration is crash-tested from every retained format.
- Every supported profile has explicit security claims, residual risks, capacity
  limits, and conformance evidence.
- A released node image boots, enrolls, upgrades, rolls back, and recovers without
  interactive shell access or an Internet dependency.

## Pareto order

The smallest set of work that changes Steward from strong primitives into a useful
product is:

1. one-command first task;
2. a durable task, event, result, and artifact path;
3. a real desired-state controller joined to execution;
4. Executor-verifiable delegated automation and Control-compromise profiles;
5. tested egress and secret mediation with low-risk and exact-effect tiers;
6. one real read-only workflow and one protected external action;
7. elastic `NodePool` enrollment, reconciliation, drain, and failure recovery;
8. quota-capable state plus an authority-scrubbed cold fork;
9. two backend assurance profiles that pass one conformance suite; and
10. one incident and offline evidence view.

More adapters, schemas, UI pages, policy documents, or signed artifact types do not
compensate for a missing end-to-end path.

## Deliberate exclusions

Defer or reject these until a demonstrated enforcement requirement changes the
decision:

- agent reasoning, planning graphs, memory frameworks, model training, and model
  serving;
- GPU scheduling, inference cost optimization, and a general model gateway;
- a generic workflow builder or catalog of business agents;
- a general remote shell, file, desktop, or code-interpreter API;
- a public skill or connector marketplace before signing and qualification are
  complete;
- an embedded secret vault, PKI, SSO product, wallet, VMM, database, or consensus
  system;
- prompt-injection classification presented as an enforcement boundary;
- arbitrary transparent TCP or UDP proxying around typed capabilities;
- arbitrary host commands, terminal access, or computer use inside Steward's
  authority processes;
- hot process-memory snapshots before an authority-scrubbing design is proven;
- a general replacement for Kubernetes, Nomad, OpenShell, ZFS, or CSI;
- a custom kernel or Linux distribution rather than a packaged immutable node
  appliance;
- a second agent engine without a concrete supported workflow and qualification
  budget;
- multi-site federation, global scheduling, and cross-site authority; and
- hosted-only analytics, assets, or update dependencies.

## Adversarial product questions

### Why not just use OpenShell or NemoClaw?

Use them when their sandbox, policy, provider routing, and onboarding are
sufficient. Steward may support OpenShell through the backend contract, but its
gateway, credentials, policy, and inference controls cannot replace or conflict
with Steward's authority boundary. Steward earns its place only when the operator
also needs runtime-neutral application identity, offline-root delegation, fleet
reconciliation, state lineage, exact one-use action authority, and independent
offline evidence.

### Why not Agyn?

Choose Agyn for a Kubernetes-native internal-agent platform with Terraform,
scale-to-zero invocation, isolated MCP tools, zero-trust service access, chat, and
per-organization observability. Choose Steward when Kubernetes cannot be required,
the site must disconnect fully, tenant roots must remain outside the controller,
node transitions require independently verified delegation, or external effects
need portable signed authorization-to-outcome evidence.

### Why not OpenClaw Machines?

Choose OpenClaw Machines for an OpenClaw-specific mini-cloud with Firecracker,
browser machines, workspace integrations, backups, chat, and terminal access.
Choose Steward when the site uses Hermes, must avoid a mandatory Cloudflare data
plane, run without KVM, remain fully disconnected, or bind every
managed action to customer-held authority and offline evidence.

### Why not Kubernetes Agent Sandbox, Sandbox0, or OpenSandbox?

These are strong execution substrates. Steward should integrate them. None by
itself defines the customer-held application, delegation, exact effect, replay,
state-authority, and offline evidence record Steward owns. If an operator only
needs isolated code execution, they should use those projects directly.

### Why not WSO2 Agent Manager, AWS AgentCore, or Microsoft Foundry?

Choose those platforms for broad enterprise identity, evaluation, observability,
managed scale, and vendor integrations. Choose Steward when the operator must own
the complete trust boundary, retain offline roots, run without a hosted dependency,
or independently verify what authority reached one external outcome. Steward
should reuse their standards and operational patterns rather than imitate their
cloud service catalogs.

### Why not Kubernetes or Nomad directly?

They already solve broad scheduling and workload lifecycle. Steward should not
rebuild those systems. Its small scheduler serves one secure site without another
control plane; existing clusters remain reusable backends. Steward adds the
agent-specific authority and evidence contract above placement.

### Why should Control be trusted at all?

It should not be trusted with tenant roots. In strict-sovereign mode Control can
propose work but cannot authorize it. In bounded-autonomous mode it can act only
inside a signed, expiring delegation that Executor revalidates. Control compromise
can still disrupt availability, hide observations, and exercise valid authority
remaining inside an active delegation; Steward must state that residual risk
plainly.

### Why not a hosted sandbox platform?

Hosted sandboxes generally provide a faster developer experience. Steward is for
customers who require local keys, local infrastructure, air-gap, data residency,
and an independently rebuildable trust boundary. Hosted providers remain useful
for lower-assurance development workloads.

### Why not solve prompt injection directly?

No classifier can make arbitrary external content reliably trustworthy. Screening,
information-flow controls, and safer models are useful defense in depth. Steward's
testable promise is that compromised reasoning still encounters a separate
identity, capability, approval, replay, and evidence boundary.

### Why not make Steward an agent framework?

Agent frameworks will evolve faster than infrastructure. Owning their reasoning
loop would create permanent feature-parity work and destroy runtime neutrality.
Steward should standardize the build, deploy, health, task, result, state, tool,
and evidence boundary while agent projects compete above it.

## Product measures

Usability:

- median install-to-first-useful-task time;
- first-task completion without documentation search;
- commands and manual edits required for default setup;
- time to qualify a new agent-engine release; and
- failures that provide one actionable `explain` result.

Security and correctness:

- egress-bypass, secret-exposure, and cross-tenant corpus pass rates;
- duplicate external effects after fault injection;
- stale-generation and replay rejection rates;
- managed effects with complete authorization-to-outcome evidence; and
- snapshot authority-contamination failures;
- unauthorized mutations possible after simulated Control compromise; and
- cross-node reachability or reusable-credential findings after simulated node
  compromise.

Reliability:

- reconciliation convergence time;
- task queue latency, instance-outbox lag, and terminal-result loss or duplication;
- placement and reservation conflict rate;
- elastic node ready and safe scale-in time;
- node-loss detection and replacement time;
- upgrade and rollback success under injected crashes;
- cold and warm fork readiness latency;
- store and evidence recovery success; and
- tested recovery point and recovery time by deployment profile.

The roadmap should change when evidence changes. Features should advance only when
they improve a complete operator outcome, preserve the authority boundary, and can
be proven through an acceptance or hostile-path test.
