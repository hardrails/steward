---
title: Product roadmap
description: Steward's product direction, delivery order, dependency choices, acceptance gates, and deliberate exclusions.
section: Product
---

# Product roadmap

> Research note: Reviewed 2026-07-19 against the linked public primary sources.
> Project capabilities and maturity can change. This roadmap describes direction,
> not a support commitment for unfinished work. See the
> [market analysis]({{ '/product/market-analysis/' | relative_url }}) for the
> current documented-feature comparison.

## Product decision

Steward is being built as the **customer-owned runtime and authority plane for AI
agents**.

It should let an operator package Hermes, OpenClaw, or another qualified agent as
one portable application; run it on infrastructure the operator controls; keep
reusable authority outside the agent; continuously reconcile its lifecycle; and
produce enforcement evidence that an auditor can verify without contacting a
vendor.

Steward should not compete with agent projects on reasoning, memory, personalities,
or prompt workflows. It should make those projects safe and operable enough to use
for real work.

The durable promise is:

> Even if an agent is manipulated by hostile content, its code, identity, network,
> credentials, state, actions, and evidence remain bounded by controls outside the
> agent process.

This is the differentiator. Docker isolation, network allowlists, dashboards, and
an MCP server are necessary, but they are no longer sufficient by themselves.

## Why this direction fits the market

The market is converging on four useful but incomplete product categories:

1. Agent frameworks provide reasoning, tools, skills, and memory, but normally run
   with the authority available to their process.
2. Sandbox platforms isolate code and expose lifecycle APIs, but usually stop at
   process, filesystem, and network policy.
3. Orchestrators place and recover workloads, but do not understand agent intent,
   one-use action authority, or prompt-injection-driven effects.
4. Governance proxies protect credentials or inspect tool calls, but often do not
   own workload generation, state lineage, node enforcement, and offline evidence.

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
| [NVIDIA NemoClaw](https://github.com/NVIDIA/NemoClaw) and [OpenShell](https://github.com/NVIDIA/OpenShell) | Guided onboarding, runtime profiles, policy explanation, hot network policy, provider abstraction, and Docker, Podman, microVM, and Kubernetes compute drivers | Runtime neutrality, disconnected operation, tenant-signed delegated automation, exact effect authority, and independently verifiable evidence |
| [OpenClaw Machines](https://github.com/mathaix/OpenClawMachines) | A self-hosted mini-cloud experience: host enrollment, placement, machine lifecycle, backups, separate browser machines, chat, terminal, and workspace MCP integration | No mandatory Cloudflare data plane, no OpenClaw-only contract, no KVM-only installation, and no ambient workspace credential authority |
| [Kubernetes Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox) | `Sandbox`, `Template`, `Claim`, snapshot, stable identity, persistent storage, scheduled shutdown, and warm-pool semantics | Steward remains useful on one ordinary Linux host and carries its authority and evidence contract across the Kubernetes substrate |
| [OpenSandbox](https://github.com/opensandbox-group/OpenSandbox) | A clear backend protocol, SDK and CLI ergonomics, Docker and Kubernetes execution, multiple isolation technologies, MCP access, and sandbox pools | Steward is an agent authority product, not a generic remote shell, file API, code interpreter, desktop, or training service |
| Hosted sandbox platforms | Fast create, pause, resume, snapshot, fork, TTL, idle timeout, and developer-friendly task APIs | Customer-owned, air-gapped operation; new authority on every restore or fork; no hosted control-plane dependency |
| WorkFlux | Outcome-first onboarding, explicit action-required states, progressive disclosure, and useful operational metrics | No hosted credential custody, business-agent catalog, or Internet-dependent control path |
| Kubernetes and Nomad | Mature placement concepts, leases, taints, drain, disruption budgets, rollout, and recovery | Do not recreate a general cluster scheduler or require either platform for a secure single-server deployment |

## Product architecture

### Agent Application Contract

One versioned, portable definition should describe:

- immutable runtime image and qualified adapter;
- Hermes, OpenClaw, or another supported engine;
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
implemented. The next scheduling layer should add image and state locality,
rollback, quota-capable portable state, and backend conformance. Instance counts, singleton identity, restart
recovery, lease-fenced stateless replacement, bounded renewal retention, and an
explanation for placement and replacement blockers are already part of the
narrow scheduler.

The controller may request authority but may not invent it. Automated operation
uses a tenant-signed, time-bounded delegation that limits application, version,
node set, lifecycle verbs, generations, and expiry. Executor independently verifies
the delegation and the controller-signed command. Tenant root keys can remain
offline or in an external signing system.

### Execution backends

Steward should own one small backend contract and a conformance suite:

- Docker plus gVisor remains the default qualified Linux backend.
- OpenShell should be evaluated as the first optional reusable backend for
  microVM, Podman, and Kubernetes breadth.
- A Kubernetes Agent Sandbox adapter should serve operators who already run
  Kubernetes.
- Kata Containers or Firecracker can be added through a backend only when a
  supported deployment needs a separate guest kernel.
- macOS uses a development backend and reports which Linux controls are absent.

Every backend must pass the same lifecycle, identity, capacity, network-closure,
credential-exclusion, crash-recovery, and evidence tests. A backend cannot weaken
Steward's native admission floor.

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

- one incident timeline across Control, Executor, Gateway, connectors, and state;
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

## Ownership decisions

| Capability | Decision | Reason |
| --- | --- | --- |
| Application contract and adapter conformance | `in-house` | This portable contract is core differentiation and must remain independently auditable. |
| Policy language | `open-source`: OPA | Policy evaluation is established infrastructure. Native safety floors remain code; OPA may only deny or narrow. |
| Human-facing schema | `open-source`: CUE | CUE provides constraints, defaults, and explanation without becoming the signed runtime format. |
| Default Linux isolation | `native-platform`: Docker, gVisor, Linux, systemd | These primitives meet the ordinary-server profile without introducing another control plane. |
| Stronger or cluster isolation | `open-source`: OpenShell, Kubernetes Agent Sandbox, Kata, or Firecracker | Steward should test and adapt mature substrates instead of writing a container runtime or VMM. |
| Agent-specific reconciliation | `in-house` | Deployment generations, delegation, placement explanation, state lineage, capability binding, and evidence are the product. |
| General scheduling and consensus | `do-nothing` | Use a narrow single-controller scheduler, Kubernetes, or a future backend. Do not build Raft or a general orchestrator. |
| Secret storage and workload identity | `open-source`: OpenBao and SPIFFE/SPIRE | Mature projects own storage, rotation, leases, attestation, and federation. Steward binds their output to its instance identity. |
| Artifact provenance | `open-source`: Cosign/Sigstore and in-toto/SLSA | Steward should verify and enforce provenance, not issue a new provenance format. |
| Offline update security | `open-source`: TUF-compatible metadata | Threshold and offline signing are established update-security problems. |
| State bytes and snapshots | `native-platform` and `open-source`: ZFS or CSI | Steward owns lineage and authority semantics; storage systems own quotas, snapshots, and clones. |
| Observability | `open-source`: OpenTelemetry and OCSF-compatible export | Do not build a tracing or security-data ecosystem. Keep signed receipts separate. |
| Capability permits, replay, and evidence | `in-house` | Exact action authority, spend-before-network replay control, generation binding, and offline evidence are core differentiation. |
| Browser and computer use | `open-source`, separate worker | Never embed arbitrary desktop automation or command execution in a Steward authority process. |

Decision: use `in-house` for the connected authority semantics and the narrow
controller that depends on them. Tradeoff: these are the reasons to choose Steward
and must stay portable and auditable. Rejected: a general in-house orchestrator,
vault, PKI, VMM, policy language, and observability stack because mature reusable
systems satisfy those context requirements with less trusted code and lower
operational ownership. Revisit only when a supported sovereign profile cannot meet
an enforcement requirement through a narrow external contract.

## Delivery roadmap

Complete the remaining roadmap as one integrated product release. Development may
use small, reviewable commits, but the public pull request and release must prove
the complete operate, contain, recover, and verify workflow together. This avoids
publishing another sequence of individually impressive primitives that still leave
the operator to assemble the system. A release is not complete because a schema,
plan command, integration example, or UI page exists; the stated outcome must pass
end-to-end acceptance and hostile-path tests.

### Implemented foundation

The roadmap starts from working primitives rather than a blank design:

- portable Hermes and OpenClaw application bundles with CUE authoring and offline
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
  and deliberate refusal to replace an assigned node without fencing proof; and
- public HTTP, client, OpenAPI, and context-aware CLI operations for applying,
  inspecting, listing, waiting for, and removing desired deployments;
- task-ready desired state that retains the exact verified intent and authenticated
  admission projection without retaining private keys; and
- a recovery-safe `task run` workflow that writes signed authority before dispatch,
  joins deployment wait, task issuance, Gateway submission, terminal observation,
  and result storage, and can derive the qualified Hermes or OpenClaw request from
  one prompt into a private recoverable run directory;
- concise `agent create` and durable `agent apply NAME` commands that reuse the
  exact application-init and deployment reconciliation implementations.
- authority-preserving in-place rollouts that retain source and target signed
  delegations, spend disruption budget atomically, and switch each instance only
  after a proven destroy; and
- durable fleet-wide tenant CPU, memory, process, and workload quotas reserved
  atomically with admission, with CLI, API, attention, and console visibility.
- a strict, owner-only incident support bundle that joins non-secret controller
  inventory and node evidence checkpoints for offline inspection without exporting
  prompts, bodies, command envelopes, credentials, private keys, result text, or
  logs.

This foundation is not yet the complete product workflow above. The normal
create, apply, and prompt path is joined, but a fresh site still needs explicit policy,
delegation, Gateway, and service-trust setup. The controller also does not yet join
continuous health recovery, snapshots, protected-secret
providers, and one offline evidence bundle into one first-time-user operation.

### Consolidated production release

This release makes Steward a complete product on one host, extends the same
contract across a small fleet, and makes disconnected operation repeatable. The
work is organized below as implementation lanes, not separate pull requests or
release trains. A capability crosses the release boundary only when its user
workflow, failure behavior, documentation, upgrade path, and evidence are joined.

#### Working runtime foundation

Outcome: `agent deployment apply` converges one application to a healthy agent,
and `task run` performs useful work through the enforced boundary.

- Consolidate common operations behind one `steward` command while retaining
  expert commands and stable JSON output.
- Add canonical deployment, instance, task, result, and condition models.
- Implement a crash-safe, idempotent desired-state loop with generations, bounded
  retry, garbage collection, and explicit degraded states.
- Join bundle build, placement, signed admission, start, health, task, result,
  egress, secrets, and evidence into one operation.
- Complete Executor-verifiable, time-bounded controller delegation without placing
  tenant root keys in Control.
- Qualify one pinned Hermes adapter and one pinned OpenClaw adapter through the
  same task, chat, health, log, and result contract.
- Ship one protected connector that performs reversible real work, such as creating
  a draft GitHub issue, plus one generic read-only OpenAPI example.

Acceptance gates:

- A fresh operator completes a useful task in under 15 minutes with no manual
  protocol artifact transfer.
- Restarting Control, Executor, Gateway, or the host converges without duplicate
  external effects.
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

- Add node leases, resources, reservations, labels, taints and tolerations,
  isolation classes, topology, image locality, and state locality.
- Make placement an actual controller decision with stale-plan detection and
  Executor revalidation.
- Extend implemented lease-fenced replacement, rescheduling, topology placement,
  cordon, quarantine, budgeted stateless drain, and fleet-wide tenant quotas with
  canary rollout, pause, and rollback.
- Add the storage backend contract and one quota-capable local backend.
- Add quiesce, snapshot, clone, archive, restore, TTL, idle expiry, and garbage
  collection state machines.
- Add `agent fork`, fork-on-task, descendant and retained-byte limits, lineage, and
  clean warm pools.
- Add a Kubernetes Agent Sandbox backend after the local backend contract passes
  conformance.
- Add an agent-facing MCP broker distinct from the operator MCP server.
- Pin MCP server identity, tool schema, version, and requested capabilities; run
  untrusted MCP servers as separately admitted workloads.
- Support deny, observe, allow, and approve modes; shadow decisions; exact approval;
  multi-party thresholds; expiry; revocation; and explicit uncertain outcomes.
- Add OpenBao and SPIFFE/SPIRE reference integrations with rotation and freshness
  policy while retaining protected-file materialization.
- Add a connector conformance kit and two or three anchor connectors.
- Extend the implemented site and tenant freeze, node quarantine, snapshot
  quarantine, and metadata-only support bundle with capability revocation and one
  coherent incident/evidence timeline.
- Finish the React console, concise CLI, autocomplete, SDK/API examples, Terraform
  modules, progressive documentation, packaging, migrations, upgrade tests, and
  release evidence.

Acceptance gates:

- Concurrent reconciliation cannot oversubscribe capacity or double-place an
  instance.
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
- Maintain at least two qualified agent engines, two isolation backends, two
  secret or identity profiles, and one complete disconnected reference deployment.

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

## Pareto order

The smallest set of work that changes Steward from strong primitives into a useful
product is:

1. one-command first task;
2. a real desired-state controller joined to execution;
3. Executor-verifiable delegated automation;
4. tested egress and secret mediation;
5. one real protected external action;
6. multi-node reconciliation and failure recovery;
7. quota-capable state plus a cold fork; and
8. one incident and evidence view.

More adapters, schemas, UI pages, policy documents, or signed artifact types do not
compensate for a missing end-to-end path.

## Deliberate exclusions

Defer or reject these until a demonstrated enforcement requirement changes the
decision:

- agent reasoning, planning graphs, memory frameworks, model training, and model
  serving;
- GPU scheduling, inference cost optimization, and a general model gateway;
- a generic workflow builder or catalog of business agents;
- a public skill or connector marketplace before signing and qualification are
  complete;
- an embedded secret vault, PKI, SSO product, wallet, VMM, database, or consensus
  system;
- prompt-injection classification presented as an enforcement boundary;
- arbitrary transparent TCP or UDP proxying around typed capabilities;
- arbitrary host commands, terminal access, or computer use inside Steward's
  authority processes;
- hot process-memory snapshots before an authority-scrubbing design is proven;
- a general replacement for Kubernetes, Nomad, OpenShell, ZFS, or CSI; and
- hosted-only analytics, assets, or update dependencies.

## Adversarial product questions

### Why not just use OpenShell or NemoClaw?

Use them when their sandbox and onboarding are sufficient. Steward should support
OpenShell as a backend rather than duplicate it. Steward earns its place only when
the operator also needs runtime-neutral application identity, offline-root
delegation, fleet reconciliation, state lineage, exact one-use action authority,
and independent offline evidence.

### Why not OpenClaw Machines?

Choose OpenClaw Machines for an OpenClaw-specific mini-cloud with Firecracker,
browser machines, workspace integrations, backups, chat, and terminal access.
Choose Steward when the site must support multiple agent engines, avoid a mandatory
Cloudflare data plane, run without KVM, remain fully disconnected, or bind every
managed action to customer-held authority and offline evidence.

### Why not Kubernetes Agent Sandbox or OpenSandbox?

Both are strong execution substrates. Steward should integrate them. Neither by
itself defines the customer-held application, delegation, exact effect, replay,
state-authority, and offline evidence record Steward owns. If an operator only
needs isolated code execution, they should use those projects directly.

### Why not Kubernetes or Nomad directly?

They already solve broad scheduling and workload lifecycle. Steward should not
rebuild those systems. Its small scheduler serves one secure site without another
control plane; existing clusters remain reusable backends. Steward adds the
agent-specific authority and evidence contract above placement.

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
- snapshot authority-contamination failures.

Reliability:

- reconciliation convergence time;
- placement and reservation conflict rate;
- node-loss detection and replacement time;
- upgrade and rollback success under injected crashes;
- cold and warm fork readiness latency;
- store and evidence recovery success; and
- tested recovery point and recovery time by deployment profile.

The roadmap should change when evidence changes. Features should advance only when
they improve a complete operator outcome, preserve the authority boundary, and can
be proven through an acceptance or hostile-path test.
