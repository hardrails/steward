---
title: Agent execution market analysis
description: A dated comparison of agent sandboxes and runtimes with Steward's operator-controlled admission, anti-replay state, and offline-verifiable receipts.
section: Product
---

# Agent execution market analysis

> Market snapshot: 2026-07-13. This analysis uses the linked primary sources.
> A vendor's documented feature is not a security certification, and an omitted
> feature is not proof that the vendor can never provide it.

Several products offer hardened containers or microVMs—small virtual machines with
their own kernel—plus egress policy, lifecycle APIs, organization controls,
observability, and audit logs. These controls no longer distinguish a runtime by
themselves.

Steward focuses on customer-owned nodes that verify local authorization, grant only
approved state, inference, service, and network operations, and export receipts for
offline verification. Its product boundary assumes the agent can be manipulated;
enforcement therefore sits outside the agent process.

## Comparison

| System | Documented focus as of the snapshot | Where Steward's focus differs |
| --- | --- | --- |
| [NVIDIA NemoClaw](https://github.com/NVIDIA/NemoClaw) / [OpenShell](https://github.com/NVIDIA/OpenShell) | NemoClaw packages supported agents around OpenShell. OpenShell documents Docker, rootless Podman, microVM, and Kubernetes drivers plus declarative process and network policy. Its README labels the project alpha and “single-player mode” while multi-tenant operation is still a stated direction. | Steward narrows the first problem to a hostile multi-tenant Linux node: tenant-bound signed intent, site-root policy, immutable artifact admission, anti-replay fences, and offline-verifiable receipts. The maturity difference is dated, not a permanent claim. |
| [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) / [AI Governance](https://docs.docker.com/ai/sandboxes/governance/) | Docker documents microVMs, filesystem and network policy, organization sign-in, decision logs, credential injection, DNS policy, and workspace sharing. Linux installation requires Kernel-based Virtual Machine (KVM) support and Docker sign-in; organization governance is a paid capability. | Steward uses Docker and gVisor on an operator-owned node without requiring a vendor login or hosted policy service. It does not claim isolation, egress policy, DNS gating, credential injection, or JSON audit as unique. |
| [OpenSandbox](https://github.com/alibaba/OpenSandbox) | OpenSandbox documents a sandbox API, Docker and Kubernetes backends, lifecycle control, and [gVisor, Kata, and Firecracker runtimes](https://open-sandbox.ai/guides/secure-container). | Steward adds site-owned admission, tenant/instance replay protection, and operator-verifiable receipts. The projects could complement each other; Steward does not depend on OpenSandbox. |
| [Kubernetes Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) | The Kubernetes SIG project documents `Sandbox` Custom Resource Definitions (CRDs), templates, claims, warm pools, state, and optional gVisor or Kata isolation. Kubernetes itself [does not define a first-class tenant object](https://kubernetes.io/docs/concepts/security/multi-tenancy/); operators must assemble the isolation policy. | Steward provides one opinionated tenant and evidence contract on a Linux node without making Kubernetes a prerequisite. A future backend could preserve that contract on Kubernetes. |
| [E2B](https://github.com/e2b-dev/infra) | E2B provides a Firecracker sandbox platform. Its [self-host guide](https://github.com/e2b-dev/infra/blob/main/self-host.md) combines Terraform, Packer, PostgreSQL, DNS, and cloud-specific infrastructure; that is a capable platform, not a one-node offline package. | Steward does not recreate a microVM platform. It provides an offline, site-policy-controlled deployment and evidence boundary for long-lived agents on Docker/gVisor. |
| [Daytona](https://github.com/daytonaio/daytona) | The public repository contains a broad sandbox API, but its README says public core development stopped after June 2026 and moved to a private codebase. The frozen public source remains under the [GNU Affero General Public License](https://github.com/daytonaio/daytona/blob/main/LICENSE). | Steward's open repository remains the complete node enforcement product. Independent rebuildability and offline maintainability are part of the boundary, not an installation option around a private core. |
| [OpenClaw](https://github.com/openclaw/openclaw/security) | OpenClaw provides agents, tools, skills, memory, and optional Docker sandboxing. Its security documentation says one gateway is not an adversarial multi-tenant boundary and that session or memory scoping does not create per-user authorization. | Steward treats the OpenClaw image, tools, memory, and configuration as untrusted workload content. OpenClaw can supply agent behavior; Steward supplies the external tenant boundary. |
| [Hermes Agent](https://github.com/NousResearch/hermes-agent/security) | Hermes provides skills, plugins, subagents, scheduled work, and several execution backends. Its security documentation describes a single-user personal-agent model and warns that skills and plugins run with the agent's authority. | Steward qualifies one exact Hermes build and places policy, credentials, resource controls, and evidence outside Hermes. It does not rely on the agent's own permission model for tenant isolation. |
| [Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/what-is-bedrock-agentcore.html) | AgentCore documents managed runtime, identity, memory, MCP gateway, code interpreter, browser, and OpenTelemetry observability. Its [Virtual Private Cloud (VPC) guide](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html) describes AWS-managed network interfaces and Identity and Access Management (IAM) service roles. | Steward serves operators who require local keys, artifacts, infrastructure, and operation without a vendor control plane or public Internet. It does not claim an equivalent managed-service portfolio. |

## Common platform capabilities

These capabilities remain useful but do not distinguish Steward:

- isolated execution with a container, gVisor, Kata, Firecracker, or microVM;
- sandbox creation, pause/resume, snapshots, templates, or pools;
- network allowlists and default-deny rules;
- filesystem restrictions and secret injection;
- organization roles, quotas, OpenTelemetry, dashboards, or JSON audit logs;
- a generic code-execution, browser, or agent SDK.

These controls remain useful. Docker and gVisor are Steward's required host
foundation, not its primary differentiator.

## Gap selection

The release analysis compared candidate work by operator value, differentiation,
risk reduction, implementation cost, and whether a hostile-path acceptance test
could prove the claim. It also started with a failure question: *how could this
feature turn one manipulated agent into another tenant's incident?*

| Candidate | Operator value | Security effect | Main release risk | Decision |
| --- | --- | --- | --- | --- |
| Named credential-brokered operations | Makes authenticated agent work possible without placing the credential in the workload. | Reduces standing secret exposure and converts a broad HTTPS tunnel into exact method, path, destination, and budget checks. | Accidentally building a general secret injector or proxy. | Build a narrow connector contract in the existing Gateway. |
| Shared-host persistent state | Makes long-lived agents practical on one multi-tenant host. | Contains byte and inode exhaustion and creates a foundation for memory provenance. | A filesystem quota that disappears after reboot would create a false isolation claim. | Keep admission closed until a qualified quota backend can be reconciled and tested. |
| Automatic journal recovery | Reduces operator intervention after partial host failures. | Can prevent duplicate effects and authority resurrection. | A convenient “force clear” path could erase the only safe ambiguity signal. | Preserve degraded containment; add recovery only when observations prove one outcome. |
| Generic workflow or browser engine | Adds broad agent features quickly. | Expands the highest-risk code and dependency surface. | Duplicates agent frameworks and weakens the small trusted core. | Leave agent behavior out of process. |

The selected connector is intentionally narrower than generic egress. A workload
names an operation; the operator maps it to one exact upstream method and path.
Gateway adds an operator-owned credential only after the signed workload grant,
destination, address, concurrency, call, byte, and time checks agree. The workload
never receives the upstream origin or credential. Generic `CONNECT` remains opaque
and receives no injected secret.

## Steward's specific focus

An **authorization-to-enforcement receipt chain** links the signed decision to run
an agent with the controls the node records:

1. a publisher-signed, immutable profile capsule defines the workload's maximum
   capabilities;
2. a site-root-signed policy scopes publishers, tenant authority, profiles,
   repositories or exact image manifests, resource ceilings, inference route
   IDs, service IDs, egress route IDs, and revocation;
3. an authenticated instance intent binds a tenant, node, instance, state lineage,
   and generation;
4. the local executor admits only the intersection, creates the constrained
   gVisor workload, and rejects replay, policy rollback, and observed drift; and
5. the node emits signed, hash-linked receipts that an operator can verify
   offline.

Gateway brokers inference, authenticated service ingress, named connector
operations, and HTTP(S) routes without raw network access. Connector credentials
are added at the last hop and are bound by digest to the retained grant. Persistent
state is scoped to one tenant and workload history and requires explicit purge, but
its local Docker volume has no enforced byte or inode quota and is limited to the
dedicated-host compatibility mode. Signed receipts record admission and lifecycle
events; network admissions include the effective route-policy digest. Individual
traffic records have the narrower guarantees documented in the capability guide.

A receipt records runtime inputs and observed enforcement decisions. It does not
reconstruct prompt meaning, prove agent intent, or certify upstream behavior.

## Standards and research signals

The following current standards and publications focus on identity,
authorization, and separating trusted instructions from untrusted data.

- The [Model Context Protocol authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
  defines transport authorization using OAuth 2.1, while its
  [security guidance](https://modelcontextprotocol.io/specification/2025-03-26/index)
  requires consent and authorization around powerful data and code-execution
  paths. A tool protocol does not replace local workload admission.
- The [Agent2Agent (A2A) Protocol](https://a2a-protocol.org/dev/specification/) is
  an open interoperability protocol for independent agents. It does not decide which
  tenant may run a workload on a host.
- [NIST's large-scale agent red-team report](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition)
  reports that every tested frontier model was hijacked at least once across more
  than 250,000 attempts. The result supports designing for a manipulated agent,
  not claiming that a prompt can eliminate prompt injection. NIST's
  [agent identity and authorization concept paper](https://www.nccoe.nist.gov/publications/other/accelerating-adoption-software-and-ai-agent-identity-and-authorization-concept)
  calls for least privilege, dynamic authorization, authority proofs, and
  tamper-resistant records.
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
  prompts, model output, agent explanations, or semantic tool actions.
- **Not a public access layer.** Steward service ingress is authenticated and
  loopback-only. It does not replace tenant end-user authentication,
  reverse-proxy design, or operator decisions about public exposure.

Operators should be able to identify exactly what Steward enforces, what a receipt
proves, and where they still need additional controls.
