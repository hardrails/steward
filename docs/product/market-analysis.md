---
title: Agent execution market analysis
description: A dated comparison of agent sandboxes and runtimes with Steward's operator-controlled admission, anti-replay state, and offline-verifiable receipts.
section: Product
---

# Agent execution market analysis

> Market snapshot: 2026-07-11. This analysis uses the linked primary sources.
> A vendor's documented feature is not a security certification, and an omitted
> feature is not proof that the vendor can never provide it.

Several products offer hardened containers or microVMs—small virtual machines with
their own kernel—plus egress policy, lifecycle APIs, organization controls,
observability, and audit logs. These controls no longer distinguish a runtime by
themselves.

Steward focuses on customer-owned nodes that verify local authorization, grant only
approved state, inference, service, and HTTP(S) paths, and export receipts for
offline verification.

## Comparison

| System | Documented focus as of the snapshot | Where Steward's focus differs |
| --- | --- | --- |
| [NVIDIA NemoClaw](https://docs.nvidia.com/nemoclaw/latest/about/overview.html) / [OpenShell](https://github.com/NVIDIA/OpenShell) | NemoClaw documents OpenShell sandboxing, routed inference, and declarative egress for always-on agents. OpenShell labels itself alpha and “single-player mode.” The current [Hermes notes](https://docs.nvidia.com/nemoclaw/latest/user-guide/hermes/reference/platform-support) list offline installation as unsupported. | Steward combines tenant-bound signed intent, site-root policy, immutable artifact admission, anti-replay fences, and offline-verifiable receipts without a vendor service in the trust path. The maturity and offline differences are dated, not permanent claims. |
| [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/governance/) / [AI Governance](https://www.docker.com/products/ai-governance/) | Docker documents microVMs, central filesystem/network and Model Context Protocol (MCP) policy, organization sign-in, decision logs, credential injection, DNS policy, and direct workspace passthrough. | Steward constrains remote, tenant-labelled instances through signed local authorization. It does not claim isolation, egress policy, DNS gating, or JSON audit as unique. |
| [OpenSandbox](https://github.com/alibaba/OpenSandbox) | OpenSandbox documents a sandbox API, Docker and Kubernetes backends, lifecycle control, and [gVisor, Kata, and Firecracker runtimes](https://open-sandbox.ai/guides/secure-container). | Steward adds site-owned admission, tenant/instance replay protection, and operator-verifiable receipts. The projects could complement each other; Steward does not depend on OpenSandbox. |
| [Kubernetes Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) | The Kubernetes SIG project documents `Sandbox` Custom Resource Definitions (CRDs) for isolated, stateful single workloads, plus templates, claims, warm pools, and optional gVisor or Kata isolation. | It provides a Kubernetes execution API and controller. Steward uses Docker/gVisor, but a future backend could preserve the same admission and receipt contract. |
| [E2B](https://www.e2b.dev/) | E2B documents Firecracker microVMs for untrusted workflows and managed, bring-your-own-cloud (BYOC), on-premises, and self-hosted options. Its [open-source project](https://github.com/e2b-dev/e2b) documents Terraform self-hosting for Amazon Web Services (AWS) and Google Cloud Platform (GCP). | Steward does not recreate a microVM platform. It provides an offline, site-policy-controlled deployment and evidence boundary for long-lived agents on Docker/gVisor. |
| [Daytona](https://www.daytona.io/docs/en/) | Daytona documents dedicated-kernel sandboxes with separate filesystems and networks, snapshots, organizations, resource limits, audit logs, OpenTelemetry, and egress controls. Its [source at the reviewed revision](https://github.com/daytonaio/daytona/blob/ec4c21b2d597091ac09ecc278f3bcc172575a987/apps/docs/src/content/docs/en/oss-deployment.mdx) documents open-source Docker Compose deployment. | Steward does not claim sandboxes, role-based access control, egress, or logs as unique. It focuses on local authorization-to-enforcement receipts for tenant-bound, preloaded agents. |
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

Gateway brokers inference, authenticated service ingress, and named HTTP(S) routes
without raw network access. Persistent state is scoped to one tenant and workload
history and requires explicit purge, but its local Docker volume has no enforced byte
or inode quota and is limited to the dedicated-host compatibility mode. Signed
receipts record admission and lifecycle events; inference and egress admissions
include the effective route-policy digest. They do not embed the complete
state/service grant or individual Gateway traffic decisions.

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
- [NIST's agent-hijacking discussion](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)
  describes the risk created when trusted instructions and untrusted external
  data are not clearly separated. NIST's 2026
  [agent identity and authorization concept paper](https://www.nist.gov/news-events/news/2026/02/new-concept-paper-identity-and-authority-software-agents)
  signals the need to apply identity practices to software agents.
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
