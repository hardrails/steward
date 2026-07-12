---
title: Agent execution market analysis
description: A dated V1.3 comparison of agent sandboxes and runtimes, the commodity baseline, and Steward's narrow sovereign-execution focus.
section: Product
---

# Agent execution market analysis

> Market snapshot: 2026-07-11. This analysis uses the linked primary sources.
> A vendor's documented feature is not a security certification, and an omitted
> feature is not proof that the vendor can never provide it.

Agent execution is rapidly becoming a capable market: microVMs and hardened
containers, egress restrictions, lifecycle APIs, organization controls,
observability, and audit logs are available from several projects. That is good
news for operators. It also means those features alone are not a durable product
claim.

Steward V1.3 is aimed at a narrower, complementary problem: a customer-owned
node should be able to verify a locally authorized deployment envelope,
grant only locally enforced state/inference/service paths, and export an
offline-verifiable receipt of the enforcement decisions it recorded.

## Comparison

| System | Documented focus as of the snapshot | Where Steward's V1.3 focus differs |
| --- | --- | --- |
| [NVIDIA NemoClaw](https://docs.nvidia.com/nemoclaw/latest/about/overview.html) / [OpenShell](https://github.com/NVIDIA/OpenShell) | NemoClaw documents a reference stack for always-on agents using OpenShell sandboxing, routed inference, and declarative egress. OpenShell currently labels itself alpha and “single-player mode”; the [Hermes platform notes](https://docs.nvidia.com/nemoclaw/latest/user-guide/hermes/reference/platform-support) currently list air-gapped/offline installs as unsupported. | Steward is not a competing policy language or agent distribution. Its shipped wedge is tenant-bound signed intent, site-root policy, immutable artifact admission, generation fences, and offline-verifiable node receipts with no vendor service in the trust path. Current maturity/offline differences are dated observations, not permanent claims. |
| [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/governance/) / [AI Governance](https://www.docker.com/products/ai-governance/) | Docker documents microVM sandboxes plus centrally managed filesystem/network policy, MCP controls, organization sign-in enforcement, and structured policy-decision audit logs. Its architecture also documents direct workspace passthrough as a supported mode. | Docker's controls are valuable endpoint governance. Steward v1.3 targets remote, tenant-labelled agent instances whose immutable Docker input and resource authority are constrained by a signed local deployment envelope. Steward should not claim that isolation, egress policy, or JSON audit logs are unique. |
| [OpenSandbox](https://github.com/alibaba/OpenSandbox) | OpenSandbox documents a unified sandbox API, Docker and Kubernetes backends, lifecycle control, and [secure runtime choices](https://open-sandbox.ai/guides/secure-container) including gVisor, Kata, and Firecracker. | This is close to a reusable execution substrate. Steward's value sits above that substrate: a site-owned admission decision, tenant/instance fencing, and an operator-verifiable receipt. The projects could be complementary; v1.3 does not depend on OpenSandbox. |
| [Kubernetes Agent Sandbox](https://agent-sandbox.sigs.k8s.io/docs/) | The Kubernetes SIG project documents `Sandbox` and related CRDs for isolated, stateful singleton workloads, templates, claims, warm pools, and optional gVisor or Kata isolation. | It is a Kubernetes execution API and controller, not a general sovereign control plane. Steward V1.3 deliberately stays on Docker and gVisor rather than adding a Kubernetes backend; a future backend could preserve the same admission and receipt contract. |
| [E2B](https://www.e2b.dev/) | E2B documents Firecracker microVM sandboxing for untrusted workflows and advertises managed, BYOC, on-premises, and self-hosted options. Its [open-source project](https://github.com/e2b-dev/e2b) documents Terraform self-hosting for AWS and GCP. | E2B validates demand for secure code-execution environments. Steward does not attempt to recreate a microVM platform; it focuses on an offline, site-policy-controlled deployment and evidence boundary for long-lived agent instances on an operator's required Docker/gVisor host. |
| [Daytona](https://www.daytona.io/docs/en/) | Daytona documents isolated sandboxes with a dedicated kernel, filesystem, network stack, snapshots, organizations, resource limits, audit logs, OpenTelemetry, and egress controls. Its [source repository](https://github.com/daytonaio/daytona/blob/main/apps/docs/src/content/docs/en/oss-deployment.mdx) documents an OSS Docker Compose deployment. | Daytona is a broad, capable agent/code-workspace platform. Steward's defensible claim is not “we have sandboxes, RBAC, or logs.” It is the specific local authorization-to-enforcement receipt chain for tenant-bound, locally preloaded agent deployment with no general egress. |
| [Amazon Bedrock AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/what-is-bedrock-agentcore.html) | AgentCore documents a managed runtime alongside identity, memory, MCP gateway, code interpreter, browser, and OpenTelemetry-compatible observability. Its [VPC documentation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html) describes AWS-managed network interfaces and IAM service roles for private-resource access. | AgentCore is a managed cloud option with deep AWS integration. Steward addresses operators who require local policy keys, locally imported artifacts, local infrastructure, and an operating path that does not require a vendor control plane or Internet access. V1.3 does not claim an equivalent managed service portfolio. |

## What is now table stakes

The comparison shows why V1.3 should not build product identity around any one
of these capabilities:

- isolated execution with a container, gVisor, Kata, Firecracker, or microVM;
- sandbox creation, pause/resume, snapshots, templates, or pools;
- network allowlists and default-deny rules;
- filesystem restrictions and secret injection;
- organization roles, quotas, OpenTelemetry, dashboards, or JSON audit logs;
- a generic code-execution, browser, or agent SDK.

Those remain useful controls. In Steward, Docker plus gVisor is a required host
substrate, not the product's moat.

## The V1.3 wedge

The V1.3 differentiator is a single **authorization-to-enforcement
receipt chain**:

1. a publisher-signed, immutable profile capsule defines a bounded workload
   ceiling;
2. a site-root-signed policy scopes publishers, tenant authority, profiles,
   repositories or exact image manifests, resource ceilings, inference route
   IDs, service IDs, and revocation;
3. an authenticated instance intent binds an actual tenant, node, instance,
   lineage, and generation;
4. the local executor admits only the intersection, creates the constrained
   gVisor workload, and rejects replay, policy rollback, and observed drift; and
5. the node emits signed, hash-linked receipts that an operator can verify
   offline.

The narrow gateway now brokers one inference route and authenticated service path
without handing a workload a general proxy or upstream secret. Persistent state
is tenant-lineage scoped and explicitly purged. These capabilities extend the
receipt chain; they do not replace it as the differentiator.

The important word is *receipt*, not *transcript*. A receipt documents the
runtime inputs and enforcement decisions Steward observed. It does not claim to
reconstruct prompt meaning, prove agent intent, or certify upstream behavior.

## Standards and research signals

Several current sources point to the same design pressure: agent interoperability
and capability are expanding, while identity, authorization, and prompt/data
boundaries need explicit treatment.

- The [Model Context Protocol authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
  defines transport authorization around OAuth 2.1, while its
  [security guidance](https://modelcontextprotocol.io/specification/2025-03-26/index)
  says implementers must build consent and authorization around powerful data
  access and code-execution paths. A tool protocol does not replace local
  workload admission.
- The [A2A Protocol](https://a2a-protocol.org/dev/specification/) is an open
  interoperability protocol for independent agent systems. It makes
  framework-neutral execution boundaries more useful; it does not itself decide
  which tenant may run a workload on a host.
- [NIST's agent-hijacking discussion](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)
  describes the risk created when trusted instructions and untrusted external
  data are not clearly separated. NIST's 2026
  [agent identity and authorization concept paper](https://www.nist.gov/news-events/news/2026/02/new-concept-paper-identity-and-authority-software-agents)
  further signals the need to apply identity practices to software agents.
- The [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  includes goal hijack, tool misuse, identity and privilege abuse, supply-chain
  vulnerabilities, unexpected code execution, and memory/context poisoning.
  Steward's narrow grants and artifact/policy binding address only part of that
  risk set; they do not make prompts or agents intrinsically safe.
- A 2026 [sandbox-assurance research framework](https://arxiv.org/abs/2606.18532)
  argues that sandbox claims depend on multiple dimensions including
  controllability, observability, containment, reproducibility, and governance
  artifacts. This is research, not a certification of Steward or any product.

## Claim limits

Product documentation should make the following limits explicit:

- **Not physical isolation.** Docker and gVisor reduce the workload's authority;
  they do not make shared hardware or host root untrusted.
- **Not a proof against host compromise.** Without hardware-backed keys or an
  external evidence anchor, node-local receipts are tamper-evident within the
  stated trust boundary, not globally non-repudiable.
- **Not universal air-gap certification.** V1.3 supports disconnected installation
  and operation after the Docker/gVisor host, approved local image, signed policy,
  and keys are prepared. It does not bootstrap a bare operating system, operate a
  model service, or confer a formal accreditation.
- **Not semantic observability.** The receipt does not include or validate
  prompts, model output, agent explanations, or semantic tool actions.
- **Not a public access layer.** V1.3 service ingress is authenticated and
  loopback-only. It does not replace tenant end-user authentication,
  reverse-proxy design, or operator decisions about public exposure.

That precision is part of the value proposition. A sovereign operator should be
able to see exactly what Steward can enforce, what its receipt means, and where
additional controls are still required.
