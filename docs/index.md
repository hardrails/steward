---
title: Steward — authority control for untrusted AI agents
description: Run containerized agents with Docker and gVisor isolation, exact action permits, credentials outside workloads, and offline-verifiable receipts.
home: true
---

<section class="hero">
  <p class="eyebrow">Open-source, operator-controlled agent application runtime</p>
  <h1>Assume the agent gets tricked.</h1>
  <p class="hero-lede">A hostile calendar invitation, email, web page, document, memory entry, or tool result can steer an AI agent toward a dangerous action. Steward limits the damage: it runs the agent in gVisor, keeps reusable credentials outside the workload, can require a signature over one exact external request, and records what its enforcement points allowed.</p>
  <div class="status-line"><span>Air-gapped operation</span><span>Tenant isolation</span><span>Exact action authority</span><span>Spend-before-network replay control</span><span>Offline evidence</span><span>Apache-2.0</span></div>
  <div class="install-box">
    <header><span>Interactive Linux install</span><button class="copy-button" type="button">Copy</button></header>
    <pre><code>curl --proto '=https' --tlsv1.2 -fsSL https://github.com/hardrails/steward/releases/latest/download/install-steward.sh | sudo /bin/bash -p</code></pre>
  </div>
  <p><a href="{{ '/getting-started/' | relative_url }}">Install Steward →</a></p>
</section>

## The boundary Steward adds

<div class="grid">
  <article class="card"><span class="number">01 / RUN</span><h3>Admit a known workload</h3><p>Signed workload and site policy fix the image, tenant, resources, and maximum capabilities. Executor runs it with gVisor, a read-only root filesystem, no Linux capabilities, and no host mounts or Docker socket.</p><a href="{{ '/guides/signed-admission/' | relative_url }}">Understand admission →</a></article>
  <article class="card"><span class="number">02 / ACT</span><h3>Authorize one real effect</h3><p>Gateway holds the reusable upstream credential. For a protected connector, it accepts only a permit signed for the exact tenant, instance, operation, task, and request bytes, then records that permit as spent before network dispatch.</p><a href="{{ '/guides/authorized-effects/' | relative_url }}">Authorize external effects →</a></article>
  <article class="card"><span class="number">03 / PROVE</span><h3>Verify what was enforced</h3><p>Executor and Gateway write separate signed, hash-linked receipts. Exports can be verified on a disconnected system and omit prompts, request bodies, response bodies, and secret plaintext.</p><a href="{{ '/reference/offline-tools/' | relative_url }}">Verify evidence →</a></article>
</div>

## Choose a path

<div class="split">
  <div>
    <h3>Try one agent</h3>
    <p>Install a Linux node, verify the hardened services, then follow one complete path to a useful, recoverable Hermes result.</p>
    <p><a href="{{ '/getting-started/' | relative_url }}">Install a node →</a> · <a href="{{ '/getting-started/first-task/' | relative_url }}">Run the first task →</a></p>
  </div>
  <div>
    <h3>Operate a fleet</h3>
    <p>Run the customer-owned control plane, enroll nodes through outbound polling, keep exact delegated agent instances converged, recover stateless agents through generation-bound leases, and inspect tenant-scoped state in the React console.</p>
    <p><a href="{{ '/guides/control-plane/' | relative_url }}">Operate Steward Control →</a> · <a href="{{ '/guides/operator-console/' | relative_url }}">Open the console →</a></p>
  </div>
</div>

Already operating Steward? Start with <code>stewardctl status</code>. The
<a href="{{ '/guides/troubleshooting/' | relative_url }}">diagnosis and recovery guide</a>
turns current findings into safe next steps without asking you to decode raw API
responses.

## Build once, choose the agent engine

Define skills, MCP endpoints, a model route, resources, state, lifetime, and
placement once. Steward validates the definition with CUE, can require an offline
OPA policy decision, and packages a deterministic bundle for Hermes.
The same surface explains which fleet node is eligible, admits and starts the
agent directly, retains durable desired state through Steward Control, and derives a
new, short-lived lineage from immutable state snapshot metadata.

```console
stewardctl agent init -runtime hermes -name workspace-auditor workspace-auditor
stewardctl agent build -file workspace-auditor/Stewardfile.cue
stewardctl agent plan -bundle agent.bundle.json -nodes nodes.json -tenant default
stewardctl agent apply -bundle agent.bundle.json -nodes nodes.json -tenant default \
  -capsule hermes.capsule.dsse.json -policy site.policy.dsse.json \
  -site-root-public-key site-root.pub -site-root-key-id site-root-1 \
  -token-file /etc/steward/executor.token
```

[Build and run an agent]({{ '/guides/build-agents/' | relative_url }}) ·
[Check platform support]({{ '/reference/platform-support/' | relative_url }})

## Useful agents, with finite authority

<div class="grid">
  <article class="card"><span class="number">01 / RESEARCH</span><h3>Search without handing over the keys</h3><p>Hermes can search and extract web sources through an isolated worker, treat retrieved text as untrusted, and publish source-linked findings to the control plane.</p><a href="{{ '/guides/research-agents/' | relative_url }}">Run a research agent →</a></article>
  <article class="card"><span class="number">02 / BUILD</span><h3>Delegate to a coding specialist</h3><p>Hermes can ask the official Codex or Claude Code CLI to inspect or change a disposable Git worktree. The CLI and its login remain in a separate gVisor container.</p><a href="{{ '/guides/coding-workers/' | relative_url }}">Connect a coding worker →</a></article>
  <article class="card"><span class="number">03 / REPORT</span><h3>Receive findings as they happen</h3><p>A running instance can send bounded status and findings through a durable, identity-stamped, at-least-once event channel. Events carry no command authority.</p><a href="{{ '/guides/controller-events/' | relative_url }}">Receive agent events →</a></article>
</div>

## What is protected

<div class="architecture-strip">
  <div><small>Untrusted input</small><strong>Web, mail, calendar, documents, tools</strong><p>May contain prompt injection or misleading data</p></div>
  <span class="arrow">→</span>
  <div><small>Untrusted runtime</small><strong>Agent in Docker + gVisor</strong><p>No reusable external credential or host authority</p></div>
  <span class="arrow">→</span>
  <div><small>Trusted boundary</small><strong>Steward Gateway</strong><p>Verifies exact authority, spends permits, injects credentials</p></div>
  <span class="arrow">→</span>
  <div><small>External effect</small><strong>Operator-approved service</strong><p>Signed enforcement evidence remains local</p></div>
</div>

Steward cannot tell whether arbitrary text is malicious, and it does not make model
output trustworthy. It constrains calls that pass through Steward. An unmanaged
browser, mounted credential, host socket, direct network route, or computer-use
worker remains a separate authority boundary.

## Secrets stay outside workloads

Use an existing secret manager or an offline process to render owner-only files for
Gateway. Steward validates the non-secret manifest, ownership, permissions, identity,
and rotation epoch. It does not build another vault, store provider credentials, or
return secret values through its control plane, console, MCP adapter, or receipts.

[Manage Gateway credentials]({{ '/guides/secrets/' | relative_url }}) ·
[Connect an inference provider]({{ '/guides/inference/' | relative_url }}) ·
[Configure state and services]({{ '/guides/positive-capabilities/' | relative_url }}) ·
[Configure egress]({{ '/guides/egress/' | relative_url }})

## Read before production

A shared host is not equivalent to separate hardware. Host root, Docker, gVisor,
the Linux kernel, Gateway, configured upstreams, and operator key custody remain
trusted. Shared-host persistent state requires Steward's separate OpenZFS worker,
which applies a hard byte and object quota to each tenant lineage. Portable Docker
volumes remain a dedicated-host-only compatibility mode.

[Security model]({{ '/concepts/security-model/' | relative_url }}) ·
[Known limitations]({{ '/limitations/' | relative_url }}) ·
[Persistent state]({{ '/guides/persistent-state/' | relative_url }}) ·
[Air-gapped deployment]({{ '/guides/air-gapped/' | relative_url }}) ·
[Cloud node pools]({{ '/guides/cloud-fleets/' | relative_url }}) ·
[Terraform bootstrap]({{ '/guides/terraform/' | relative_url }}) ·
[MCP setup]({{ '/guides/mcp/' | relative_url }})

## Why this product exists

Agent frameworks optimize what an agent can do. Sandboxes isolate code. Secret
managers protect credentials. Network gateways mediate traffic. Steward connects
those boundaries into a local authorization-to-enforcement record: exact signed
authority, durable spend before network access, credentials outside the workload,
and offline-verifiable receipts.

The [dated market analysis]({{ '/product/market-analysis/' | relative_url }})
compares that claim with public product documentation and states its limits.
[The product roadmap]({{ '/product/roadmap/' | relative_url }}) explains what
Steward should build, reuse, and deliberately leave to other systems.
