---
title: Steward — authority control for untrusted AI agents
description: Run containerized agents with Docker and gVisor isolation, exact action permits, credentials outside workloads, and offline-verifiable receipts.
home: true
---

<section class="hero">
  <p class="eyebrow">Open-source, operator-controlled agent infrastructure</p>
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
    <p>Install a Linux node, verify the hardened services, then run a bounded Hermes Agent or OpenClaw adapter behind Steward.</p>
    <p><a href="{{ '/getting-started/' | relative_url }}">Install a node →</a> · <a href="{{ '/guides/hermes-agent/' | relative_url }}">Run Hermes →</a> · <a href="{{ '/guides/openclaw/' | relative_url }}">Run OpenClaw →</a></p>
  </div>
  <div>
    <h3>Operate a fleet</h3>
    <p>Run the customer-owned control plane, enroll nodes through outbound polling, inspect tenant-scoped state in the React console, and transfer commands signed outside the browser.</p>
    <p><a href="{{ '/guides/control-plane/' | relative_url }}">Operate Steward Control →</a> · <a href="{{ '/guides/operator-console/' | relative_url }}">Open the console →</a></p>
  </div>
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
[Configure inference and services]({{ '/guides/positive-capabilities/' | relative_url }}) ·
[Configure egress]({{ '/guides/egress/' | relative_url }})

## Read before production

A shared host is not equivalent to separate hardware. Host root, Docker, gVisor,
the Linux kernel, Gateway, configured upstreams, and operator key custody remain
trusted. Persistent Docker volumes are restricted to an explicit dedicated-host
compatibility mode because the portable local volume driver has no hard byte or
inode quota.

[Security model]({{ '/concepts/security-model/' | relative_url }}) ·
[Known limitations]({{ '/limitations/' | relative_url }}) ·
[Air-gapped deployment]({{ '/guides/air-gapped/' | relative_url }}) ·
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
