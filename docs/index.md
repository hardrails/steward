---
title: Steward node field manual
description: Install and operate Steward—the open-source sovereign admission and Docker/gVisor execution runtime for tenant-bound AI agent workloads.
home: true
---

<section class="hero">
  <p class="eyebrow">Open-source sovereign agent infrastructure</p>
  <h1>Keep agent execution under local authority.</h1>
  <p class="hero-lede">When signed admission is configured, know which agent artifact was authorized, for which tenant, under which local policy—and keep a receipt the node can verify without a vendor. Steward binds that decision to a hardened Docker + gVisor workload.</p>
  <div class="status-line"><span>Signed local authority</span><span>Offline-verifiable receipts</span><span>Docker + gVisor</span><span>Apache-2.0</span></div>
  <div class="install-box">
    <header><span>Interactive Linux install</span><button class="copy-button" type="button">Copy</button></header>
    <pre><code>curl -fsSL https://github.com/hardrails/steward/releases/latest/download/install-steward.sh | sudo bash</code></pre>
  </div>
  <p><a href="{{ '/getting-started/' | relative_url }}">Start with installation →</a></p>
</section>

## One node boundary, three questions you must answer

<div class="grid">
  <article class="card"><span class="number">01 / AUTHORIZE</span><h3>Why may this run?</h3><p>The opt-in signed path intersects publisher capsule, site-root policy, and tenant-bound intent locally. Stale generations and policy rollback are denied.</p><a href="{{ '/guides/signed-admission/' | relative_url }}">Signed admission →</a></article>
  <article class="card"><span class="number">02 / CONSTRAIN</span><h3>What may it do?</h3><p>Executor admits immutable, resource-bounded images and grants only lineage state, approved inference/service paths, and signed named HTTP(S) routes.</p><a href="{{ '/concepts/security-model/' | relative_url }}">Security model →</a></article>
  <article class="card"><span class="number">03 / VERIFY</span><h3>What did the node enforce?</h3><p>Signed, hash-linked receipts bind the accepted artifact, policy, generation, and mutation outcome for offline verification.</p><a href="{{ '/product/positioning/' | relative_url }}">Why Steward exists →</a></article>
</div>

## Choose your path

<div class="split">
  <div>
    <h3>I operate Linux infrastructure</h3>
    <p>Install a node, inspect its hardened services, enroll it with your control plane, and learn the release/rollback path.</p>
    <p><a href="{{ '/getting-started/' | relative_url }}">Install a node →</a></p>
  </div>
  <div>
    <h3>I integrate a control plane</h3>
    <p>Use the public OpenAPI and uplink contracts from any independently operated control plane.</p>
    <p><a href="{{ '/reference/api/' | relative_url }}">Read the contracts →</a></p>
  </div>
</div>

## System boundary

<div class="architecture-strip">
  <div><small>Authority inputs</small><strong>Capsule + policy + intent</strong><p>Signed artifact ceiling, local trust, tenant generation</p></div>
  <span class="arrow">→</span>
  <div><small>Linux node</small><strong>Steward + Executor</strong><p>Admission, journal, replay fences, signed receipts</p></div>
  <span class="arrow">→</span>
  <div><small>Sandbox</small><strong>Agent OCI image</strong><p>Docker + gVisor, fixed least privilege</p></div>
</div>

Model serving remains separately controlled. Steward's local gateway brokers an
operator-selected OpenAI-compatible route without placing its real credential in
the agent container.

## Agent compatibility in v1.4

Steward can host constrained Hermes Agent and OpenClaw images with persistent
state, a local OpenAI-compatible route, one declared private service, and standard
HTTP(S) proxy access through named, signed routes. Images that require raw TCP/UDP,
transparent interception, raw secrets, host mounts, privileged mode, or undeclared
ports remain outside the boundary.

<div class="callout warning">
  <strong>Do not erase the boundary</strong>
  Do not mount the Docker socket into an agent, add broad host mounts, or replace
  gVisor with the default runtime to make an image work. Those changes defeat the
  security property Steward exists to provide.
</div>

[Test Hermes Agent compatibility]({{ '/guides/hermes-agent/' | relative_url }}) ·
[Test OpenClaw compatibility]({{ '/guides/openclaw/' | relative_url }}) ·
[Configure positive capabilities]({{ '/guides/positive-capabilities/' | relative_url }}) ·
[Configure egress]({{ '/guides/egress/' | relative_url }}) ·
[Bootstrap with Terraform]({{ '/guides/terraform/' | relative_url }}) ·
[Connect an MCP client]({{ '/guides/mcp/' | relative_url }}) ·
[Read all v1.4 limitations]({{ '/limitations/' | relative_url }})

## Market position

Sandbox lifecycle, microVMs, egress policy, credential injection, and JSON audit
logs are increasingly table stakes. Steward focuses on a different gap: portable,
operator-owned authorization inputs tied to the node's recorded enforcement
decision, including disconnected sites. Read the [dated comparison]({{ '/product/market-analysis/' | relative_url }}) and its claim limits.

## Documentation model

This field manual separates learning, procedures, concepts, and exact reference so
you can enter at the level your task requires. Start with the guided install, use the
how-to guides during operations, read the concepts when evaluating trust, and use
the reference pages for automation.
