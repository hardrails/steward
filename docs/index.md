---
title: Steward — isolated AI agent execution on Linux
description: Install and operate Steward for operator-controlled local admission, Docker/gVisor isolation, tenant-bound commands, and offline-verifiable receipts.
home: true
---

<section class="hero">
  <p class="eyebrow">Open-source, operator-controlled agent infrastructure</p>
  <h1>Keep agent execution under local authority.</h1>
  <p class="hero-lede">With signed admission enabled, Steward verifies which agent artifact local policy permits, which tenant and instance it serves, and which capabilities it may receive. Steward then creates a hardened Docker + gVisor workload and records a receipt that can be verified offline.</p>
  <div class="status-line"><span>Signed local authorization</span><span>Offline-verifiable receipts</span><span>Docker + gVisor</span><span>Apache-2.0</span></div>
  <div class="install-box">
    <header><span>Interactive Linux install</span><button class="copy-button" type="button">Copy</button></header>
    <pre><code>curl -fsSL https://github.com/hardrails/steward/releases/latest/download/install-steward.sh | sudo bash</code></pre>
  </div>
  <p><a href="{{ '/getting-started/' | relative_url }}">Start with installation →</a></p>
</section>

## Three questions for every workload

<div class="grid">
  <article class="card"><span class="number">01 / AUTHORIZE</span><h3>Why may this run?</h3><p>Signed admission requires the publisher's workload limits, the operator's site policy, and the tenant's instance request to allow the same deployment. A stored instance generation rejects delayed commands for a replaced instance; a separate policy epoch rejects policy rollback.</p><a href="{{ '/guides/signed-admission/' | relative_url }}">Signed admission →</a></article>
  <article class="card"><span class="number">02 / CONSTRAIN</span><h3>What may it do?</h3><p>Executor accepts only immutable, resource-bounded images. Signed policy can grant approved model, private-service, and HTTP(S) routes. Persistent Docker state is available only through an explicit dedicated-host compatibility mode because it has no portable hard quota.</p><a href="{{ '/concepts/security-model/' | relative_url }}">Security model →</a></article>
  <article class="card"><span class="number">03 / VERIFY</span><h3>What did the node enforce?</h3><p>Hash-linked, signed receipts record the accepted artifact, policy, instance generation, and host-mutation result for offline verification.</p><a href="{{ '/reference/offline-tools/' | relative_url }}">Verify and export evidence →</a></article>
</div>

## Choose your path

<div class="split">
  <div>
    <h3>I operate Linux infrastructure</h3>
    <p>Install a node, inspect its hardened services, connect it to your control plane, and learn how upgrades and rollback work.</p>
    <p><a href="{{ '/getting-started/' | relative_url }}">Install a node →</a></p>
  </div>
  <div>
    <h3>I integrate a control plane</h3>
    <p>Use the public OpenAPI and outbound uplink contracts from any independently operated control plane.</p>
    <p><a href="{{ '/reference/api/' | relative_url }}">Read the contracts →</a></p>
  </div>
</div>

## System boundary

<div class="architecture-strip">
  <div><small>Authorization inputs</small><strong>Workload profile + site policy + instance request</strong><p>Artifact limits, local trust, tenant and instance identity</p></div>
  <span class="arrow">→</span>
  <div><small>Linux node</small><strong>Steward node services</strong><p>Admission, capability gateway, durable anti-replay state, signed receipts</p></div>
  <span class="arrow">→</span>
  <div><small>Sandbox</small><strong>Agent container image</strong><p>Docker + gVisor, fixed minimal privileges</p></div>
</div>

Model serving is managed separately. Steward's local gateway connects the agent to
an operator-selected, OpenAI-compatible route without putting the upstream
credential in the agent container.

## Agent adapter contracts

Steward defines fixed filesystem and runtime layouts for Hermes Agent and OpenClaw
adapters. These contracts do not certify the official upstream images. Neither
official image is currently validated for direct use with Steward. Before signing
an operator-built adapter's exact image digest and command, validate it against the
documented image, identity, state, authentication, and runtime requirements.

An accepted adapter can receive a local OpenAI-compatible route, one declared
private service, and HTTP(S) proxy access through named, signed routes. Persistent
Docker state requires an explicit dedicated-host compatibility setting because
the portable local volume driver cannot enforce hard byte or inode quotas. Steward
rejects images that require raw TCP/UDP, transparent interception, raw secrets,
host mounts, privileged mode, or undeclared ports.

<div class="callout warning">
  <strong>Do not erase the boundary</strong>
  Do not mount the Docker socket into an agent, add broad host mounts, or replace
  gVisor with the default runtime to make an image work. Those changes remove the
  isolation Steward is intended to enforce.
</div>

[Review the Hermes Agent adapter contract]({{ '/guides/hermes-agent/' | relative_url }}) ·
[Review the OpenClaw adapter contract]({{ '/guides/openclaw/' | relative_url }}) ·
[Configure positive capabilities]({{ '/guides/positive-capabilities/' | relative_url }}) ·
[Configure egress]({{ '/guides/egress/' | relative_url }}) ·
[Bootstrap with Terraform]({{ '/guides/terraform/' | relative_url }}) ·
[Connect an MCP client]({{ '/guides/mcp/' | relative_url }}) ·
[Import images and export evidence]({{ '/reference/offline-tools/' | relative_url }}) ·
[Read all current limitations]({{ '/limitations/' | relative_url }})

## Market position

Many products now provide sandbox lifecycle, small virtual-machine isolation,
egress policy, credential injection, and JSON audit logs. Steward focuses on
operator-owned authorization tied to the node's recorded enforcement decision,
including at disconnected sites. Read the
[dated comparison]({{ '/product/market-analysis/' | relative_url }}) and its claim
limits.

## Documentation model

Start with the guided installation. Use the how-to guides for operations, the
concept pages to evaluate trust and design, and the reference pages for exact
automation contracts.
