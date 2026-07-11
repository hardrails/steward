---
title: Steward node field manual
description: Install, secure, operate, and audit Steward—the open-source Docker and gVisor node runtime for isolated multi-tenant AI agent workloads.
home: true
---

<section class="hero">
  <p class="eyebrow">Open-source sovereign agent infrastructure</p>
  <h1>Keep agent execution under local authority.</h1>
  <p class="hero-lede">Steward turns an operator-controlled Linux server into a hardened execution node for untrusted AI agent images. It keeps Docker authority out of the control plane, works across trust boundaries, and has no dependency on private software.</p>
  <div class="status-line"><span>Docker + gVisor</span><span>Air-gap capable</span><span>Control-plane neutral</span><span>Apache-2.0</span></div>
  <div class="install-box">
    <header><span>Interactive Linux install</span><button class="copy-button" type="button">Copy</button></header>
    <pre><code>curl -fsSL https://github.com/hardrails/steward/releases/latest/download/install-steward.sh | sudo bash</code></pre>
  </div>
  <p><a href="{{ '/getting-started/' | relative_url }}">Start with installation →</a></p>
</section>

## One node boundary, three hard problems

<div class="grid">
  <article class="card"><span class="number">01 / ISOLATE</span><h3>Untrusted workloads</h3><p>Executor admits only immutable, resource-bounded images and applies a fixed Docker + gVisor sandbox.</p><a href="{{ '/concepts/security-model/' | relative_url }}">Security model →</a></article>
  <article class="card"><span class="number">02 / CONTROL</span><h3>Remote fleets</h3><p>Outbound HTTPS channels carry commands and evidence without exposing Docker or requiring inbound node access.</p><a href="{{ '/concepts/control-plane-boundary/' | relative_url }}">Trust boundary →</a></article>
  <article class="card"><span class="number">03 / OWN</span><h3>Sovereign operation</h3><p>Static artifacts, offline installation, public contracts, operator-owned PKI, and zero private dependencies.</p><a href="{{ '/guides/air-gapped/' | relative_url }}">Air-gapped guide →</a></article>
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
  <div><small>Remote</small><strong>Independent control plane</strong><p>Tenancy, policy, desired state, fleet evidence</p></div>
  <span class="arrow">→</span>
  <div><small>Linux node</small><strong>Steward + Executor</strong><p>Lifecycle, admission, replay fencing</p></div>
  <span class="arrow">→</span>
  <div><small>Sandbox</small><strong>Agent OCI image</strong><p>Docker + gVisor, fixed least privilege</p></div>
</div>

Inference is intentionally outside this boundary. Operators can expose local models
through a separately controlled OpenAI-compatible gateway.

## Agent compatibility in v0.1

Steward is designed to host agent runtimes such as Hermes Agent and OpenClaw, but
v0.1 only supports hardened image-admission and lifecycle validation. The connected,
persistent operation these agents need requires future explicit grants for egress,
secrets, storage, and ports.

<div class="callout warning">
  <strong>Do not erase the boundary</strong>
  Do not mount the Docker socket into an agent, add broad host mounts, or replace
  gVisor with the default runtime to make an image work. Those changes defeat the
  security property Steward exists to provide.
</div>

[Test Hermes Agent compatibility]({{ '/guides/hermes-agent/' | relative_url }}) ·
[Test OpenClaw compatibility]({{ '/guides/openclaw/' | relative_url }}) ·
[Read all v0.1 limitations]({{ '/limitations/' | relative_url }})

## Documentation model

This field manual separates learning, procedures, concepts, and exact reference so
you can enter at the level your task requires. Start with the guided install, use the
how-to guides during operations, read the concepts when evaluating trust, and use
the reference pages for automation.
