---
title: Steward — locally authorized AI agent execution on Linux
description: Run untrusted agents with signed outcome releases, Docker/gVisor isolation, exact tenant-signed tasks, durable replay control, and offline-verifiable receipts.
home: true
---

<section class="hero">
  <p class="eyebrow">Open-source, operator-controlled agent infrastructure</p>
  <h1>A sandbox is only the beginning.</h1>
  <p class="hero-lede">A sandbox limits untrusted code, but does not establish who authorized it, which tenant it represents, or whether a sensitive request was replayed. Steward adds a self-hosted fleet controller, verifies local artifact and tenant policy, runs the agent with Docker + gVisor, can require an off-node tenant key to sign one exact service request, and records enforcement receipts that remain verifiable offline.</p>
  <div class="status-line"><span>Self-hosted fleet control</span><span>Signed local admission</span><span>Exact tenant-signed tasks</span><span>Durable replay control</span><span>Offline-verifiable receipts</span><span>Apache-2.0</span></div>
  <div class="install-box">
    <header><span>Interactive Linux install</span><button class="copy-button" type="button">Copy</button></header>
    <pre><code>curl --proto '=https' --tlsv1.2 -fsSL https://github.com/hardrails/steward/releases/latest/download/install-steward.sh | sudo /bin/bash -p</code></pre>
  </div>
  <p><a href="{{ '/getting-started/' | relative_url }}">Start with installation →</a></p>
</section>

## Three questions for every workload

<div class="grid">
  <article class="card"><span class="number">01 / AUTHORIZE</span><h3>Why may this run?</h3><p>Signed admission requires the publisher's workload limits, the operator's site policy, and the tenant's instance request to allow the same deployment. A stored instance generation rejects delayed commands for a replaced instance; a separate policy epoch rejects policy rollback.</p><a href="{{ '/guides/signed-admission/' | relative_url }}">Signed admission →</a></article>
  <article class="card"><span class="number">02 / CONSTRAIN</span><h3>What may it do?</h3><p>Executor accepts only immutable, resource-bounded images. Signed policy can grant approved model, private-service, exact connector, and HTTP(S) routes. A service-scoped tenant key can authorize one exact task without entering the node. Persistent Docker state is available only through an explicit dedicated-host compatibility mode because it has no portable hard quota.</p><a href="{{ '/concepts/security-model/' | relative_url }}">Security model →</a></article>
  <article class="card"><span class="number">03 / VERIFY</span><h3>What did the node enforce?</h3><p>Hash-linked, signed receipts record the accepted artifact, policy, instance generation, host mutation, exact task permit and request digest, dispatch outcome, and observed run ID. They never contain the raw prompt.</p><a href="{{ '/reference/offline-tools/' | relative_url }}">Verify and export evidence →</a></article>
</div>

## Choose your path

<div class="split">
  <div>
    <h3>I operate Linux infrastructure</h3>
    <p>Install a node, inspect its hardened services, connect it to your control plane, and learn how upgrades and rollback work.</p>
    <p><a href="{{ '/getting-started/' | relative_url }}">Install a node →</a></p>
  </div>
  <div>
    <h3>I operate a fleet</h3>
    <p>Install the bundled controller, enroll nodes once, deliver exact signed commands without placing signing keys in the controller, and promote one qualified Hermes release through a signed plan and evidence-bound batch gates.</p>
    <p><a href="{{ '/guides/control-plane/' | relative_url }}">Operate Steward Control →</a> · <a href="{{ '/guides/fleet-rollout/' | relative_url }}">Run a proof-carrying rollout →</a></p>
  </div>
</div>

## System boundary

<div class="architecture-strip">
  <div><small>Authorization inputs</small><strong>Workload profile + site policy + signed command</strong><p>Artifact limits, local trust, tenant and instance identity</p></div>
  <span class="arrow">→</span>
  <div><small>Management host</small><strong>Steward Control</strong><p>Enrollment, bounded inventory, exact command delivery; no signing keys or Docker</p></div>
  <span class="arrow">→</span>
  <div><small>Linux node</small><strong>Steward node services</strong><p>Admission, capability gateway, durable anti-replay state, signed receipts</p></div>
  <span class="arrow">→</span>
  <div><small>Sandbox</small><strong>Agent container image</strong><p>Docker + gVisor, fixed minimal privileges</p></div>
</div>

Model serving is managed separately. Steward's local gateway connects the agent to
an operator-selected, OpenAI-compatible route without configuring, mounting, or
injecting the upstream credential into the agent container. Named connectors apply
the same separation to exact authenticated API operations: Steward directly gives
the agent a logical operation and finite call budget, not the configured upstream
origin or secret. Gateway rejects the exact connector credential in response
headers and the decoded body stream. Configured upstreams remain trusted not to
transform that value, disclose private origin details, or return other application
secrets. For a configured service operation, a tenant key scoped by signed site
policy can authorize one exact request. Gateway records and spends that permit
before dispatch. The private key stays off-node. A successful replay returns the
recorded run ID without dispatching again; an ambiguous outcome fails closed.

## Agent adapters

Steward provides a qualified Hermes Agent adapter definition for exact upstream
commit `095b9eed3801c251796df93f48a8f2a527ff6e70`. The retained qualification applies to
`linux/amd64`; other platforms are not yet qualified. The source-built image runs as
`65532:65532`, uses the fixed Steward inference relay, and exposes only bounded
negotiation, health, run submission, and run-status operations on port `8766`.
Qualification runs the signed `steward.workspace-audit` skill under gVisor, changes
persisted workspace state, restarted the container, and required a fresh changed
result. It also required Hermes to discover and load the exact signed
`steward.connector-work` skill before demonstrating one authenticated effect, replay and
undeclared-operation denial, and a separate signed Gateway receipt chain. The
service-task path scopes a tenant key to `hermes-api`, signs the exact run request,
dispatches it through Gateway, and audits authorization, dispatch, and terminal records
offline. The run ID remains application output from the untrusted Hermes service.

A publisher-signed agent release can present that qualified work as an observable
outcome while binding the exact capsule, offline archive, deterministic canary,
qualification-evidence digest, and known limits. Steward then follows a fixed
choose/configure/preflight/activate/canary/prove/monitor contract. The release
describes the workload; local policy, tenant intent, live admission, and the
off-node task key still authorize it.

The official Hermes image remains inadmissible. Steward ships the pinned builder,
not a prebuilt Hermes OCI archive, because dependency and base-image notices are
incomplete. Operators build, inspect, and sign their exact output. OpenClaw remains
a layout contract and has not completed qualification.

Persistent Docker state requires the explicit dedicated single-tenant host setting
because the portable local volume driver cannot enforce hard byte or inode quotas.
Steward rejects images that require raw TCP/UDP, transparent interception, raw
secrets, host mounts, privileged mode, or undeclared ports.

<div class="callout warning">
  <strong>Do not erase the boundary</strong>
  Do not mount the Docker socket into an agent, add broad host mounts, or replace
  gVisor with the default runtime to make an image work. Those changes remove the
  isolation Steward is intended to enforce.
</div>

[Build and run the Hermes Agent adapter]({{ '/guides/hermes-agent/' | relative_url }}) ·
[Browse an offline agent catalog]({{ '/guides/agent-catalog/' | relative_url }}) ·
[Activate a qualified Hermes release]({{ '/guides/agent-activation/' | relative_url }}) ·
[Roll it out through canary and batch gates]({{ '/guides/fleet-rollout/' | relative_url }}) ·
[Review the OpenClaw adapter contract]({{ '/guides/openclaw/' | relative_url }}) ·
[Configure positive capabilities]({{ '/guides/positive-capabilities/' | relative_url }}) ·
[Broker authenticated API operations]({{ '/guides/connectors/' | relative_url }}) ·
[Configure egress]({{ '/guides/egress/' | relative_url }}) ·
[Bootstrap with Terraform]({{ '/guides/terraform/' | relative_url }}) ·
[Connect an MCP client]({{ '/guides/mcp/' | relative_url }}) ·
[Import images and export evidence]({{ '/reference/offline-tools/' | relative_url }}) ·
[Read all current limitations]({{ '/limitations/' | relative_url }})

## Market position

Many products now provide sandbox lifecycle, small virtual-machine isolation,
egress policy, credential injection, JSON audit logs, and self-hosted fleet
control. Steward focuses on
an operator-owned controller and authorization tied to the node's recorded
enforcement decision, including external signing keys, exact tenant-signed service
tasks, durable delivery and node-local replay control, and offline correlation at
disconnected sites. Among the products reviewed, none
documents this complete combination; that statement is limited to the linked public
documentation and snapshot date. Read the
[dated comparison]({{ '/product/market-analysis/' | relative_url }}) and its claim
limits.

## Documentation model

Start with the guided installation. Use the how-to guides for operations, the
concept pages to evaluate trust and design, and the reference pages for exact
automation contracts.
