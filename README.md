# Steward

**Run untrusted AI agents without giving them unrestricted authority.**

[![CI](https://github.com/hardrails/steward/actions/workflows/ci.yml/badge.svg)](https://github.com/hardrails/steward/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hardrails/steward?display_name=tag)](https://github.com/hardrails/steward/releases/latest)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-f2532d)](https://hardrails.github.io/steward/)
[![License](https://img.shields.io/github/license/hardrails/steward)](LICENSE)

An agent can read a hostile calendar invitation, email, web page, document, tool
result, or memory entry and mistake embedded text for instructions. A container
limits where that agent runs. It does not decide whether the agent may send an
email, change an account, call an internal service, or spend a reusable API key.

Steward is the open-source agent application runtime and enforcement plane for
that missing boundary. It packages Hermes or OpenClaw agents behind one portable
contract, places them on customer-controlled infrastructure, mediates their
network capabilities, and records which exact authority produced each managed
external action.

Steward is designed for security, platform, and sovereign-infrastructure teams
that need local control, air-gapped operation, tenant isolation, and evidence
they can verify without a vendor service.

## What Steward does

| Problem | Steward's control |
| --- | --- |
| Untrusted agent images and configuration | Verifies signed workload and site-policy artifacts, sanitizes offline OCI imports, and admits only the pinned image and declared capabilities. |
| Multiple tenants on one Linux host | Gives every workload a separate gVisor sandbox, resource reservation, lifecycle identity, command fence, and capability network. Persistent Docker volumes remain a dedicated-host compatibility feature. |
| Prompt injection reaching a powerful tool | Keeps reusable connector credentials outside the workload. A protected action can require a tenant signature over the exact operation and request bytes. |
| Replayed or stale authority | Spends one-use permits before network dispatch and rejects old instance generations and command sequences. |
| Inference and service credentials | Gateway injects credentials only at the trusted outbound boundary. Agents receive a scoped route, not the upstream secret. |
| Disconnected and sovereign sites | Uses local keys, static Go binaries, local state, offline OCI archives, and customer-operated control services. No hosted service is required after transfer. |
| Incident review and audit | Writes signed, hash-linked Executor and Gateway receipts. Receipt exports can be verified offline and omit prompt, request, response, and secret plaintext. |

Steward cannot make model output trustworthy and does not claim to detect every
prompt injection. Its job is narrower and testable: even if the agent is
compromised, Steward can still deny, constrain, spend, and prove the authority
used for actions that pass through its enforcement boundaries.

## Install on Linux

Docker must already be installed. The guided installer supports systemd-based
DEB, RPM, and other Linux distributions on AMD64 and ARM64. It can optionally
install and register gVisor after asking for approval.

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/hardrails/steward/releases/latest/download/install-steward.sh | sudo /bin/bash -p
```

Keep `/bin/bash -p`. Privileged Bash mode prevents a root process from loading
user-controlled startup files and imported shell functions.

Piping a script to root trusts GitHub's TLS delivery and the release account. For
higher assurance, download and inspect the installer, verify the release manifest
through your own trust process, or follow the
[air-gapped installation guide](https://hardrails.github.io/steward/guides/air-gapped/).

After installation:

```console
sudo /usr/local/libexec/steward/node-doctor
sudo -H stewardctl context set local-node \
  -node-token-file /etc/steward/executor-observer-token
sudo -H stewardctl node whoami
```

Running `stewardctl` without arguments now shows the small set of common tasks.
Use `stewardctl help <command>` for a focused explanation and install shell
completion with:

```console
stewardctl completion install
```

## Install on macOS

The native macOS archive supports agent authoring, CUE/OPA policy checks, the
control plane, CLI, MCP interface, and Docker Desktop development. It supports
Intel and Apple Silicon. Docker Desktop is not represented as the qualified
Linux/gVisor production boundary.

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/hardrails/steward/releases/latest/download/install-macos.sh | /bin/bash -p
```

Run `stewardctl agent doctor` after installation. Use a hardened Linux node for
sensitive production workloads until the report identifies a hardened execution
profile.

Start with the [installation tutorial](https://hardrails.github.io/steward/getting-started/)
or use the [unattended and Terraform paths](https://hardrails.github.io/steward/guides/terraform/)
for repeatable infrastructure.

## Run an agent

Steward supports containerized agents that expose bounded service APIs. The
included adapters make Hermes Agent and OpenClaw usable behind Steward's fixed
security boundary.

- [Run Hermes Agent](https://hardrails.github.io/steward/guides/hermes-agent/)
- [Run OpenClaw](https://hardrails.github.io/steward/guides/openclaw/)
- [Understand workload admission](https://hardrails.github.io/steward/guides/signed-admission/)
- [Configure inference, services, connectors, and egress](https://hardrails.github.io/steward/guides/positive-capabilities/)

Inference remains a separate operator responsibility. Steward expects an
OpenAI-compatible endpoint or another explicitly configured service and mediates
the route and credential.

Start a portable agent project with:

```console
stewardctl agent create workspace-auditor -runtime hermes workspace-auditor
cd workspace-auditor
stewardctl agent build
```

Use the [agent application guide](https://hardrails.github.io/steward/guides/build-agents/)
to select Hermes or OpenClaw, apply offline OPA policy, explain fleet placement,
admit and start the workload directly or through Steward Control, and derive a
temporary or long-lived fork from persistent state.

With a CLI context configured as described in the guide, the common path is:

```console
stewardctl agent apply workspace-auditor
stewardctl task run workspace-auditor "Review this workspace and propose one issue"
```

A named CLI context supplies Control, tenant, Gateway, service-trust, and task-key
paths. Prompt mode creates a private run directory containing the exact request,
signed bundle, and verified result, and prints those paths without printing the
prompt or result. If the terminal or host fails after dispatch, resume the retained
bundle with `task submit` and `task wait`; do not create replacement authority that
might duplicate the work. The explicit request, operation, and output flags remain
available for automation and off-node signing.

## Authorize real work

A normal sandbox decides whether a process may open a network connection.
Steward can additionally decide whether this exact agent instance may perform
this exact connector operation with these exact request bytes.

The protected flow is:

```text
untrusted content -> agent proposes action -> exact signed permit
                                             |
                                             v
agent -> private relay -> Gateway verifies and spends permit -> external service
                                             |
                                             v
                                  signed receipt chain
```

The signing key stays outside the agent and can stay off the node. Gateway holds
the reusable upstream credential, verifies the tenant and instance binding,
checks the canonical operation and request digest, durably records the permit as
spent, and only then performs network resolution and dispatch.

Use the [Authorized Effects guide](https://hardrails.github.io/steward/guides/authorized-effects/)
for one-use and multi-party approvals. Use
[context-locked effects](https://hardrails.github.io/steward/guides/context-locked-effects/)
when a new managed connector response should invalidate an older approval.

This protection covers only calls routed through Steward. An unmanaged browser,
host credential, mounted socket, direct network path, or computer-use worker is a
separate authority boundary.

## Keep secrets out of agents

Steward does not implement another secret vault. An operator-selected secret
manager writes owner-only files for Gateway; Steward validates the non-secret
manifest, file ownership, permissions, identity, and expected rotation epoch.

```console
sudo stewardctl secret materialization prepare \
  -manifest /etc/steward/secrets/materialization.json

sudo stewardctl secret materialization check \
  -manifest /etc/steward/secrets/materialization.json
```

This provider-neutral handoff works with an existing vault, hardware-backed
service, configuration-management system, or manual offline process. Gateway
reads the value; the agent, control plane, React console, receipts, and MCP
adapter do not.

See [Manage Gateway secrets](https://hardrails.github.io/steward/guides/secrets/).

## Operate a fleet

`steward-control` is a customer-operated control plane for tenant-scoped
operators, one-time node enrollment, outbound node polling, signed command
delivery, durable desired deployments, deterministic placement of exact delegated
instances, inventory, attention findings, and separately witnessed evidence.

Control uses a purpose-separated online key only within a short-lived
tenant-signed delegation. Tenant keys remain outside Control, and Executor verifies
both signatures and the exact delegated scope before changing Docker. The
controller schedules only onto recently observed nodes, atomically reserves the
CPU, memory, process, tenant, and workload-slot limits Executor enforces, and
reports a stable blocked reason when it cannot proceed. A site administrator can
also set one durable CPU, memory, process, and workload ceiling for a tenant across
the entire fleet, so adding nodes does not multiply that tenant's allowance.
Quota pressure appears in the same attention feed and React console as failed
commands and stale evidence. Tenant-signed soft label
preferences and one topology spread key influence placement without widening
hard admission authority, and every decision retains its score inputs. It can
replace a lease-managed stateless instance after the signed expiry fence. For
planned work, site administrators can run a restart-safe node drain that cordons
first and moves stateless instances within each deployment's maximum-unavailable
budget. During an incident, an operator can freeze new command delivery for one
tenant or the whole site without hiding node heartbeats, reports, or evidence.
The freeze is deliberately a delivery fence: already accepted work keeps running
until its existing authority or lease ends. Stateful migration, surge-based
zero-downtime rollout, and automatic rollback remain explicit gaps.

Its embedded React console is available at `/console/`. The console keeps the
operator bearer only in tab memory, loads no remote assets, and never receives
private signing keys or secret plaintext. It shows each observed agent runtime's
last successful workload status separately from its latest signed operation.
Mutating Executor commands are signed outside the browser; the console reviews
and transfers the unchanged envelope.

`steward-mcp` exposes bounded node, control, and pre-signed task operations to a
local Model Context Protocol client over standard input and output. MCP
credentials are privileged and must never be given to the untrusted agent whose
authority Steward is meant to constrain.

- [Operate Steward Control](https://hardrails.github.io/steward/guides/control-plane/)
- [Use the operator console](https://hardrails.github.io/steward/guides/operator-console/)
- [Configure MCP](https://hardrails.github.io/steward/guides/mcp/)
- [Verify and export evidence](https://hardrails.github.io/steward/reference/offline-tools/)

## Security defaults

Every admitted agent uses:

- the pinned local OCI config digest;
- gVisor's `runsc` runtime;
- fixed unprivileged UID and GID `65532:65532`;
- no Linux capabilities and `no-new-privileges`;
- a read-only root filesystem and bounded temporary filesystems;
- explicit memory, swap, CPU, PID, and workload-count limits;
- no host mounts, devices, published ports, Docker socket, or arbitrary
  environment variables;
- `network=none` unless signed policy grants a capability route; and
- an isolated capability network with no host-gateway access when networking is
  required.

These controls reduce authority. A shared host is not equivalent to separate
hardware. Host root, Docker, gVisor, the Linux kernel, the configured inference
service, Gateway, and operator key custody remain trusted. Hardware side channels
and kernel compromise remain residual risks.

Read the [security model](https://hardrails.github.io/steward/concepts/security-model/)
and [known limitations](https://hardrails.github.io/steward/limitations/) before
production deployment. Report vulnerabilities through [SECURITY.md](SECURITY.md).

## Components

```text
offline tenant/site keys ---- signed policy, commands, permits ----+
                                                                   |
customer control host: steward-control + React console             |
                         ^                                         |
                         | node-initiated authenticated polling     |
                         v                                         v
Linux node: steward-executor -> Docker + gVisor agent -> steward-relay
                 |                                      |
                 +-> signed lifecycle receipts          +-> steward-gateway
                                                            | inference
                                                            | services
                                                            + connectors
```

- `steward-executor` is the only long-running Steward service with Docker
  authority. It verifies admission and owns workload lifecycle.
- `steward-gateway` mediates inference, service, connector, and HTTP(S) egress
  without giving reusable upstream credentials to workloads.
- `steward-relay` is a fixed-destination helper inside each capability network.
- `steward-control` provides the optional self-hosted fleet plane and console.
- `stewardctl` is the operator CLI and offline verification tool.
- `steward-mcp` is the bounded local MCP adapter.
- `steward` remains the compatibility supervisor for the generic public uplink.
  New Steward Control deployments use Executor's signed command protocol.

## Zero private dependencies

Steward is not a reasoning framework, prompt graph, model server, hosted SaaS
control plane, general container orchestrator, secret manager, or
endpoint-detection product. It is the portable application and enforcement layer
between an untrusted agent runtime and the authority to act.

The repository has zero build-time or runtime dependency on a private package,
API, account, or tool. The Go module intentionally uses only the standard
library:

```console
$ go list -m all
github.com/hardrails/steward
```

Public contracts live under [`openapi/`](openapi/). Architecture decisions, the
[market analysis](https://hardrails.github.io/steward/product/market-analysis/),
and the [product roadmap](https://hardrails.github.io/steward/product/roadmap/)
live in the documentation site.

## License

Steward is available under the [Apache License 2.0](LICENSE).
