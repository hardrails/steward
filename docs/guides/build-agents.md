---
title: Build and run an agent
description: Define, validate, package, place, run, and fork a Hermes or OpenClaw agent application with CUE and optional OPA policy.
section: Guides
---

# Build and run an agent

Steward provides one application surface around Hermes and OpenClaw. The agent
runtime still owns its reasoning loop. Steward defines the immutable image,
skills, model route, resources, state, placement, and lifetime that operators can
inspect before granting authority.

The bundle is portable and contains no runtime authority. `agent apply` combines
it with a publisher-signed workload capsule and site-root-signed policy, asks an
Executor to admit it, and starts the admitted workload. Executor still checks the
exact image, tenant, resources, capabilities, generation, and node identity before
Docker changes.

## Check this machine

```console
stewardctl agent doctor
```

The report distinguishes `development` from `hardened`. On macOS, Docker Desktop
runs Linux containers in a VM but does not provide Steward's qualified
Docker/gVisor node boundary. Use macOS to author, validate, and test agents; place
sensitive production work on a Linux node that reports `hardened`.

## Create an agent project

```console
mkdir workspace-auditor
stewardctl agent init -runtime hermes -name workspace-auditor workspace-auditor
cd workspace-auditor
```

`Stewardfile.cue` is concrete CUE. Replace the placeholder image with the digest
of the adapter image you built and qualified. Image tags alone are rejected.

Validate and build it:

```console
stewardctl agent validate
stewardctl agent build
```

The bundle contains no API key, connector credential, reusable permit, runtime
reference, or receipt key. Configure model and service secrets through Gateway's
[external materialization boundary]({{ '/guides/secrets/' | relative_url }}).

JSON input is also accepted. The repository includes concrete
[Hermes](https://github.com/hardrails/steward/tree/main/examples/agents/hermes)
and [OpenClaw](https://github.com/hardrails/steward/tree/main/examples/agents/openclaw)
examples for systems that generate configuration programmatically.

## Apply organizational policy

OPA is optional. When supplied, it must return the boolean `true`; denial,
undefined output, malformed output, timeout, or oversized output stops the build.
The OPA bundle digest and query are recorded in the agent bundle.

```console
opa build --bundle ../examples/policy --output policy.tar.gz
stewardctl agent build \
  -policy-bundle policy.tar.gz \
  -policy-query data.steward.agent.allow
```

OPA can reduce what a definition may request. It cannot turn off gVisor, expand
Executor admission, mint credentials, or override Steward's native safety floors.
Carry the CUE and OPA binaries plus the policy bundle into an air-gapped site as
version-pinned, checksummed tools.

## Explain placement

Export or collect a bounded node inventory, then run:

```console
stewardctl agent plan \
  -bundle agent.bundle.json \
  -nodes ../examples/agents/nodes.json \
  -tenant default
```

Steward first rejects nodes that fail tenant, readiness, architecture, isolation,
label, taint, or resource requirements. It then scores eligible nodes using image
and snapshot locality, preferred labels, and current agent count. Node ID breaks
ties, so the same inputs produce the same decision. Every rejection and score
adjustment is returned.

## Run the agent on one node

Use `agent apply` after the Executor has its signed-admission policy and the
selected node is reachable through a loopback connection or SSH port forwarding:

```console
stewardctl agent apply \
  -bundle agent.bundle.json \
  -capsule hermes.capsule.dsse.json \
  -policy site.policy.dsse.json \
  -site-root-public-key site-root.pub \
  -site-root-key-id site-root-1 \
  -tenant default \
  -node-id node-1 \
  -token-file /etc/steward/executor.token
```

The command verifies every local artifact and derives the exact admission intent
before contacting Executor. It then admits and starts the workload and returns the
`runtime_ref` needed by lifecycle and task commands. Add `-nodes nodes.json` to
select a node using the same deterministic placement rules as `agent plan`, or
use `-plan-only` to inspect the derived intent without changing the node.

When `-lineage-id` is omitted, Steward derives a stable lineage from the bundle,
tenant, instance, and generation. Repeating the same apply after an ambiguous
network failure therefore presents the same identity to Executor. Supply the new
lineage from `agent fork` when starting a state fork.

Put the node URL and token path in a [CLI context]({{ '/guides/cli/' |
relative_url }}) to omit `-node-url` and `-token-file` from routine commands. The
signed capsule, policy, and site-root key remain explicit trust inputs. Follow the
[signed admission guide]({{ '/guides/signed-admission/' | relative_url }}) to
create and install them.

`agent apply` currently targets one selected node. It does not continuously
reconcile desired state or move the workload after node failure.

## Deploy through Steward Control

Use `agent deploy` when the Executor reaches a separately hosted Steward Control
service through outbound polling. The tenant command key must be authorized for
`admit` and `start` in site policy:

```console
stewardctl agent deploy \
  -bundle agent.bundle.json \
  -capsule hermes.capsule.dsse.json \
  -policy site.policy.dsse.json \
  -site-root-public-key site-root.pub \
  -site-root-key-id site-root-1 \
  -tenant default \
  -node-id node-1 \
  -command-key tenant-command.pem \
  -command-key-id tenant-command-1 \
  > agent.deployment.json
```

A [CLI context]({{ '/guides/cli/' | relative_url }}) supplies the Control URL,
private CA, operator token path, tenant, and node in routine use. `agent deploy`
keeps the tenant private key on the operator machine. It signs one short-lived,
exact admission command and, after the node reports successful admission, one
exact start command. Control retains and leases those opaque signed bytes; it
cannot manufacture another operation.

The command waits for protocol-4 reports and returns the Executor runtime
reference only after the node reports `running`. It fails if admission is denied,
the node reports an uncertain outcome, the command expires, or the wait times out.
Repeated admission and start attempts remain fenced and idempotent at Executor,
but this command is not yet a continuous controller: it does not replace a failed
node or keep a replica count converged after the command exits.

The deployment file contains the exact intent and authenticated admission result,
not credentials or private keys. It can authorize a real task without splitting
those fields into separate files:

```console
stewardctl task issue \
  -deployment agent.deployment.json \
  -trust service-trust.json \
  -request task-request.json \
  -operation-id hermes.run \
  -key tenant-task.pem \
  -key-id tenant-task-1 \
  -out task.bundle.json

stewardctl task submit \
  -bundle task.bundle.json \
  -gateway-url http://127.0.0.1:8081 \
  -token-file /etc/steward/gateway-control.token

stewardctl task wait \
  -bundle task.bundle.json \
  -gateway-url http://127.0.0.1:8081 \
  -token-file /etc/steward/gateway-control.token \
  -result-out task-result.json
```

`task issue` verifies that the task key appears in the admission projection and
binds one exact JSON request to the admitted tenant, instance, generation, model
service, operation policy, and short validity window. `task wait` stores the first
terminal result in a new owner-only file; it does not silently overwrite a prior
observation. See the [Hermes guide]({{ '/guides/hermes-agent/' | relative_url }})
or [OpenClaw guide]({{ '/guides/openclaw/' | relative_url }}) for their supported
request shapes and qualification limits.

## Fork persistent state

A snapshot is immutable metadata produced by a trusted storage provider. It binds
the state digest to one agent bundle and runtime. Create a fork plan with:

```console
stewardctl agent fork \
  -bundle agent.bundle.json \
  -snapshot snapshot.json \
  -ttl 2h
```

Steward generates a new instance ID and lineage ID. The default expiry action is
`destroy`. A fork never copies credentials, permits, runtime identity, receipt
keys, active network connections, or process memory. Storage cloning and the
subsequent signed admission remain explicit provider and Executor operations.

## What this surface does not do

It is not a visual workflow builder, prompt graph, model server, live-memory
checkpoint system, or general-purpose cluster scheduler. Those capabilities
would enlarge the trusted product without improving Steward's core guarantee:
an untrusted agent receives only explicit, constrained, and reviewable authority.
