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

## Keep desired state through Steward Control

Use a durable deployment when Executor nodes poll a separately hosted Steward
Control service and the agent should keep converging after the operator disconnects.
Copy `/var/lib/steward-control/controller.public.pem` from the management host to
the trusted tenant signing station. Do not copy `controller.private.pem`.

Create the exact instance list and admission template described in the
[offline tools reference]({{ '/reference/offline-tools/' | relative_url }}), then
issue a short-lived delegation with all five lifecycle operations:

```console
stewardctl executor-command delegation issue \
  -delegation-id auditor-deployment \
  -tenant-id default \
  -controller-public-key controller.public.pem \
  -controller-key-id controller-default \
  -operations admit,renew,start,stop,destroy \
  -node-ids node-1,node-2 \
  -instances instances.json \
  -admission-template admission-template.json \
  -key tenant-command.pem \
  -key-id tenant-command-1 \
  -out delegation.dsse.json
```

The tenant command key must be authorized by the site policy for every delegated
operation. The delegation expires within 24 hours and names exact nodes, instances,
lineages, generations, resources, capabilities, routes, and connectors. Control
cannot widen those fields.

With a CLI context supplying Control, the operator token, private CA, and tenant,
apply and inspect the deployment:

```console
stewardctl agent deployment apply auditor \
  -bundle agent.bundle.json \
  -capsule hermes.capsule.dsse.json \
  -delegation delegation.dsse.json

stewardctl agent deployment status auditor
stewardctl agent deployment list
```

The apply command checks the bundle, capsule envelope, delegation lifetime, tenant,
capsule digest, and lifecycle scope locally. It fetches the current revision and
infers a safe deployment generation. Control then selects an active allowed node
that advertises delegated-command support, has reported within the configured
freshness threshold, satisfies the capsule architecture and signed placement
constraints, and has reserved host and tenant capacity. It then drives `admit`,
a bounded workload-lease renewal, and `start`. It renews the lease while the agent should remain running. Removing
desired state similarly needs only the name:

```console
stewardctl agent deployment remove auditor
```

Removal is asynchronous. Watch status until the deployment is `removed`. A failed
or uncertain Executor outcome becomes `degraded` and is not silently retried.
`last_error` also reports retryable controller conditions using stable values:
`no_eligible_node`, `assigned_node_unavailable`, `awaiting_lease_expiry`,
`stateful_replacement_unsupported`, `replacement_generation_exhausted`,
`scheduling_observation_unavailable`, `placement_constraints_unsatisfied`,
`workload_limit_exceeded`, `node_capacity_exhausted`,
`tenant_capacity_exhausted`, `delegation_expired`,
`controller_key_mismatch`, or
`invalid_deployment_authority`. The controller
rechecks these conditions and clears the value when it can enqueue the next command.
`deployment_command_record_missing` is different: it means the durable command
result needed to prove the next state is unavailable. Steward marks the deployment
`degraded` and requires operator recovery instead of guessing or retrying the effect.

A stale node is not a fence by itself. For a lease-managed stateless deployment,
Executor persists the latest signed expiry locally and stops the agent, trusted
relay, and Gateway authority when it expires. Control records the expiry before
delivery, waits through the command clock-skew allowance, advances the instance
generation within the tenant-signed range, and then selects an eligible node. A
lost renewal report therefore delays replacement; it cannot make replacement
earlier. Before that bound, status reports `awaiting_lease_expiry`.

Executor publishes the CPU, memory, process, and workload ceilings it enforces
locally. Control reserves those resources in the durable transaction that queues
`admit`; concurrent reconciliation cannot overcommit the retained budget.
Executor still checks real Docker usage before creation. Failed and
`outcome_unknown` effects keep their reservation because the workload may still
exist. A successful destroy or safely fenced replacement releases it.

## Take a node out of placement

Before planned host work, stop new controller placements while existing agents
continue to run:

```console
stewardctl control node drain -reason "kernel maintenance" node-1
```

Control returns a generated `request_id`. Keep it if you may need to cancel the
operation. The drain durably cordons the node, then moves only stateless desired
deployment instances that have an eligible destination and budget room. A
replacement is admitted only after the old runtime reports successful destroy,
and its instance generation advances so delayed commands cannot affect it.

Set the budget when applying a deployment. `1` is the default; `0` pauses
voluntary movement without changing desired state:

```console
stewardctl agent deployment apply auditor -tenant acme -max-unavailable 1
```

Canceling stops new moves. An instance already marked for movement continues
because a stop or destroy result may already be in flight:

```console
stewardctl control node cancel-drain \
  -request-id drain-REPLACE_WITH_RETURNED_ID \
  node-1
```

A completed, cancelled, or failed drain leaves the node cordoned. A failed drain
identifies the instance whose lifecycle command failed; Steward does not retry
that uncertain effect or claim the workload stopped. Inspect the degraded
deployment and apply fresh generation authority before attempting another drain.
After the host is healthy, restore placement explicitly with
`stewardctl control node uncordon node-1`. The separate node-local maintenance
workflow remains the gate for package activation and unmanaged exact-runtime
cleanup; see [Upgrade safely](upgrades.md).

For suspected compromise, use quarantine instead:

```console
stewardctl control node quarantine -reason "suspected credential theft" node-1
```

Quarantine stops new command leases and causes lease-managed stateless
deployments to recover only after their conservative lease fence. It does not
erase evidence, revoke credentials, or claim that a stateful workload can be
migrated safely. Inspect and rotate credentials before the distinct
`unquarantine` action. Revoke the node if its identity must never return.

To narrow placement, add this optional object to `admission-template.json`:

```json
{
  "placement": {
    "required_isolation": "gvisor",
    "required_labels": [
      {"key": "region", "value": "west"}
    ],
	"preferred_labels": [
	  {"key": "disk", "value": "fast"}
	],
	"spread_by": "zone",
    "tolerations": ["dedicated"]
  }
}
```

Required labels remain hard eligibility constraints. Preferred labels are soft:
more exact matches rank ahead of lower load. `spread_by` first prefers nodes
that report the label, then the topology value with the fewest instances from
this deployment. The stored instance includes the matched keys, spread value,
same-domain count, node load, and decision time.

The arrays must be sorted and contain no duplicates. Keys, values, and
tolerations may contain letters, digits, `.`, `_`, `:`, `/`, and `-`, up to 128
bytes each. Every node taint requires an exact toleration. These fields are part
of the tenant-signed delegation, so Control cannot silently move the workload
outside them.

Delegations without `renew` retain the older non-relocatable behavior and report
`assigned_node_unavailable`. Stateful instances are also not moved automatically:
local Docker state is not a portable, quota-enforced snapshot. They report
`stateful_replacement_unsupported`. See
[Known limitations]({{ '/limitations/' | relative_url }}) for the remaining trust
and availability constraints.

Keep lifecycle authority valid for any operation Control may still need. After a
delegation expires, Executor correctly refuses new commands under it. To roll an
agent forward or remove it later, sign and apply a higher deployment and instance
generation with a fresh delegation before requesting cleanup. Steward does not
silently extend or reinterpret an expired tenant signature.

A new generation must retain every instance that has not reached `removed` and
advance that instance's generation without changing its lineage. Omitting a live,
in-progress, or failed instance is rejected because forgetting it would leave its
workload unmanaged. An already removed instance may be omitted from the next
generation.

Wait for a ready single-instance deployment and export its exact non-secret intent
and authenticated admission result when another tool needs a portable handoff:

```console
stewardctl agent deployment wait auditor -out agent.deployment.json
```

For a deployment with multiple running instances, add `-instance-id`. A deployment
created before task-ready state was introduced must be rolled forward to a new
generation; Steward will not reconstruct a missing admission result from guesses.

For routine work, configure the [CLI task defaults]({{ '/guides/cli/' |
relative_url }}) once and run the entire authorized task lifecycle in one command:

```console
stewardctl task run auditor \
  -request task-request.json \
  -operation-id hermes.run \
  -bundle-out task.bundle.json \
  -result-out task-result.json
```

This waits for the deployment, checks the exact admitted service and task key,
persists the signed bundle before dispatch, submits through the node-local Gateway,
and saves verified terminal bytes. The bundle remains the recovery handle after a
timeout or interrupted terminal. Resume it instead of minting replacement
authority.

## Run one synchronous deployment through Control

Use `agent deploy` when the Executor reaches a separately hosted Steward Control
service through outbound polling and the operator needs one synchronous
admit-and-start result for the task tooling. The tenant command key must be
authorized for `admit` and `start` in site policy:

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
but this one-shot command does not create durable desired state. Use `agent deployment
apply` for controller reconciliation.

The deployment file contains the exact intent and authenticated admission result,
not credentials or private keys. The separate commands below remain the expert and
off-node signing path:

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
  -gateway-url http://127.0.0.1:8091 \
  -token-file /etc/steward/gateway-service-token

stewardctl task wait \
  -bundle task.bundle.json \
  -gateway-url http://127.0.0.1:8091 \
  -token-file /etc/steward/gateway-service-token \
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
