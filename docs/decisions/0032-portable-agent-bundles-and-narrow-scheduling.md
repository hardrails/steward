# Portable agent bundles and narrow scheduling

## Status

Accepted. The one-shot placement decision remains current; the fleet mutation
decision is superseded by [0034]({{ '/decisions/0034-durable-delegated-reconciliation/' | relative_url }}).

## Decision

Steward defines a small, versioned agent application bundle above its existing
Hermes and OpenClaw adapters. The bundle describes an immutable image, adapter
contract, logical model route, skills, MCP endpoints, resources, placement,
state, and lifetime. It never contains credentials, reusable permits, runtime
references, receipt keys, or arbitrary host commands.

Steward also owns a deterministic filter-and-score scheduler for this bundle.
It produces an explainable placement decision. `stewardctl agent apply` may turn
that decision into a node-local mutation only by translating the bundle into an
exact intent and using Executor's existing signed-admission and lifecycle APIs.
The authenticated capsule, site policy, Executor role, and live capacity checks
remain authoritative; a bundle or scheduler decision cannot widen admission.

Decision: use `built-in`: the existing Executor API and bounded node client own the
mutation path. Rejected: `in-house` agent deployment endpoints or a second runtime
tracker because either would duplicate admission, idempotency, and lifecycle
checks at a weaker boundary. Revisit only if an external scheduler adapter cannot
express the same signed intent without bypassing Executor.

The original fleet deployment also used `built-in`: Steward's existing tenant-signed command
protocol, durable Control courier, and protocol-4 admission projection. The
operator signs `admit` and `start` locally; Control never receives private command
authority. Rejected: storing a tenant command private key in Control. A later
design added automatic operation through an exact tenant-signed delegation and a
separate online controller key; see decision 0034.

Decision: use `in-house`: a narrow agent-aware scheduler. Its tenant,
isolation, lineage, signed-authority, and evidence semantics are Steward's core
differentiation. Rejected: `open-source` Kubernetes or Nomad as mandatory
substrates because Steward must work on one ordinary Linux server and support a
macOS development path without requiring another cluster. Revisit when users
need preemption, autoscaling, or high-availability scheduler consensus.

CUE and OPA remain replaceable operator-side tools. CUE compiles a human-facing
definition to concrete JSON. OPA evaluates organizational policy and may only
deny; it cannot weaken Steward's native safety floors. Their output is bounded
and strictly decoded at the same trust boundary as hand-written JSON.

Decision: use `open-source`: CUE and OPA as separately installed, explicitly
invoked tools. Rejected: `in-house` configuration and policy languages because
those are mature commodity capabilities and would enlarge Steward's trusted
code. Revisit if the command-line contracts cannot be pinned and mirrored for
air-gapped operation.

## Consequences

- The Go module retains no third-party dependencies.
- An operator can build, inspect, schedule, and fork an agent artifact offline,
  then admit and start it on one selected node without dropping to raw APIs.
- Kubernetes, Nomad, and other substrates can be adapters rather than required
  control planes.
- Scheduling is initially single-decision and intentionally lacks preemption,
  autoscaling, and consensus.
- A fork clones declared persistent state, not live memory or authority.
