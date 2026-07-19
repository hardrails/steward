# Portable agent bundles and narrow scheduling

## Status

Accepted.

## Decision

Steward defines a small, versioned agent application bundle above its existing
Hermes and OpenClaw adapters. The bundle describes an immutable image, adapter
contract, logical model route, skills, MCP endpoints, resources, placement,
state, and lifetime. It never contains credentials, reusable permits, runtime
references, receipt keys, or arbitrary host commands.

Steward also owns a deterministic filter-and-score scheduler for this bundle.
It produces an explainable placement decision. Existing tenant-signed commands
and Executor admission remain the authority that may actually create or start a
workload; a scheduler decision cannot widen admission.

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
- An operator can build, inspect, schedule, and fork an agent artifact offline.
- Kubernetes, Nomad, and other substrates can be adapters rather than required
  control planes.
- Scheduling is initially single-decision and intentionally lacks preemption,
  autoscaling, and consensus.
- A fork clones declared persistent state, not live memory or authority.
