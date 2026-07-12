---
title: "Decision 0004: Use host tools for release and relay activation"
description: Use Docker content identity, systemd, root-owned symbolic links, and an OS lock for node release activation.
section: Architecture decision
---

# Decision 0004: Use host tools for release and relay activation

## Decision

Use Docker builds and immutable image IDs, systemd service control, a `flock` file
lock, SHA-256 manifests, root-owned files, and atomic symbolic-link replacement.
Steward owns only the small transaction that coordinates these host mechanisms.

Each release declares its durable-state reader and writer ranges. A transition stops
active Steward services, proves that managed containers and capability networks are
absent, checks retained grants, journal state, and file versions, builds or verifies
the target relay binding, preflights the target, and then switches the active-release
symlink and relay binding. A failed start restores the prior links only when the old
release can still read the observed state.

## Tradeoff

This keeps installation air-gapped and adds no new package manager, container
registry, upgrade controller, or language dependency. The transaction is
Linux-specific and must handle partial host failures explicitly. It changes the two
links one after the other because one atomic filesystem operation cannot cover both
locations. The recovery path therefore validates and repairs both links while
holding the same exclusive lock.

## Rejected options

- A container registry alone does not coordinate systemd and durable-state
  activation or bind a host-built relay to the installed binary. An on-site
  registry can still be one input to a disconnected deployment.
- Kubernetes rollout machinery would add a cluster control plane to a single-host
  Docker deployment and would not manage the existing systemd boundary.
- A third-party updater would own release selection without understanding Steward's
  anti-replay, evidence, Gateway, and relay compatibility constraints.

Revisit this choice if Steward supports a non-systemd host or a multi-node substrate
whose rollout mechanism can preserve the same gates.
