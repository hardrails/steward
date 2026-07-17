---
title: Qualify a closed OpenClaw agent surface
description: Why Steward reuses one digest-pinned official OpenClaw image behind a small one-shot adapter instead of exposing the full Gateway.
section: Architecture decision
---

# Qualify a closed OpenClaw agent surface

- Status: Accepted
- Date: 2026-07-17
- Rung: exact upstream open-source release plus a small in-house adapter

## Context

OpenClaw supplies useful agent behavior, skills, and tools, but its full Gateway also
supplies channels, browser control, plugins, scheduled work, nodes, discovery, and
interactive administration. Qualifying all of those surfaces together would grant
more authority than Steward needs to prove that an agent can perform real work.
OpenClaw's own security model also says one Gateway is not an adversarial
multi-tenant boundary. Steward must keep tenant isolation outside the agent.

Current security research points in the same direction. NIST's agent identity and
authorization work calls for explicit identity, delegated authority, accountability,
and prompt-injection mitigation. Microsoft's analysis of privileged tool-enabled
agents identifies overprivileged tools, capability-intent mismatch, and ambient
authority as recurring risks. These publications do not evaluate Steward, but they
support deterministic enforcement around the model instead of relying on a prompt
to distinguish instructions from hostile data.

## Decision

Derive the Steward adapter from the exact official OpenClaw `2026.7.1` OCI image,
pinned by index digest and source revision. Add only a small adapter that:

- starts as UID/GID `65532:65532` with a read-only root filesystem;
- generates first-run configuration from Steward's fixed inference relay values;
- exposes health, negotiation, run submission, and run status on one port;
- permits only OpenClaw's `read` and `exec` tools inside the outer gVisor sandbox;
- allows one active run, bounds retained state, request and response bytes,
  connections, and execution time;
- returns a narrow result that excludes OpenClaw sessions, prompts, filesystem
  paths, and system-prompt reports; and
- publishes one exact built-in skill and refuses startup if its persisted bytes or
  permissions drift.

The build first pulls the exact upstream image, then runs Docker assembly with
network access disabled. It publishes an offline image archive and canonical
attestation through one atomic directory rename. Steward's existing bounded OCI
inspector independently verifies the archive manifest, config, platform, and tag.
The attestation records the separate manifest digest, config digest, and runtime
image ID because Docker engines do not expose `.Id` consistently across storage
backends.

The destructive qualification gate runs the exact image under gVisor with an
internal-only network, fixed resources, no capabilities, `no-new-privileges`, a
read-only root, and the non-root identity. A local OpenAI-compatible fixture makes
OpenClaw call the real custom skill. The gate verifies restart reuse, public-network
denial, body and concurrency limits, normalized results, and fail-closed skill
tamper detection. Its committed evidence contains only hashes and gate outcomes.

## Deliberate exclusions

This qualification does not expose or certify OpenClaw Gateway, Control UI,
channels, browser control, cron, plugins, remote nodes, discovery, arbitrary skills,
or nested Docker sandboxes. Each would require its own capability and acceptance
contract. The adapter's `exec` tool remains powerful inside its capsule; gVisor,
filesystem, network, resource, image, and signed-policy controls are the outer
boundary.

## Rejected alternatives

- **Rebuild the complete OpenClaw source tree.** Steward would own a large JavaScript
  dependency and release pipeline while still needing to qualify the resulting
  behavior. Exact official OCI reuse is smaller and preserves upstream identity.
- **Expose the full Gateway and disable risky features by documentation.** A feature
  that remains reachable is authority, even if operators are told not to use it.
- **Fork OpenClaw broadly.** A long-lived fork creates an unbounded security and
  compatibility obligation. The adapter stays outside upstream core behavior.
- **Trust Docker `.Id` as the config digest.** Containerd-backed Docker can report
  the OCI manifest digest instead. Steward records and verifies all identities
  explicitly.

## Consequences

Operators get a working, air-gap-transferable OpenClaw agent with a real custom
skill and a retained qualification record. They do not get OpenClaw's complete
consumer-product surface through Steward. A future upstream release or additional
tool requires a new pin, review, build, and qualification; a mutable tag cannot
inherit this result.

Steward does not independently reproduce the upstream image from source. Operators
therefore trust the authenticated official OCI release as a build input. Sites that
require source-reproducible OpenClaw images must add and qualify a separate build
recipe before admission.
