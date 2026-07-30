---
title: Define a native portable agent service contract
description: Why Steward standardizes only bounded deployment, health, invocation, and result transport while leaving workflow and product semantics outside the runtime.
section: Architecture decision
---

# Define a native portable agent service contract

- Status: Accepted
- Date: 2026-07-29
- Rung: in-house

## Context

Steward already has portable OCI bundles, signed workload admission, finite
deployment authority, private service grants, tenant-signed tasks, at-most-once
Gateway dispatch, bounded lifecycle observation, retained terminal results, and
signed evidence. A non-Hermes agent could use the lower-level generic profile and
manual Gateway configuration, but there was no one worker interface a deployment
tool could target without learning an agent-specific API.

The missing interface must not turn Steward into a reasoning framework or hosted
workflow product. Team formation, decomposition, prompts, memory policy, semantic
schemas, evaluation, report assembly, and end-user interaction change rapidly and
belong above the enforcement plane. Putting them in the public runtime contract
would freeze product choices into every worker and make the weakest generic
semantics a shared trust boundary.

## Decision

Decision: use `in-house`: define one small
`steward.agent-service.v1` compatibility contract over Steward's existing
application, admission, deployment, and signed service-task primitives.

The `agent-service-v1@v1` runtime profile fixes:

- OCI entry command `serve`;
- unprivileged identity `65532:65532`;
- mutable state path `/state`;
- private service `agent-api` on port `8080`; and
- adapter contract `steward.agent-service.v1`.

The HTTP interface fixes only:

- `GET /v1/healthz`, which reports readiness, deployment identity, and immutable
  release digest;
- `POST /v1/invocations`, which accepts one strict request of at most 64 KiB and
  binds a caller-selected idempotency identity; and
- `GET /v1/invocations/{run_id}`, which reports the existing five-state lifecycle
  vocabulary and at most 1 MiB of terminal result data.

Gateway's `agent-service` preset maps the interface onto
`steward.task-lifecycle.v1`. Existing signed authority and evidence remain
authoritative. A completed response is an agent assertion and does not qualify
the worker's reasoning or result. Large outputs belong in an independently
governed object or artifact service; the terminal result should carry a bounded
reference and digest.

**Tradeoff:** worker authors gain one stable, portable target and deployment
tools gain one reusable integration seam. Steward owns a small protocol and
profile forever, but does not take ownership of application semantics or a new
always-on subsystem.

## Rejected alternatives

- **Add a workflow engine, agent team protocol, semantic layer, or report model.**
  These are product behavior rather than enforcement, and would expand the public
  compatibility surface far beyond the demonstrated runtime need.
- **Adopt a FaaS or Kubernetes serverless framework.** The current requirement is
  a portable invocation boundary, not a second scheduler, autoscaler, or cluster
  control plane. Existing finite deployments and task lifetimes are sufficient
  for the first integration.
- **Expose arbitrary worker paths and commands in the bundle.** That would weaken
  auditability and duplicate the lower-level generic profile. The named profile
  deliberately fixes the executable and service surface.
- **Add provider SDKs or a remote-agent credential broker.** Gateway already owns
  bounded credential and network mediation. Remote origins need a demonstrated
  trust, identity, and recovery model before they become a deployment target.
- **Treat the generic terminal schema as proof of correct work.** Different agent
  types need different qualification evidence. The neutral contract promises
  transport compatibility only.

## Consequences

- An independently built agent image can be published, admitted, deployed,
  invoked, observed, and forked through the same bounded Steward primitives as a
  qualified adapter.
- The composed site path can authorize `agent-api` without accepting arbitrary
  commands or ports.
- Worker implementations remain language- and provider-neutral and Steward's Go
  module remains dependency-free.
- Automatic scale-to-zero, remote hosted origins, streaming, cancellation after
  dispatch, and worker-specific qualification remain out of scope.
- Revisit the contract only when a deployed worker cannot express a required
  recovery or isolation guarantee through the fixed interface. Add application
  fields only when they are necessary for enforcement, not for product
  convenience.
