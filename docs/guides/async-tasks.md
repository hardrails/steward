---
title: Run tasks through Steward Control
description: Queue signed Hermes work through Steward Control, follow its durable status, retrieve bounded results, cancel safely, and understand the authority and privacy boundaries.
section: Guide
---

# Run tasks through Steward Control

Use asynchronous tasks when you operate Steward from a different machine than
the agent node, or when your client should be able to disconnect after submitting
work. Control retains the task, the node's Executor collects it over its existing
outbound connection, and Gateway verifies the tenant signature before contacting
Hermes.

This is a task courier, not a source of authority. Control cannot invent a task or
weaken a deployment's permissions. It routes the exact request and signed permit
that you created; Gateway remains the component that decides whether the request
may run.

## Before you begin

You need:

- a running, task-ready Hermes deployment;
- a protocol-4 node connected to Control, with its host-local Gateway control
  client configured;
- a tenant operator token; and
- the service-trust file and task-authority key used by that deployment.

The normal setup saves those paths in a CLI context. Check the selected context:

```console
stewardctl context show
```

If you intentionally avoid contexts, pass the equivalent Control, tenant, trust,
and task-key flags shown by `stewardctl help`. Contexts improve command ergonomics;
they do not move private keys into Control.

## Queue a Hermes prompt

Name the durable deployment and provide one prompt:

```console
stewardctl task enqueue researcher "Compare the primary sources and cite every conclusion."
```

Steward waits for a task-ready instance, creates an owner-only run directory,
builds the exact Hermes request, signs a short-lived task permit locally, and
queues both with Control. The JSON response contains the task ID and paths to the
private request and bundle. It does not print the prompt or permit.

The default permit window is five minutes and the hard maximum is 15 minutes.
This limit reduces the value of a stolen permit. It also means a task that cannot
reach its assigned node before expiry will become `deadline_exceeded`; durable
does not mean authority lives forever.

For an existing expert-mode bundle, use:

```console
stewardctl task enqueue -bundle ./task.bundle.json
```

An exact retry is idempotent. Reusing the same tenant and task ID with different
permit or request bytes returns a conflict.

## Follow progress

List recent submitted tasks:

```console
stewardctl task list
```

Inspect one task:

```console
stewardctl task get TASK_ID
```

The main states are:

| State | Meaning |
| --- | --- |
| `queued` | Control retained the request, but no node lease is active. |
| `leased` | The assigned node holds a short delivery lease. A crash can safely cause redelivery. |
| `dispatched` | Gateway accepted the exact signed request and returned a run identity. |
| `running` | Gateway observed a nonterminal Hermes status. |
| `completed`, `failed`, `cancelled` | The authenticated node reported the terminal status returned by its host-local Gateway. |
| `cancel_requested` | Work may already be running; Steward has recorded intent but cannot claim it stopped. |
| `deadline_exceeded` | The signed authority expired. `outcome_may_continue` tells you if dispatch may already have occurred. |
| `outcome_unknown` | Steward cannot prove a final outcome. Do not blindly issue different authority for the same external effect. |

The older `/tasks` projection is different: it summarizes untrusted events sent
by an agent. `/task-requests` is the canonical lifecycle for work submitted
through Control. Keeping these models separate prevents agent telemetry from
becoming command authority.

## Retrieve a result

When `result_available` is true, write the exact terminal observation to a new
owner-only file:

```console
stewardctl task result TASK_ID -out ./result.json
```

Ordinary list and get operations return only the result digest and byte count.
The explicit result operation can return sensitive agent-authored content, so its
HTTP response uses `Cache-Control: no-store` and the CLI never prints the body.
Steward retains individual results up to 512 KiB, with separate 16 MiB per-tenant
and 64 MiB site-wide result ceilings. It retains task request and permit courier
material under separate 16 MiB per-tenant and 64 MiB site-wide ceilings. When a
result cannot fit, metadata remains available but the result endpoint returns
`task_result_unavailable`. When new courier material cannot fit after terminal
record eviction, submission fails closed with `capacity_exceeded`. Use a
separately governed artifact service for large files.

Treat agent output as untrusted data. A matching digest proves that the downloaded
bytes match the digest and byte count reported through the authenticated node
channel. Control does not receive or independently verify signed Gateway evidence
for this result. A compromised node can forge results for workloads on that node,
and an honest result does not prove that the agent's claims are correct or that
retrieved web content was safe.

## Cancel without making false promises

```console
stewardctl task cancel TASK_ID
```

A queued task is cancelled before dispatch. The current generic Gateway lifecycle
has no cross-runtime remote-cancel operation after Hermes accepts a run. In that
case Steward records `cancel_requested` and `outcome_may_continue=true`, then
continues observing for a terminal state. This distinction prevents a successful
HTTP response from being mistaken for proof that external work stopped.

## What survives a restart

Control writes submissions, lease generations, task identities, status, and
bounded results to its existing hash-chained durable store. Executor delivery is
at-least-once: a lost acknowledgement can cause the same task to be delivered
again. Gateway's one-use permit ledger turns an exact retry into replay of the
recorded dispatch identity instead of a second external effect.

The Control state directory and its backups contain exact request bytes,
replayable-until-expiry signed permits, and retained result bytes. Protect them as
sensitive authority-bearing data. These values are deliberately absent from task
list responses, metrics, logs, the operator console's ordinary inventory, and
support bundles.

## Trust boundary

Control structurally inspects a permit only to enforce bounds and route it to the
named tenant and node. Those fields are attacker-controlled until Gateway verifies
the signature against the task-authority key bound during admission. Executor
calls only its host-local Gateway control socket; it does not dispatch directly
to the agent. Control treats an authenticated node report as lifecycle input, not
as proof of correct work. A compromised node can forge lifecycle and result
reports for that node, but cannot use this channel to bypass Gateway on an
uncompromised node. A compromised Control can withhold, delay, or replay exact
retained bytes, but it cannot create a valid new tenant signature or change the
request without Gateway rejecting it.

This boundary works in `strict-sovereign` mode because Control transports existing
tenant authority rather than holding a controller signing key. Availability still
depends on Control, and compromise can expose retained prompts and results; the
mode limits execution authority, not confidentiality or denial of service.

For a fixed number of recurring runs, use
[finite scheduled tasks]({{ '/guides/scheduled-tasks/' | relative_url }}). For a
running agent that must pause for a bounded operator decision, use
[agent interactions]({{ '/guides/agent-interactions/' | relative_url }}).
