---
title: Receive events from running agents
description: Use Steward's durable instance-to-controller event channel for bounded status, findings, and progress without granting command authority.
section: How-to guide
---

# Receive events from running agents

A long-running agent sometimes needs to report a finding or status change when no
task request is waiting. Controller events provide that path. They are small,
structured messages from an admitted instance to Steward Control.

An event is not a command and carries no authority back into the node. Its tenant,
node, instance, lineage, generation, runtime, and policy identity come from the
active Gateway grant; the workload cannot choose those fields.

## Delivery contract

- Relay accepts events only on the fixed local event socket.
- Gateway requires an active grant with the controller-event capability, bounds
  and validates the message, persists it before acknowledgement, and queues it for
  the node uplink.
- Executor publishes queued events through its authenticated outbound Control
  connection. Control retains them under the derived tenant and node identity.
- Delivery is **at least once**. A retry can reproduce an event, so consumers must
  deduplicate by event ID or the workload-supplied idempotency key.
- A full local queue returns backpressure to the workload. Events are never
  silently converted into best-effort log lines.

The payload contains a kind, stable code, severity, short summary, optional bounded
attributes, and an idempotency key. It is suitable for progress, findings, and
operator attention—not full prompts, page bodies, binary artifacts, or secrets.

## Read events

The React control room has **Fleet tasks** and **Agent signals** views. The task
view groups correlated progress; the signal view preserves each retained event.
From a trusted terminal:

```console
stewardctl control event list \
  -tenant-id research \
  -limit 100 \
  -token-file /etc/steward/control-operator.token
```

Pass the returned `next_after` value to `-after` for the next page. The HTTP API
and MCP server expose the same tenant-scoped retained data; see
[APIs and schemas]({{ '/reference/api/' | relative_url }}) and
[MCP operations]({{ '/guides/mcp/' | relative_url }}).

## Read task progress

Set `task_id` on related status and finding events to make them appear as one
fleet task projection:

```console
stewardctl control task list \
  -tenant-id research \
  -limit 100 \
  -token-file /etc/steward/control-operator.token
```

Steward groups events by tenant, task ID, instance ID, and instance generation.
This prevents a reused task ID from merging two different workload lineages.
Use these stable event codes when they match the actual lifecycle:

| Code | Projected state |
| --- | --- |
| `task_started`, `task_progress` | `agent_reported_running` |
| `task_completed` | `agent_reported_completed` |
| `task_failed` | `agent_reported_failed` |
| `task_cancelled` | `agent_reported_cancelled` |
| Any other code with `task_id` | `agent_reported_activity` |

The first reported terminal state remains sticky. If later events claim a
different terminal state, run ID, node, or runtime, Steward adds a conflict
condition instead of silently replacing history. The projection retains only
bounded metadata. It survives eviction of its source events, then ages out under
its own oldest-first limits. It is not a task queue, cancellation API, artifact
store, or proof that the agent performed the reported work correctly.

## Trust and retention

Event content is untrusted agent output. Display it as data, do not execute markup
or commands from it, and do not use it as authorization. The control room escapes
rendered content and never turns an event into a mutation.

Control retains the newest 1,024 events per tenant and 4,096 across the site,
evicting the oldest records in the same durable transaction that accepts newer
ones. Task projections use separate limits of 1,024 per tenant and 4,096 across
the site, so raw-event eviction does not roll completed work back to an earlier
state. Gateway's undelivered outbox is separately capped at 16 events per grant,
32 per tenant, and 64 per node. If Control is unavailable, the node retries
without discarding an acknowledged event; when the outbox is full, new events fail
visibly until delivery frees capacity. Include enough source or task context in
the bounded attributes to investigate, but keep large evidence in a separately
governed artifact store.

The [web research profile]({{ '/guides/research-agents/' | relative_url }}) uses
this channel to report source-linked findings after one signed top-level task.
