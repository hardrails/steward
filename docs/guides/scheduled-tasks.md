---
title: Run finite scheduled agent tasks
description: Sign one bounded Hermes task schedule, let Steward Control materialize only its authorized runs, and understand missed, overlapping, cancelled, and restarted work.
section: How-to guide
---

# Run finite scheduled agent tasks

Use a Steward schedule when the same agent request should run at known times—for
example, a daily source review or a finite set of repository checks.

A schedule is not an unbounded cron entry. The tenant signs one exact request and
the complete run envelope: deployment, workload generation, start time, interval,
run count, dispatch window, maximum concurrency, overlap behavior, and optional
Workroom session. Steward Control can materialize only those run numbers. It
cannot change the request or extend the schedule.

## Before you begin

You need a task-ready Hermes deployment and a CLI context containing the Control
connection, tenant, service-trust inventory, and task-authority key paths. The
same context used by `stewardctl task enqueue` is sufficient.

Check the current context first:

```console
stewardctl context show
```

## Schedule a finite run

Run one task ten seconds from now:

```console
stewardctl task schedule researcher \
  "Summarize new primary-source findings and retain the source URLs"
```

Run the same request once an hour for the next 24 runs:

```console
stewardctl task schedule researcher \
  -every 1h \
  -runs 24 \
  "Summarize new primary-source findings and retain the source URLs"
```

The CLI resolves the live deployment, derives its exact Hermes service operation,
builds the request, and signs the schedule locally. It does not send the private
key to Control. The default first run is ten seconds in the future; use
`-start-in 30m` to change that delay.

To place each generated task in an existing Workroom session:

```console
stewardctl task schedule researcher \
  -every 24h \
  -runs 30 \
  -project market-intelligence \
  -session daily-review \
  "Review the approved sources and report material changes"
```

Project and session must be supplied together. They organize the run; they do not
widen its authority.

## Inspect and cancel

```console
stewardctl task schedule list
stewardctl task schedule show SCHEDULE_ID
stewardctl task schedule cancel SCHEDULE_ID
```

The React console's **Schedules** view shows the same bounded metadata and recent
run states. It does not receive the request body, permit bytes, result body, or
private task key.

Cancellation prevents future runs from being materialized. It cannot prove that a
run already dispatched to Hermes stopped. Inspect each generated task before
issuing replacement authority.

## Overlap and missed runs

The default `-max-concurrency 1 -overlap skip` prevents a slow run from building
an unbounded queue. Use `-overlap queue` when every signed run should wait for the
previous run and the finite backlog is acceptable. Concurrency can be raised only
within Steward's signed safety limit.

The missed-run policy is `skip`. If Control was offline until a run's signed
dispatch window had passed, it records that run as skipped instead of pretending
expired authority can still execute. Steward does not replay a burst of old work
after recovery.

A run can also be skipped when its exact target is unavailable. This is honest
state, not an automatic retargeting decision: the schedule is signed to one
admitted workload generation and cannot silently follow a replacement instance.
Create new schedule authority after reviewing the replacement deployment.

## Restart and replay behavior

Schedules and run projections live in Control's durable, hash-chained state. On
restart, Control reconstructs the next authorized run number. It never creates
more than one task for the same schedule ordinal.

Node delivery remains at-least-once. A lost acknowledgement can redeliver the
same generated task, but Gateway's deterministic task identity and one-use permit
ledger prevent the exact retry from becoming a second external effect.

Control state contains the exact request and a schedule signature that can
authorize future runs until their individual windows pass. Protect and back up the
state directory as authority-bearing sensitive data.

## Limits

A schedule has at most 10,000 runs. Intervals range from one minute through
30 days, the first run must begin within 30 days, and each dispatch window is at
most 15 minutes and cannot exceed the service operation's own permit maximum.
Control retains at most 512 schedules site-wide and 128 per tenant.

These bounds keep one compromised operator credential or malformed client from
creating unlimited controller work. For a permanently running service, use a
durable deployment. For event-driven work, submit one signed task per event
instead of polling through a schedule.

[Run remote tasks]({{ '/guides/async-tasks/' | relative_url }}) ·
[Keep work in a Workroom]({{ '/guides/workrooms/' | relative_url }}) ·
[Understand Control's boundary]({{ '/concepts/control-plane-boundary/' | relative_url }})
