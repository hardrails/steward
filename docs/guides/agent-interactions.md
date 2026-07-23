---
title: Answer a running agent safely
description: Let an admitted agent ask one bounded question and return an operator response signed for that exact question and workload generation.
section: How-to guide
---

# Answer a running agent safely

Some useful work cannot be completed safely by guessing. An agent may need an
operator to choose between known options, confirm missing context, or provide a
short non-secret answer.

Steward interactions provide that pause-and-answer channel without turning
Control into a general command authority. The running instance opens a bounded
question through Gateway. Control durably carries the question. An operator
signs a response for the exact question digest, workload identity, and generation.
Gateway verifies that binding before the instance can collect the answer.

## Review open questions

The React console shows open questions in the **Workrooms** view and a complete
bounded inbox in **Questions**. The console is read-only for interactions because
a private task key does not belong in browser memory.

Use the trusted CLI to inspect the exact record:

```console
stewardctl control interaction list
stewardctl control interaction show -interaction-id INTERACTION_ID
```

The record identifies the tenant, node, instance, runtime reference, generation,
question text, permitted choices, expiry, and request digest. Treat the question
as untrusted agent-authored text. Never paste a secret into a response.

## Sign one response

Choose one of the listed options:

```console
stewardctl control interaction respond \
  -interaction-id INTERACTION_ID \
  -choice continue
```

When the question explicitly permits text:

```console
stewardctl control interaction respond \
  -interaction-id INTERACTION_ID \
  -text "Use the public quarterly filing, not the unsourced summary"
```

The selected CLI context supplies tenant and task-key paths. The CLI fetches the
current question, validates the option or text rule, signs a short-lived response,
and submits the unchanged response and permit to Control. Control cannot alter the
answer without invalidating its digest.

## Security and failure behavior

An interaction response is context, not permission for an unrelated external
effect. A protected connector call still requires its own Authorized Effects
permit. This prevents an innocent “continue” answer from becoming reusable tool
authority.

Responses expire and bind to one exact workload generation. A replacement or
re-created instance cannot collect an old answer. Delivery is at-least-once, so
the instance must treat the interaction identity as idempotent.

Control can delay, withhold, or replay exact retained bytes. It cannot create a
valid new response, change its content, or retarget it to another workload without
the tenant key. A compromised node can forge a question attributed to workloads
on that node; the operator must still judge the request.

Questions and responses are bounded but may contain sensitive operational text.
They live in Control's owner-only durable state and should follow the same backup
and retention controls as task requests. They are omitted from ordinary metrics,
logs, and support bundles.

[Authorize an external effect]({{ '/guides/authorized-effects/' | relative_url }}) ·
[Receive non-blocking agent events]({{ '/guides/controller-events/' | relative_url }}) ·
[Operate the React console]({{ '/guides/operator-console/' | relative_url }})
