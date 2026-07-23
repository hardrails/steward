---
title: Keep agent work in a durable Workroom
description: Group signed tasks, sessions, artifact locations, and selected memory without storing prompts, secrets, or artifact bytes in Steward Control.
section: How-to guide
---

# Keep agent work in a durable Workroom

An agent chat is a poor system of record. It is easy to lose the question, the
sources behind an answer, and the relationship between one run and the next.
A Steward **Workroom** gives that work a durable project and session structure.

Workrooms are indexes, not shared filesystems or agent memory databases. Steward
Control retains:

- a project name, purpose, default agent reference, and skill names;
- bounded sessions and the signed task IDs attached to each session;
- the byte count, SHA-256 digest, media type, and opaque storage location of an
  artifact; and
- memory references that an operator selected explicitly.

Control does not store prompts, task requests, task results, model transcripts,
artifact bytes, storage credentials, or signing keys. Keep artifact bytes in an
S3-compatible or other operator-managed store. An `external_ref` is metadata; it
must not contain a presigned URL, password, bearer token, or other secret.

## Create a project and session

The examples assume that a CLI context already supplies the Control URL,
credential file, and tenant. Add `-tenant-id TENANT` when your context does not
set one.

```console
stewardctl workroom create market-intelligence \
  -name "Market intelligence" \
  -description "Primary-source research for the weekly brief" \
  -agent researcher

stewardctl workroom session create market-intelligence \
  -id battery-supply \
  -title "Battery supply-chain changes"
```

Open `/console/`, choose the tenant, then select **Workrooms**. The embedded React
console shows projects, sessions, linked tasks, artifact digests, selected memory,
open agent questions, and recent scheduled runs. It remains an inspection surface:
private task keys never enter the browser.

## Attach a signed task

Create the task through the normal signed lifecycle, then name the project and
session when it enters the Control courier:

```console
stewardctl task enqueue researcher \
  "Compare primary sources on recent battery supply constraints. Separate facts from inference and retain source URLs." \
  -project market-intelligence \
  -session battery-supply
```

The task permit is unchanged. Workroom linkage neither signs a task nor expands
its agent, operation, request, deadline, or service authority. Submission fails
atomically if the project or session is missing or archived, so a task cannot
silently become detached from the intended record.

For automation that already created a task bundle:

```console
stewardctl task enqueue \
  -bundle task.bundle.json \
  -project market-intelligence \
  -session battery-supply
```

For recurring work, attach one finite signed schedule to the same session:

```console
stewardctl task schedule researcher \
  -every 24h \
  -runs 14 \
  -project market-intelligence \
  -session battery-supply \
  "Review the approved sources and report material changes"
```

Each materialized run becomes a normal signed task linked to the session. See
[Run finite scheduled tasks]({{ '/guides/scheduled-tasks/' | relative_url }})
for overlap, missed-run, restart, and cancellation behavior.

## Register an artifact

Upload the result to storage you operate. Calculate its digest locally, then
register only the non-secret metadata:

```console
stewardctl workroom artifact add market-intelligence \
  -session battery-supply \
  -task research-task-01 \
  -id weekly-brief-01 \
  -name "Weekly battery brief" \
  -media-type application/pdf \
  -bytes 48231 \
  -sha256 sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  -ref s3://research-artifacts/market-intelligence/weekly-brief-01.pdf
```

Steward does not dereference or verify `-ref`. The size and digest let another
system verify downloaded bytes against the Workroom index.

## Select durable memory

Memory is opt-in. First register an artifact, then point a memory reference at
that artifact:

```console
stewardctl workroom memory add market-intelligence \
  -id approved-supplier-baseline \
  -title "Operator-approved supplier baseline" \
  -artifact weekly-brief-01
```

This reference does not inject content into Hermes by itself. A trusted
application can resolve the artifact through its own storage policy and include
the verified bytes in a later signed task. This separation prevents model-created
text from silently becoming durable authority or trusted memory.

## Limits and concurrent changes

One Control store retains at most 1,024 projects. Each tenant has at most 128
projects; a project has at most 64 sessions, 256 artifacts, 64 memory references,
and 256 task IDs per session. Project replacement and deletion use an exact
revision. A stale writer receives a conflict instead of overwriting newer work.

Deleting a project is refused while a retained Control task refers to it. Archive
or retain a completed project according to your evidence policy; do not delete it
as a substitute for expiring task results or deleting external storage.

[Run a web research agent]({{ '/guides/research-agents/' | relative_url }}) ·
[Run remote tasks]({{ '/guides/async-tasks/' | relative_url }}) ·
[Answer an agent safely]({{ '/guides/agent-interactions/' | relative_url }}) ·
[Operate the React console]({{ '/guides/operator-console/' | relative_url }})
