---
title: Add total-batch research extraction
description: Why partial source failures are values in an additive v2 contract backed by killable standard-library processes.
section: Architecture decision
---

# Add total-batch research extraction

- Status: Accepted
- Date: 2026-07-29
- Rung: built-in

## Context

Multi-source research expects some pages to reject, disappear, or contain an
unsupported representation. The v1 extractor is deliberately fail-fast, so one
such source discards otherwise useful work. Changing that response in place
would silently break signed profiles and consumers. In-process thread fan-out is
also insufficient because a blocking system resolver cannot be cancelled and
can outlive both worker and Gateway authority.

## Decision

Add `/v2/extract` with the same bounded URL request and a strict ordered outcome
for every URL. Only the closed, message-free source failure taxonomy is an item
value; request, authentication, service, protocol, and overall response-size
faults reject the whole call. Successful outcomes retain the requested and
resolved URLs, original media type, normalized `text/plain` content, and explicit
32 KiB truncation state.

Use Python's standard process, selector, and signal primitives to run at most
four sources concurrently. The parent kills each process group after 15 seconds
and the batch after 50 seconds, containing resolver, socket, parser, and PDF
descendants without adding a runtime dependency. Expose v2 through a distinct
Gateway connector identity and leave v1 unchanged.

**Tradeoff:** Short-lived processes cost more than threads, but provide a
killable deadline boundary for otherwise non-cancellable work.

**Rejected:** Mutating v1 would break its fail-fast contract. One connector call
per URL would multiply orchestration, receipt, and retry state. A thread pool
cannot enforce the batch deadline around a wedged resolver. A new durable-workflow
engine is disproportionate to this worker-local bounded fan-out.

## Consequences

Source children retain the parent UID and container filesystem; stripped
environments and descriptors do not make them a credential trust boundary.
Operators must continue to sandbox the entire worker container. Revisit if the
extractor must survive worker restarts, distribute sources across nodes, or
assign independent durable identities and retry histories to individual URLs.
