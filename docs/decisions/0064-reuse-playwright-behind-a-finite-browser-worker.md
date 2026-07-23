---
title: Reuse Playwright behind a finite browser research worker
description: Why Steward owns a narrow search and read protocol while reusing pinned Playwright only inside a separate gVisor workload.
section: Architecture decision
---

# Reuse Playwright behind a finite browser research worker

- Status: Accepted
- Date: 2026-07-23
- Rung: open-source dependency

## Context

Hermes research needs visible text from public pages that require JavaScript.
Putting browser automation in Steward's Go processes would violate their
dependency and isolation boundary. Giving Hermes a general browser, raw URL fetch,
or Playwright MCP surface would expose a much larger prompt-injection and SSRF
authority than research requires. Building a browser engine is not credible.

## Decision

Reuse exact-integrity Playwright and the official digest-pinned browser image in a
separate non-root gVisor worker. Steward owns the finite protocol: search through
an operator-controlled SearXNG service, issue short-lived opaque source
references, and read only those references in fresh credential-free browser
processes. The worker has no click, type, upload, download, evaluate, cookie,
arbitrary URL, or generic browser API.

The worker rejects non-public DNS results, pins the chosen address, blocks
cross-origin subrequests, and bounds input, output, screenshots, concurrency, and
time. Network topology remains the outer private-route denial boundary. A weekly
workflow proposes pinned Playwright updates only after audit, boundary tests, and
an image build.

**Tradeoff:** Playwright supplies maintained browser control and cross-platform
browser packaging, while Steward retains a small reviewable authority surface.
It adds a sizeable optional image and an npm supply chain that must be qualified.

**Rejected:** a generic Playwright MCP server, because a manipulated model would
receive far more browser authority than source reading requires. Browser code
inside Control, Gateway, Executor, or the Go module was rejected because a browser
compromise must not share their process boundary. The lightweight static extractor
alone was rejected because it cannot read JavaScript-rendered sources.

## Consequences

Rendered text and screenshots remain untrusted and are not proof that a claim is
true. The worker is not suitable for authenticated sessions or consequential
browser actions. Revisit this decision if Playwright cannot be rebuilt and audited
offline, upstream image provenance becomes unsuitable, Chromium isolation changes
materially, or a smaller maintained engine satisfies the same tested contract.
