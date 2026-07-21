---
title: OpenClaw support retirement
description: What happens to older OpenClaw definitions and how to move to the supported Hermes runtime.
section: Reference
permalink: /reference/openclaw-migration/
---

# OpenClaw support retirement

Steward no longer ships or qualifies an OpenClaw adapter. New and existing agent
definitions that select `runtime.engine: openclaw` fail validation. Steward does
not rewrite an OpenClaw workspace, skill, or configuration because those inputs
are untrusted and the two runtimes do not have a safe one-to-one contract.

Create a new Hermes project, review every requested skill and capability, import
only the data you intend to trust, build a fresh digest-pinned image, and authorize
that new application through the normal signed-admission workflow. Keep the old
OpenClaw state offline until the Hermes result has been independently verified.

Historical decisions and market analysis may still mention OpenClaw. Those pages
record prior designs or compare competing products; they are not a statement of
current runtime support.
