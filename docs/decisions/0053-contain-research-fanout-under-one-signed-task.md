---
title: Contain research fan-out under one signed task
description: Why parallel research uses bounded in-sandbox delegation instead of unsigned remote dispatch.
section: Architecture decision
---

# Contain research fan-out under one signed task

- Status: Accepted
- Date: 2026-07-21
- Rung: native-platform

## Context

Research applications need several independent searches and source extractions in
parallel. Requiring a person to sign every sub-question is impractical. Removing
task authentication entirely, however, would create a second remote execution
tier whose requests are not attributable to a tenant authority.

Hermes already supports child-agent delegation within one running task. Those
children inherit the parent's tool surface and remain inside the same container,
Gateway grant, task deadline, and connector call budget.

## Decision

Use one normally signed top-level research task and allow bounded internal Hermes
delegation only in the research tool profile. Steward fixes the research profile
at four concurrent children, twelve model iterations per child, one spawn level,
a 180-second child timeout, no dangerous-command auto-approval, and 32 parent
turns. The developer and workspace profiles do not receive delegation.

**Tradeoff:** Research fan-out is easy and does not require a signature for every
internal reasoning step, while all remote entry still has one durable tenant
authorization and result record.

**Rejected:** An unsigned Gateway task endpoint would weaken identity, replay,
quota, and audit guarantees for a convenience that internal delegation already
provides. A new cryptographic delegation format is unnecessary until a controller
must dispatch independently addressable remote tasks rather than child work inside
one admitted instance.

## Consequences

Child findings are untrusted agent output. Confirmed findings can leave the
instance through the bounded controller-event channel, and the top-level task
result remains the authoritative completion record. Connector and inference
budgets still bound aggregate work.

Revisit if research workers must survive the parent task, run on different nodes,
or receive distinct remote identities and retention policies.
