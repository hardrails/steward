# 0084. Reuse network receipts for inference attempts

- Status: Accepted for implementation; qualification required before release
- Date: 2026-09-11
- Rung: native-platform

## Context

One dispatched agent task can make several provider calls. A task receipt cannot
establish the number of potentially paid inference attempts, especially after a
lost response or worker recovery. Accounting needs to observe the outbound
boundary, not trust an agent's task ID or reported token count.

## Decision

Extend the existing bounded, signed network-call ledger with version-9 inference
attempts. Reuse its tenant quotas, fsync, terminal reservations, fail-closed
writer, restart handling and offline verifier. Each attempt has a gateway-minted
identity and the admitted tenant, runtime, generation, grant and route policy.
An opt-in route setting requires a retained authorization before HTTP transport;
the setting and capacity are bound into route policy. Omitted configuration
retains legacy behavior, not a claim of zero usage.

Authorization is a conservative count of potentially paid attempts. A crash
between persistence and network transmission remains uncertain. A terminal
record describes response headers or transport failure, not generation
completion, output quality, token usage or the provider's invoice. Non-rewindable
bounded requests and disabled redirect following prevent hidden body replay.

**Tradeoff:** A distinct receipt vocabulary preserves existing task and connector
semantics without another daemon, key store, database or dependency. Consumers
must verify complete signed chain coordinates and exact runtime ownership;
an agent-supplied correlation header cannot establish task attribution.

**Rejected:** Reusing Executor lifecycle evidence would mix high-volume network
events into a separate admission chain. A metrics counter loses uncertainty and
restart custody. A second accounting service duplicates the existing ledger.

## Consequences

Older readers reject version 9; historical receipts are not rewritten. Required
accounting stops forwarding when durable capacity or the writer is unavailable.
Gateway startup closes unfinished attempts as outcome unknown. Reconfiguration
preserves the requirement unless explicitly changed, and retained grants prevent
silent route-policy replacement. Billing reconciliation and consumer-specific
release policy remain outside Steward. Revisit when a provider supports a
verifiable request/billing protocol or per-task attribution is required across
concurrent work within one grant.
