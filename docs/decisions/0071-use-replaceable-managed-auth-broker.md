# 0071. Use a replaceable managed-auth broker

- Status: Accepted
- Date: 2026-08-14
- Rung: commercial

## Context

Steward must let a tenant connect common OAuth services without exposing provider
credentials to an agent, application control plane, browser, log, or artifact.
OAuth consent, token refresh, provider-specific credential injection, and account
revocation are commodity integration work. Runtime authority, bounded data access,
receipts, and normalized results remain Steward responsibilities.

## Decision

Use Pipedream Connect as the first replaceable managed-auth broker behind a
provider-neutral Steward worker boundary. The worker may create an app-scoped,
short-lived connect link, reconcile or revoke the resulting account, and invoke
only named reviewed provider operations. The first operation lists bounded Google
Drive file metadata with the `drive.metadata.readonly` provider scope. Steward
requests exact Pipedream scopes, freezes the upstream API target, validates the
response, and never exposes a general Pipedream action, MCP, or proxy surface.

**Tradeoff:** buying credential custody and refresh removes substantial secret and
provider lifecycle ownership while Steward retains the product's differentiated
authority and evidence guarantees. The boundary uses Pipedream's REST protocol and
opaque account identifiers so another broker can replace it.

**Rejected:** implementing OAuth and refresh logic in Steward because it recreates
commodity security-sensitive infrastructure; direct Pipedream actions, MCP, or a
general proxy because their changing authority surface cannot be frozen into one
reviewed operation.

## Consequences

Pipedream is an external processor and operational dependency. Deployments fail
closed when it is unavailable or unconfigured, credentials remain in the worker,
and the control plane stores only opaque non-secret handles. Production readiness
requires a real consent, reconciliation, invocation, and revocation exercise.

Revisit if Pipedream cannot meet data-residency, compliance, availability, unit
economics, or exact-scope requirements; if a self-hosted broker becomes cheaper to
operate; or if provider-native workload identity removes the need for stored OAuth
credentials.
