# 0075. Add finite Microsoft 365 reads

- Status: Accepted
- Date: 2026-08-16
- Rung: commercial

## Context

Assistants, briefings, and operational workflows need recent Microsoft 365 mail and
calendar context. OAuth custody, refresh, and revocation are commodity work. The
default Pipedream Microsoft clients request mail, calendar, and file write authority,
while one combined Microsoft Graph connection would couple unrelated permissions.
Neither is compatible with a least-privilege pre-built integration.

## Decision

Reuse Pipedream Connect with two separate custom OAuth clients behind Steward's
existing replaceable broker boundary. The Outlook Mail profile requires `Mail.Read`
and returns at most 20 inbox previews from the last 30 days. The Outlook Calendar
profile requires `Calendars.ReadBasic` and returns at most 50 basic primary-calendar
events from the next 14 days. Each operation has a fixed target, projection, deadline,
and response bound. Callers cannot provide Microsoft Graph URLs, queries, folders,
calendars, time ranges, page tokens, attachments, message or event IDs, provider
headers, or write actions.

**Tradeoff:** commercial credential custody removes token-lifecycle ownership while
separate custom clients and finite Steward operations preserve exact authority.
**Rejected:** Pipedream's default Microsoft clients because they request write/send
permissions; one combined Graph connection because it bundles unrelated authority;
owning Microsoft OAuth because it recreates security-sensitive context work; and a
generic Graph or MCP proxy because its authority exceeds the two read jobs.

## Consequences

Production enablement requires custom OAuth client configuration and real
consent/reconcile/read/revoke qualification for each profile. Mail previews and
calendar content remain untrusted evidence and cannot acquire control authority.
OneDrive is deferred until Steward can return useful bounded document content rather
than metadata alone. Revisit Pipedream if compliance, residency, availability, or
unit economics make the broker unsuitable, or revisit the operation boundary when a
separately reviewed confirm-before-commit write job is required.
