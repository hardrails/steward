# 0073. Add a finite recent Gmail read

- Status: Accepted
- Date: 2026-08-15
- Rung: commercial

## Context

Assistants and scheduled workflows need recent inbox context, but OAuth custody,
refresh, revocation, and provider credential injection are commodity work. A generic
Gmail proxy or caller-defined search would create open-ended authority, while headers
alone do not satisfy the useful job of understanding incoming work.

## Decision

Reuse Pipedream Connect behind Steward's existing replaceable broker boundary and
add one reviewed `gmail.readonly` operation. It reads at most 20 inbox messages from
the last 30 days, extracts bounded headers and plain text within one deadline, and
accepts no caller query, URL, message ID, attachment, or write action.

**Tradeoff:** commercial credential custody removes token-lifecycle ownership while
the finite Steward operation preserves least privilege, output bounds, and a stable
contract. **Rejected:** owning Google OAuth and token refresh because it recreates
security-sensitive context work; a generic Gmail/MCP proxy because its authority is
too broad; metadata-only access because it cannot support the user job.

## Consequences

Google production verification and potentially a restricted-scope security
assessment are launch dependencies. Email content remains untrusted evidence and
must not acquire control authority downstream. Revisit if compliance, residency,
availability, or unit economics make Pipedream unsuitable, or if the product needs
a separately reviewed write capability.
