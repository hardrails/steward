# 0074. Add a finite upcoming Google Calendar read

- Status: Accepted
- Date: 2026-08-15
- Rung: commercial

## Context

Assistants, chief-of-staff workflows, daily briefings, and scheduling preparation
need near-term calendar context. OAuth custody, refresh, and revocation are commodity
work. A generic Calendar proxy, MCP server, or caller-selected query would create
open-ended authority, while calendar writes have materially higher consequences and
are not required for the first useful read job.

## Decision

Reuse Pipedream Connect behind Steward's existing replaceable broker boundary and
add one reviewed `calendar.events.readonly` operation. It reads at most 50 events
from the primary calendar for the next 14 days, expands recurring events, orders by
start time, and returns bounded normalized content within one deadline. It accepts
no caller calendar ID, query, time range, URL, page token, attendee limit, provider
header, or write action.

**Tradeoff:** commercial credential custody removes token-lifecycle ownership while
the finite Steward operation preserves least privilege, deterministic bounds, and a
stable contract. **Rejected:** owning Google OAuth and token refresh because it
recreates security-sensitive context work; Pipedream's generic tools or MCP surface
because their authority exceeds the read job; calendar writes because they require
separate confirmation, idempotency, and consequence controls.

## Consequences

Google production verification remains a launch dependency. Calendar content and
participants remain untrusted evidence and must not acquire control authority
downstream. The broker remains replaceable because callers depend on Steward's
finite schema rather than Pipedream's provider contract. Revisit if compliance,
residency, availability, or unit economics make Pipedream unsuitable, or if a
separately reviewed, confirm-before-commit write capability becomes a priority.
