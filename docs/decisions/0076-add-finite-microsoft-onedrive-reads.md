# 0076. Add finite Microsoft OneDrive reads

- Status: Accepted
- Date: 2026-08-24
- Rung: commercial

## Context

Custom assistants and research workflows need owner-selected Microsoft documents.
OAuth custody and refresh are commodity work, but a generic Graph or MCP connection
would expose route, query, site, and potentially write authority far beyond that job.
The existing Pipedream/Steward boundary already proves separate custom OAuth apps,
exact Microsoft scopes, owned-account checks, deadlines, bounds, and revocation.

## Decision

Reuse Pipedream Connect with a separate `microsoft_onedrive` custom OAuth client and
add fixed Steward operations requiring delegated `Files.Read`. One operation lists at
most 50 children of root or one strictly validated selected folder. A second refetches
metadata and reads at most ten selected UTF-8 plain-text or Markdown files, bounded to
64 KiB each and 240 KiB aggregate under one 30-second deadline. The broker retains
Graph's preauthenticated download redirect; Steward never returns it or a credential.

**Tradeoff:** commercial credential custody and redirect handling avoid owning token
lifecycle while a small stdlib transport preserves finite authority. **Rejected:**
Pipedream's default Microsoft client because it requests broader permissions; generic
Graph/MCP access because it accepts bearer-equivalent authority; delta because a
correct initial mirror must consume every page; search because it adds caller query
and continuation semantics; and a new Office/PDF parser because binary conversion is
a separate security and dependency boundary.

## Consequences

Production enablement requires real consent, exact-scope reconciliation, nested-folder
listing, selected text read, and revocation qualification. Binary, Office, and PDF
items are visible but explicitly unsupported. SharePoint libraries and shared-with-me
traversal remain out of scope until a selected-site permission and owner UX contract
is reviewed. Revisit Pipedream if compliance, residency, availability, or unit
economics make the broker unsuitable; revisit extraction only as an independently
bounded capability rather than expanding this credential worker.
