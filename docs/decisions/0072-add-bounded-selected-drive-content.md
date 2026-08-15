# 0072. Add bounded selected Google Drive content

- Status: Accepted
- Date: 2026-08-14
- Rung: in-house

## Context

The managed Google Drive release proved credential custody and metadata listing,
but metadata alone cannot supply owner documents to a workload. Pipedream offers a
general proxy and action catalog, and its Google Drive actions can cover more file
types. Those surfaces let a caller choose changing provider authority and would
make Steward responsible for an unbounded vendor contract.

Google recommends `drive.file` plus Google Picker for per-file authorization. The
current managed broker boundary does not expose a custody-preserving Picker flow;
creating a second OAuth path only for selection would duplicate the commodity
credential lifecycle that decision 0071 deliberately bought.

## Decision

Build one finite `google-drive.content.read` operation inside the existing optional
integration worker. It accepts only one app-scoped external user, one verified
account handle, and one through ten unique canonical file IDs. Steward refetches
metadata, checks download authority, selects the Google endpoint and format, and
returns request-ordered bounded normalized outcomes. V1 supports native Google Docs
as plain text plus UTF-8 `text/plain` and `text/markdown` blobs. Each file is capped
at 64 KiB and aggregate text at 320 KiB; oversize content is rejected, not truncated.
Token lookup, ownership verification, metadata reads, and content reads share one
30-second batch deadline, so selecting more files cannot multiply the upstream
timeout. The aggregate content and field-specific provider-metadata bounds keep
worst-case JSON escaping within the worker's 1 MiB response ceiling.

The configured custom OAuth client changes from metadata-only access to exactly
`drive.readonly`. Existing grants therefore become not-ready until explicit
reconsent. Google classifies this as a restricted scope, so public production use is
gated on Google's verification and any required security assessment.

**Tradeoff:** a small reviewed operation owns the product's differentiating
authority, normalization, and evidence semantics while Pipedream continues to own
commodity OAuth custody and refresh. Checkbox selection at the control plane narrows
actual use but is not represented as per-file OAuth authority.

**Rejected:** generic Pipedream actions, MCP, and raw proxy access because they
delegate authority selection to callers; direct Google OAuth/Picker in Steward or a
product control plane because it creates a second credential path; broad document
parsing because it adds parser attack surface before the source contract is proven.

## Consequences

Provider text is attacker-influenceable data and must enter a workload through a
separate untrusted-evidence boundary; Steward never interprets it or permits it to
choose another operation. Each content response remains `no-store` and contains no
account or broker credential. Production evidence must include real consent, read,
revocation, outage, prompt-injection, and retained-source removal tests.

Revisit the scope and selection design when the managed broker can support Google
Picker with `drive.file` without exposing reusable provider credentials, or if
restricted-scope compliance, data residency, availability, or cost makes the
current broker unsuitable.
