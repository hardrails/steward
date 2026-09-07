# 0077. Retain runtime tree identity across squash merges

- Status: Accepted
- Date: 2026-09-06
- Rung: native-platform

## Context

Runtime qualification must match the production inputs being released. The
repository permits squash merges and deletes merged branches, so the original
qualified commit may be absent from a clean release checkout. Evidence retention
must not invalidate unchanged runtime inputs.

## Decision

Retain a SHA-256 digest of Git's native `ls-tree` records for `cmd`, `internal`,
`go.mod`, and `go.sum`. Compare those content-addressed trees with the current
checkout, reject dirty tracked runtime files, and check the actual compiler/embed
inventory for untracked inputs. Keep the original commit, tree, and binary digests
as provenance without requiring the original commit object for verification.

**Tradeoff:** native Git content identity survives squash merges and shallow
checkouts without a separate source archive, persistent branch, or dependency.

**Rejected:** looking up the original qualified commit requires unreachable
history after merge. Changing repository merge policy or retaining every branch
would add an operational requirement unrelated to runtime correctness.

## Consequences

Fresh qualification records must include the runtime-tree digest; older records
are not rewritten. A shallow-clone regression proves both continued verification
without the original commit and rejection of changed source. Revisit if runtime
build inputs move outside the recorded paths or release builds no longer use Git.
