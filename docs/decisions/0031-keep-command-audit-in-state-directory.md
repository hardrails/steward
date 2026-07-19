# 0031. Keep the command audit in the service state directory

- Status: Accepted
- Date: 2026-07-19
- Rung: native-platform

## Context

Steward's packaged supervisor writes structured operational logs to standard output
for systemd's journal and also maintains a dedicated JSON Lines command audit. The
old audit path was below `/var/log`. Ubuntu permits its trusted `syslog` group to
write that parent directory, while Steward's installer correctly rejects a writable
ancestor for an application-owned audit path. Relaxing the ancestor check would let
another process in that group replace the audit directory.

## Decision

Store the command audit at `/var/lib/steward/audit.jsonl`, below systemd's
owner-only `StateDirectory`. Continue sending operational logs to standard output
and journald.

**Tradeoff:** The audit is no longer under the conventional log hierarchy, but its
path works across supported systemd distributions without weakening ancestor checks.

**Rejected:** Accepting `root:syslog 0775` for `/var/log`, because a writable parent
is not an appropriate trust root for Steward's application-owned audit history.

## Consequences

Current packages do not require or create `/var/log/steward`. An older audit file is
left in place during upgrade and must be retained or archived according to site
policy. Revisit if Steward adopts a platform API that can create and hold a protected
log directory without trusting writable path ancestors, or if the signed evidence
ledger replaces the separate command audit entirely.
