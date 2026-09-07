# 0078. Reuse the native task issuer in a private signing station

- Status: Accepted
- Date: 2026-09-07
- Rung: native-platform

## Context

Host applications need task authority without holding a tenant private key or
asking a person to transfer a bundle for every turn. Steward already validates
admission, intent, operation trust and exact request bytes before issuing a task.
The signing boundary must remain outside both the workload and its application.

## Decision

Expose the existing issuer through an optional Unix-socket signing-station
process. The operator pins one runtime admission, one to eight allowed operations,
a finite permit lifetime and a finite issuance capacity. Callers supply only a
task ID, an allowed operation ID and exact request bytes. The station retains
each issued bundle before returning it and
refuses changed replays, replacement configuration and ambiguous retained files.
It does not dispatch tasks, create runtime grants, authorize connector effects or
sign answers. Socket access is issuance authority for the allowed operations.

Use native Unix identity separation: a distinct host UID reaches the socket
through an explicit dedicated client GID. Its signer-owned parent is `0710` and
the socket is `0660`; the private store and key snapshots remain owner-only.
The signer must be a member of the client group to create the socket without
root privileges. A matching signer/client UID is not an isolation boundary.

**Tradeoff:** reuse the CLI's validation and signing code without another crypto
implementation, network-facing service, database or dependency. The operator
still runs an isolated signing process and protects its socket and persistent
storage. The initial station is finite and single-runtime, not a fleet authority.

**Rejected:** signing inside the host application breaks key separation. Giving
Control the tenant task key broadens its trust role. A generic remote signing API
does not enforce Steward's admission and exact-operation contract.
An owner-only socket with matching client ownership was rejected in review:
under a shared filesystem, that arrangement also gives the client access to the
signer's key snapshots. Dedicated group access permits separation without a new
credential protocol, platform-specific peer-credential syscalls or privileged
socket-ownership handoff. Unix root, signer-UID processes and debuggers remain
inside the trusted operator boundary.

## Consequences

The host verifies returned authority independently before committing a dispatch
claim. Deployment must keep the private key and station store out of application
and workload mounts; share only the private socket. Existing CLI issuance remains
available for offline operators. Independent security review and integration
proof remain release requirements. Revisit if remote multi-tenant issuance is
needed; do not expose this socket protocol over an unauthenticated TCP listener.
Removing the optional station restores the offline bundle-transfer workflow;
existing permits and Gateway replay protection require no format migration.

The Linux identity regression starts separate unprivileged signer, client and
outsider processes. It verifies exact task replay over the group socket, denial
of source-key/snapshot/store reads and socket deletion by clients, and refusal
of outsider connections. CI requires this check in addition to protocol tests.
