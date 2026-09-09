# 0079. Confine host-visible ZFS with packaged AppArmor

- Status: Accepted
- Date: 2026-09-08
- Rung: native-platform

## Context

The storage helper's mounts must be visible to the Docker daemon. Systemd
filesystem sandboxing created a private mount namespace: backend checks passed
inside it, but a container received the underlying unquotaed directory. Dropping
confinement or making state world-writable is not an acceptable repair.

## Decision

Use an AppArmor allowlist while the worker shares the host mount namespace.
Include the policy in the verified release inventory. A privileged systemd
pre-start command loads that exact selected policy; `aa-exec` then enters it before
executing the worker with only `CAP_SYS_ADMIN` and `CAP_CHOWN`. No new daemon or Go
dependency is introduced. Loading failure prevents startup even when an older
profile is already present. A missing profile cannot launch an unconfined worker.

**Tradeoff:** native filesystem and mount confinement keeps host-visible ZFS
usable, but narrows this optional backend to hosts with AppArmor. The worker,
Docker and ZFS remain trusted host infrastructure: a path allowlist does not
restrict all ZFS ioctls or remove Docker's root-equivalent authority.

**Rejected:** private mount namespaces hide required mounts; mount-propagation
plumbing adds topology and recovery ownership. An unconfined helper loses the
filesystem boundary. A separate policy daemon duplicates systemd lifecycle work.
SELinux support is deferred until an actual supported-host requirement justifies
another tested policy, not silently replaced by permissive operation.

## Consequences

The policy uses packaged paths. Custom paths require a reviewed policy and unit
override. The confined worker uses a root-owned token copy; Executor keeps its
own owner-only copy. Rotations quiesce callers and replace both copies.

An opt-in Linux test derives an isolated fixture from the packaged assets and
checks startup, host mount-namespace identity, enforcing profile identity, refusal
of invalid/missing policy, and successful recovery. It removes only its random
unit, profile and child dataset. Ordinary unit tests do not claim live kernel
enforcement; separate sandbox acceptance proves writes, quotas and replacement.

Revisit for a supported SELinux-only target or a storage driver that does not
require host-visible mounts. Replacing this policy needs no tenant data-format
migration, but requires equivalent host and sandbox acceptance before admission.
