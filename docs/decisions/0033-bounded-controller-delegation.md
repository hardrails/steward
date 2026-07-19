# Bounded controller delegation

## Status

Accepted.

## Context

A desired-state controller must be able to replace, start, stop, and inspect agent
instances after the operator disconnects. Giving Steward Control a tenant command
private key would make a controller compromise equivalent to tenant authorization.
Keeping all tenant keys offline without delegation would require an operator to
sign every reconciliation command and would not provide automatic recovery.

Transport authentication is not sufficient. A node credential proves which
Control instance delivered a command; it does not prove that a tenant authorized
that controller to operate a specific deployment.

## Decision

Decision: use `in-house`: a tenant-signed, time-bounded command delegation built on
Steward's existing Ed25519 and DSSE command contract. Tradeoff: Executor can verify
both the offline tenant authority and the online controller command without a
network dependency or a second policy engine. Rejected: store a tenant command key
in Control because controller compromise would grant the key's complete lifetime
authority. Revisit if an interoperable delegation standard can express the same
offline, exact, Executor-verifiable constraints without widening trust.

One delegation fixes:

- the tenant and controller public key;
- a canonical operation set;
- at most 64 exact node identities;
- at most 128 exact instance and lineage identities;
- a claim generation and per-instance generation range;
- an exact admission capsule, resources, capabilities, state disposition, model
  route, service, egress routes, connectors, and effect mode when `admit` is
  allowed; and
- an issue and expiry window no longer than 24 hours.

The tenant command key signing the delegation must be authorized by site policy for
every delegated operation. Executor verifies that signature first, verifies the
command with only the embedded controller public key, requires the command's signed
authorization-context digest to equal the exact delegation envelope digest, and
then checks every scope member locally.

The exact instance list is intentional. A prefix plus a count would require shared
cross-node counter state or allow independent nodes to exceed the tenant's intended
replica ceiling. The controller may choose an allowed node for an exact authorized
instance, but it cannot invent another instance, lineage, resource request, route,
or connector.

OPA remains a policy-narrowing tool and SPIFFE/SPIRE may authenticate the controller
process. Neither substitutes for the tenant's portable authorization artifact.

## Consequences

- Steward Control needs only its online controller key and the public delegation.
  It does not receive the tenant command private key.
- A stolen controller key expires with the delegation and cannot operate outside
  the exact signed scope. Operators must still revoke or replace an active
  delegation after suspected compromise.
- Existing Executor command generations and sequences continue to reject stale or
  replayed commands inside the delegated scope.
- Protocol-4 nodes advertise `controller-delegation-v1`; a reconciler must not
  select an older node for delegated automation.
- Delegation limits authority, not availability. A compromised controller can
  still stop or churn authorized instances when those verbs are delegated.
- New replicas, different capabilities, or an expired validity window require a
  new tenant signature.
