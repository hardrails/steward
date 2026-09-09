# 0081. Reuse the private signer for exact owner answers

- Status: Accepted
- Date: 2026-09-09
- Rung: native-platform

## Context

A host needs to deliver an owner's answer without holding the admitted task key.
The native keyless courier exists, but `control interaction respond` combines
key access, signing and submission. The private station previously signed only tasks.

## Decision

Extend the existing single-runtime Unix-socket station with an explicit
`-allow-responses` option. Reuse native question validation, response signing,
signature verification, the station's lock and durable first-issuance store, and
the separate keyless courier. Expose that same native verifier through the offline
`control interaction verify-response` command so hosts need neither a second
cryptographic implementation nor trust in the socket response alone. Hosts compare
its verified statement to independently retained runtime, question and answer policy.
Keep response and task record identities disjoint
while sharing the capacity bound. The option is off by default and frozen in the
store binding; existing task-only bindings remain byte-compatible.

**Tradeoff:** no additional service, dependency, key transfer or cryptographic
implementation. Socket clients gain bounded answer-signing authority when opted in;
the host still authenticates owner decisions and Gateway still checks its pending
question. The station does not assert that a host-supplied question is authentic.

**Rejected:** giving the host `control interaction respond` and the private key,
because it violates key isolation and couples signing to an uncertain network effect.
A separate answer-signing daemon would duplicate the existing lifecycle and storage.

## Consequences

Lost acknowledgments recover the original unexpired permit. Changes and expired
permits conflict rather than issuing a second decision. Retained capacity is shared
and finite. This is not a business approval service or an external-write grant.
Revisit if independently delegated response-only keys or runtime-fleet issuance
become a concrete requirement.
