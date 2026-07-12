# 0001. Extend the native Steward gateway for egress

- Status: Accepted
- Date: 2026-07-11
- Rung: native-platform

## Context

Steward needs enforceable HTTP(S) egress on an air-gapped-installable, single-host,
multi-tenant node. The public repository must retain zero private and third-party Go
dependencies, and the agent must not receive raw Docker networking.

## Decision

Extend the existing trusted relay/gateway topology using Go's standard `net`,
`net/http`, `net/url`, and `net/netip` packages. Keep policy intersection and grant
binding as a thin in-house layer because they are part of Steward's core trust model.

**Tradeoff:** this gives Steward a small, auditable, offline-packaged enforcement
boundary and reuses the topology already covered by lifecycle receipts, at the cost
of owning a deliberately limited HTTP proxy implementation.

**Rejected:** Envoy, Squid, and a general policy engine because they add supply-chain,
configuration, packaging, and attack-surface cost without improving the v1.4
HTTP(S)-only requirement.

## Consequences

Raw TCP, UDP, transparent interception, and TLS MITM remain outside this component.
Revisit if customers require non-HTTP protocols, L7 inspection inside HTTPS tunnels,
or throughput/connection scale that cannot be met by the bounded native gateway.
