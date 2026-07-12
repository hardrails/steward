---
title: Extend Steward Gateway for signed egress
description: Why Steward uses its bounded standard-library Gateway instead of a general proxy or policy engine.
section: Architecture decision
---

# Extend Steward Gateway for signed egress

- Status: Accepted
- Date: 2026-07-11

## Context

Steward needs enforceable HTTP(S) egress for multiple tenants on one host, including
offline sites. The repository must keep zero private or third-party Go dependencies,
and workloads must not receive raw Docker networking.

## Decision

Extend the trusted Relay/Gateway design with Go's `net`, `net/http`, `net/url`, and
`net/netip` packages. Keep policy combination and workload grant binding inside
Steward because they belong to its trust boundary.

**Tradeoff:** the enforcement component stays small, auditable, and
offline-packaged. Steward must maintain the limited HTTP proxy. Gateway traffic
decisions use its bounded newline-delimited JSON (JSONL) audit log. Gateway refuses
an allow decision if it cannot persist that audit record. Denial and terminal audit
writes are best-effort because a storage failure must not turn a denial into access
or keep a finished connection open. Signed Executor receipts cover admission and
lifecycle effects, not individual proxy requests.

**Rejected:** Envoy, Squid, and general policy engines add supply-chain inputs,
configuration, packaging, and attack surface without improving this bounded
HTTP(S)-only design.

Use a pinned copy of the IANA IPv4 and IPv6 special-purpose registries for the
default address decision. Go's `IsGlobalUnicast` includes ranges such as
`100.64.0.0/10`, so it is not a public-Internet safety test by itself. Operators
can override special-purpose unicast with an explicit CIDR. Unspecified and
multicast destinations, and the IPv4 limited broadcast address, remain invalid.

Use native HTTP framing for unknown-length response integrity. Gateway streams the
body, advertises a completion trailer, and aborts the stream on a read failure or
byte-limit overflow. Full response spooling was rejected because it would break
token and event streaming and would add memory or disk pressure at the trust
boundary.

## Consequences

This component excludes raw TCP, UDP, transparent interception, and TLS interception.
Reconsider if operators need non-HTTP protocols, application-layer inspection
inside HTTPS tunnels, or more connections than the Steward Gateway can support.
Compare the pinned special-purpose table with the IANA registries during security
releases and update its table tests when IANA changes an allocation.
