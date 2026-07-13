---
title: Broker named HTTPS connector operations in Steward Gateway
description: Why agents receive narrow logical operations instead of upstream credentials or a general authenticated proxy.
section: Architecture decision
---

# Broker named HTTPS connector operations in Steward Gateway

- Status: Accepted
- Date: 2026-07-13
- Rung: existing subsystem

## Context

An agent often needs an authenticated API to do useful work. Giving the workload a
long-lived bearer token makes prompt injection, a malicious skill, or a compromised
agent process a credential-exfiltration event. Steward's inference path already
keeps one credential in Gateway, but generic HTTP(S) egress cannot safely add a
credential inside an opaque `CONNECT` tunnel.

The boundary must remain framework-neutral, work without a hosted control plane,
and preserve Steward's dependency-free build. It must not become a vault, an
arbitrary header injector, or a general TLS interception proxy.

## Decision

Extend the existing Relay/Gateway subsystem with **named connector operations**.
Site configuration binds each operation to one exact HTTP method and upstream path,
one HTTPS origin, bounded concurrency, request bytes, response bytes, and duration,
plus one owner-only credential file. Signed capsule, site policy, and instance
intent independently constrain which connector IDs a workload may receive.

The workload calls a logical connector ID through its per-instance Relay. Gateway
resolves and pins an allowed upstream address, strips agent-supplied credentials and
cookies, sends the configured request itself, and adds either a Bearer authorization
value or an API-key header at the last hop. Redirects, caller-selected origins,
caller-selected paths, and caller-selected credential headers are unavailable.

Connector configuration and credential-content digests are bound to the retained
Gateway grant. A configuration or credential change therefore requires the old
grant to be drained and replaced; reload cannot silently change authority beneath a
running workload. Gateway records a bounded pre-effect allow decision before it
opens the upstream request and a terminal outcome after the bounded response.

Reuse Go's `net/http`, `net/url`, `net/netip`, existing special-address policy,
credential loading, grant persistence, Relay sockets, and admission intersection.
This is the lowest-ownership option that preserves the signed offline contract.

**Rejected:**

- injecting credentials into generic HTTPS `CONNECT` traffic, which would require
  TLS interception or would expose the credential to the workload;
- a general secret, environment-variable, file, or arbitrary-header injection API;
- Envoy, Squid, Open Policy Agent, or a hosted connector service as a required
  component, because each adds supply-chain and operational ownership without
  replacing Steward's signed admission and grant binding; and
- a complete agent workflow engine. Steward brokers authority at its enforcement
  boundary; Hermes, OpenClaw, or another agent still decides how to use an admitted
  operation.

## Consequences

The first contract favors precise, auditable operations over API breadth. Dynamic
path templates, redirects, browser sessions, OAuth authorization flows, raw TCP,
and arbitrary request headers remain unavailable. Operators can use an external
secret manager to materialize the owner-only credential file, but Steward does not
depend on or implement that manager.

A connector receipt proves that Steward admitted and mediated a bounded network
operation. It does not prove prompt meaning, agent intent, upstream correctness, or
that a hostile host administrator preserved the complete receipt chain.

Shared-host persistent state remains disabled until a qualified backend can prove
hard byte and inode quotas after restart and during reconciliation. Connector work
must not weaken that existing fail-closed boundary.
