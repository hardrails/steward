---
title: Architecture
description: Steward's components, trust boundaries, authority flow, and offline operation model.
section: Concepts
---

# Architecture

Steward separates six responsibilities that agent platforms often combine:

1. define a portable Hermes or OpenClaw agent application;
2. explain which fleet node satisfies its declared constraints;
3. decide which immutable workload and capabilities are allowed;
4. run the workload behind a hardened container boundary;
5. mediate external authority without giving reusable credentials to the workload;
6. retain evidence of the enforcement decision.

The first two responsibilities produce deterministic, inspectable artifacts.
They do not create authority. Signed admission and the Executor remain the only
path from a definition or placement decision to a Docker mutation.

## Component map

```text
                    customer-operated management host
             +--------------------------------------------+
             | steward-control                            |
operator --->| scoped API + embedded React console        |
signed files | enrollment, inventory, command transport   |
             | separate evidence witness                  |
             +---------------------^----------------------+
                                   |
                     outbound authenticated node polling
                                   |
+-------------------------- Linux execution node ---------------------------+
|                                                                           |
| steward-executor ---- Docker socket                                       |
|      |              signed lifecycle receipts                             |
|      v                                                                    |
| Docker + gVisor workload -- private capability network -- steward-relay    |
|                                                            |              |
|                                                            v              |
|                                                    steward-gateway         |
|                                                    credentials + permits   |
|                                                    signed action receipts  |
+------------------------------------------------------------|--------------+
                                                             v
                                       inference, services, connectors, egress
```

`stewardctl` runs where an operator needs it: signing station, management host,
node, or offline audit system. `steward-mcp` is an optional local stdio adapter
over bounded public node, control, and pre-signed task operations.

`stewardctl agent` provides the runtime-neutral authoring surface. CUE compiles
human-facing definitions to concrete JSON, OPA may deny them under an offline
organizational policy, and Steward validates the result again at its own strict
boundary. The bundle selects a qualified Hermes or OpenClaw adapter; it does not
replace that runtime's reasoning loop.

The legacy `steward` supervisor remains for the generic public uplink contract.
New Steward Control deployments deliver signed lifecycle commands through
Executor's uplink.

## Trust domains

### Executor

Executor is the only long-running Steward service with Docker authority. Docker
socket access is root-equivalent, so the packaged node requires Executor to be the
Docker group's only member.

Executor verifies:

- the publisher-signed workload profile;
- site-root-signed policy;
- tenant, node, instance, and generation binding;
- immutable OCI image identity;
- resource and aggregate capacity;
- requested capability subsets; and
- lifecycle command signature, sequence, and expiry.

It records accepted lifecycle decisions in a signed hash chain before or around the
relevant mutation according to the protocol contract.

### Workload

The workload is untrusted. It receives:

- its declared command and fixed unprivileged identity;
- bounded temporary filesystems;
- optional Steward-owned persistent state only in dedicated-host mode; and
- only the relay address for capabilities admitted by signed policy.

It does not receive the Docker socket, host mounts, upstream origins, reusable
connector credentials, tenant signing keys, or arbitrary environment variables.

### Relay

Relay is a fixed-destination network helper inside the workload's private Docker
network. It does not make policy decisions and does not hold reusable credentials.
Its purpose is to give the workload a stable local capability address while
keeping Gateway outside the workload network namespace.

### Gateway

Gateway is trusted with configured upstream origins and reusable credentials. It
implements four capability shapes:

- OpenAI-compatible inference routes;
- bounded service operations and lifecycle tasks;
- named authenticated connector operations; and
- explicit HTTP(S) egress policy.

For protected connector operations, Gateway verifies the exact signed permit and
current grant, records the task as spent in durable state, then performs DNS and
network dispatch. This ordering prevents a compliant retry from causing another
effect.

Gateway signs a separate receipt chain. It does not return configured secret values
through responses, receipts, the console, or MCP.

### Steward Control

Control is a customer-operated management and evidence-witness plane. Nodes poll it
outbound, which works behind normal inbound firewalls and network address
translation.

Control stores signed command envelopes and bounded desired deployments. It never
needs tenant private keys. For automatic lifecycle reconciliation, it signs only
within an exact tenant delegation using a separate online key; Executor verifies
both layers locally. Control has no Docker authority and does not receive Gateway
credential plaintext. Its operator bearer determines API scope. A different
witness key signs bounded evidence exports and checkpoints.

The embedded React console uses the same API. Static assets are compiled into the
Go binary, no CDN or telemetry is required, and the operator bearer remains in tab
memory. The browser transfers already signed command bytes; it is not a signing
station.

## Authority flow

### Workload admission

```text
publisher key -> workload profile --+
site root key -> site policy --------+-> Executor admission -> Docker mutation
tenant intent -----------------------+
```

Each signed layer can reduce capability. No layer can expand beyond the workload
profile and site policy. The instance generation prevents delayed authority for an
older workload from acting on its replacement.

### Service task

```text
off-node tenant task key
        |
        v
exact service + operation + task + request bytes
        |
        v
Gateway authorization -> dispatch -> terminal observation
        |
        v
signed task receipt chain
```

The task key is scoped in site policy and remains off-node. The exact bundle is
also the recovery handle after a timeout.

### Authorized effect

```text
agent proposes exact connector request
        |
separate action signer(s)
        |
        v
exact permit -> Gateway verifies current instance and policy
                         |
                    durable spend
                         |
                      DNS/network
                         |
                   external service
```

A threshold can require distinct configured keys to sign the same canonical
request. Context locking can additionally bind the permit to the current digest of
prior managed connector responses.

## Secret handoff

Steward deliberately does not implement a vault. An operator-selected materializer
writes values and epoch markers into protected Gateway-owned roots. Steward
validates a non-secret manifest, directory and file identity, permissions, stable
reads, and expected epoch. Gateway then loads the value at its trusted boundary.

This is a `native-platform` filesystem contract around an `open-source` or
operator-selected secret manager, rather than an `in-house` secret store.

## Tenant isolation

On a shared host, tenant separation includes:

- a gVisor sandbox per workload;
- unique lifecycle and generation identity;
- per-workload and aggregate tenant resource reservations;
- a private capability network per networked workload;
- tenant-scoped commands, grants, task keys, and action keys;
- non-borrowing evidence budgets; and
- durable replay and policy-epoch state.

These controls do not eliminate host or hardware trust. Use distinct hosts or
independently isolated virtual machines when policy requires a stronger boundary.

## Evidence model

Executor and Gateway maintain separate append-only, hash-linked signed journals.
Control can retain bounded node deltas and sign a witness projection.

Offline verification needs:

- an independently authenticated public key and key ID;
- the complete required receipt range;
- the last accepted sequence and chain hash when rollback detection matters; and
- the exact permit or task bundle for authority correlation.

Receipts exclude content by design. They identify policy, digest, task, operation,
permit, sequence, and outcome metadata; they are not a transcript or proof that an
agent's natural-language claim is true.

## Air-gapped operation

After software, OCI archives, models, configuration, and public keys cross the
facility boundary, Steward has no hosted runtime dependency. Nodes, Control,
Gateway, signing stations, and audit systems may all operate on private networks.

Air-gapped operation still requires an authenticated supply chain and local
recovery procedures. Checksums do not authenticate an untrusted file and checksum
supplied together.
