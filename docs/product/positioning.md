---
title: Why Steward exists
description: "Steward's product direction: operator-controlled local admission, credential-brokered operations, tenant-bound commands, and offline-verifiable receipts."
section: Product
---

# Why Steward exists

> This page describes shipped behavior. Proposed hardening is listed separately in
> [current limitations]({{ '/limitations/' | relative_url }}#runtime-hardening-still-ahead).

Autonomous agents are useful because they can act: run code, retain state, call
models, and offer services. Before an agent starts, an operator must know which
tenant it serves, which artifact may run, which capabilities it may receive, and
what the local runtime will enforce.

A sandbox isolates a workload, but does not explain why that workload was
authorized, which tenant approved one sensitive request, or whether that request
was replayed. Steward connects local admission and exact task authority to a
constrained workload and records receipts that the operator can verify without
contacting a vendor.

## The operator outcome

After preparing a Docker and gVisor host and importing the required artifacts, an
operator can:

1. self-host the bundled controller, create tenants and scoped operators, enroll
   nodes once, and inspect bounded fleet inventory without a vendor service;
2. deliver an exact tenant-signed command while keeping the signing key outside
   the controller and node;
3. admit a signed, immutable agent profile for one tenant, node, and instance;
4. require that profile to comply with site-root-signed policy, per-workload
   resource limits, and host/tenant aggregate memory, CPU, PID, and
   workload-count caps;
5. run the agent in a tenant-labelled, gVisor-sandboxed Docker workload with
   no default network access, while granting only approved state, inference,
   service, exact connector operations, or named HTTP(S) routes, and optionally
   require an off-node tenant authority to sign the exact request for selected
   agent-service or connector operations; and
6. export a node-local, tamper-evident receipt of the accepted inputs and recorded
   enforcement decisions. Tamper-evident means changes within the supplied chain
   can be detected; detecting removal of a complete suffix requires an independently
   retained exact head. It does not mean the host cannot replace the entire chain.

The operator keeps control of keys, policy, artifacts, infrastructure, and
evidence when external services are unavailable. Steward does not rely on the
agent's own account of its behavior.

## The control path

```text
publisher-signed profile capsule
              +
site-root-signed local policy
              +
authenticated tenant instance intent
              |
              v
trusted signer -> exact signed command -> Steward Control -> node outbound poll
                                                    |
                                                    v
       Steward admission and generation fence
              |
              v
gVisor workload + optional dedicated-host state + per-instance trusted relay
              |
              v
optional service-scoped task permit -> Gateway durable authorization -> agent
optional connector action permit    -> Gateway durable authorization -> upstream
              |
              v
node-local signed, hash-linked enforcement receipt
```

Each input has a separate purpose:

- A **profile capsule** is a publisher-signed description of an immutable image
  and the maximum capabilities of a reusable agent profile. It contains no secret,
  raw upstream URL, arbitrary host path, Docker option, or caller-selected
  privilege.
- A **site policy** is signed by the operator's site root key. It limits publishers,
  tenants, profiles, repositories or exact image digests, resources, inference
  routes, services, connector IDs, egress routes, and publisher revocation state.
- An **instance intent** is a separately authenticated command to run a profile for
  a tenant, node, and instance. A generation fence—an increasing counter keyed by
  `(tenant_id, instance_id)`—prevents an older command from replacing newer state.
- A **task permit** is a tenant-key-signed, short-lived statement for one exact
  configured service request. Signed site policy scopes that public key to explicit
  service IDs; the private key remains off-node. The permit cannot add a capability
  that the profile, site policy, intent, and active grant did not already allow.

Steward grants only what all three inputs allow. A trusted publisher can authorize
a profile and its maximum capabilities, but cannot choose a tenant's schedule or
identity.

## A receipt is not an agent transcript

The lifecycle receipt records evidence from controls Executor can enforce. It binds the
tenant, runtime reference, capsule and policy digests, instance generation,
lifecycle event, and outcome from a fixed vocabulary. When Gateway authority is
present, the admission commit also stores the effective route-policy digest. The
lifecycle chain does not embed the full instance intent, state or service
selection, actual Gateway grant ID, or individual Gateway traffic decisions.
HTTP(S) egress decisions use a separate unsigned newline-delimited JSON (JSONL)
audit log. Connector and service-task authorizations and terminal outcomes use a
separate Gateway-signed, hash-linked chain. Permit-backed records bind the authority
key ID, exact signed envelope, and request digests to the stable task call and
terminal outcome. Service-task records may retain the run ID observed from the
agent, but that value is untrusted application output. Both receipt chains exclude prompts, model
responses, agent logs, the meaning of agent actions, credentials, and bodies.

This gives an auditor a bounded question they can answer locally: *what did
this node accept and record?* It does **not** prove that a model was honest,
that an agent's explanation was true, that an upstream service behaved as
claimed, or that every semantic action inside a container was safe.

For exact service tasks, replay prevention is node-local and lasts only while the
same signed Gateway ledger and epoch are retained. It is an at-most-once dispatch
claim, not exactly-once execution across nodes or inside an upstream system. An
unknown outcome stays spent because a duplicate effect is worse than visible
ambiguity.

The receipt is tamper-evident only within the supplied chain and documented node
trust boundary. The host root user, host kernel, Docker, gVisor, signing-key
protection, and operator configuration remain trusted. Steward does not claim
hardware attestation (proof tied to hardware state), protection from a hostile host
administrator, cross-node anchoring, detection when all trailing records are
removed without an external checkpoint, or formal certification. Executor holds
the lifecycle receipt key. Gateway holds a different connector receipt key and
also performs the network effect that key records. Neither key is isolated in a
separate signing service.

## Capabilities require explicit grants

Steward enforces five optional, explicitly granted capabilities. A signed request
does not enable a capability by itself. If the required local components are
missing, admission fails closed:

- **State**: an executor-owned Docker volume scoped to a tenant and lineage. A
  lineage is the persistent-state identity shared across approved workload
  replacements. The volume uses a fixed profile path, is not a host bind mount or
  encrypted by Steward, and remains readable by a trusted host administrator.
  Docker's portable local volume driver has no hard byte or inode quota, so state
  is disabled by default and may be enabled only in dedicated-host compatibility
  mode.
- **Inference**: one logical route resolved by a local gateway. The gateway
  adds the upstream credential at the last hop. Steward does not directly
  configure, mount, or inject that credential into the workload, and exposes no
  general-purpose inference proxy.
- **Service**: one declared agent port reached through the paired relay and an
  authenticated local gateway. The endpoint does not provide tenant end-user
  authentication or public exposure. For configured JSON POST operations, signed
  site policy can scope a tenant task key to the service. Gateway then requires one
  short-lived permit for the exact request, writes authorization before dispatch,
  and refuses automatic retry after an ambiguous outcome.
- **Connector**: named HTTP operations whose exact upstream origin, method, path,
  credential mode, address policy, concurrency, call count, byte limits, and
  duration are fixed by the node operator. Steward directly gives the workload a
  logical operation endpoint, not the configured upstream credential, private
  origin, or a general authenticated proxy. A durable task claim and call budget
  are spent before Gateway opens the upstream request. Per connector, the operator
  can additionally require a short-lived permit signed by a tenant-scoped off-node
  action key for the exact admitted instance, operation, task, and request bytes.
- **Egress**: named HTTP(S) routes allowed by the publisher capsule, tenant policy,
  and instance intent, then mapped by the host operator to hostnames, ports,
  verified IP addresses, concurrency limits, byte limits, and time limits. The
  agent receives a standard proxy, not a raw network interface. Layered denial
  limits bound synchronous audit work at grant, tenant, and host scope.

Gateway rejects the exact connector credential in upstream response headers and the
decoded body stream. Inference and connector upstreams remain trusted not to encode
or transform authentication material, disclose private origin details, or return
other application secrets. These grants isolate how Steward supplies authority;
they are not general response data-loss-prevention filters.

The non-secret action-trust inventory used by the signer is unsigned. Operators
must authenticate it when moving it off-node. It prevents common issuance mistakes;
it is not a grant and does not replace Gateway's live enforcement decision.
A service-trust inventory has the same boundary: it is tenant-specific signing
preflight, not an authorization artifact.

These contracts include lifecycle ordering, drift inspection, journaling, and
explicit state purge with a receipt. When the observed outcome of a failed mutation
is known, Executor can compensate. When the outcome is ambiguous, it retains the
prepared journal entry, degrades readiness, and blocks conflicting work instead of
claiming rollback. Steward provides no raw TCP/UDP,
transparent interception, default-allow route, TLS interception, browser
automation, interactive shell, device grant, arbitrary environment variable, or
caller-controlled host mount. Excluding these paths keeps each grant bounded and
reviewable.

## What Steward is not trying to replace

Steward is not an agent framework, workflow designer, model router, browser
service, generic sandbox API, or hosted control-plane service. The bundled
self-hosted controller is deliberately not an enterprise identity provider,
approval system, placement scheduler, desired-state reconciler, or fleet user
interface. Steward does not host models, inspect prompts, calculate token costs,
design multi-agent workflows, or make semantic claims about agent behavior.

Existing sandboxes and agent platforms can complement Steward. Steward addresses a
specific question: can a customer-operated node enforce a locally authorized
deployment, narrow selected external effects—including an agent-service task—to one
independently signed request, prevent a second node-local dispatch within the
retained ledger epoch, and produce portable evidence of that enforcement while
disconnected?

An open-source or self-hosted fleet controller is not unique to Steward. The
differentiator under evaluation is the complete authorization-to-enforcement path:
controller-blind tenant keys, node-local signed admission, durable replay fences,
and evidence that remains verifiable offline.

Among the systems in the dated comparison, no reviewed product documents the same
combination of a customer-operated air-gapped fleet controller and nodes,
site-signed artifact and tenant admission, controller-blind tenant signing keys,
service-scoped off-node task keys, exact-request dispatch, durable delivery and
node-local replay control, and offline-verifiable authorization-to-outcome receipts.
This is a limited statement about linked public documentation, not a claim that
Steward is first, unique, certified, or immune to defects.
See the [market analysis]({{ '/product/market-analysis/' | relative_url }}) for a
dated comparison and its limits.

## Operator responsibilities

Steward identifies the artifact, limits capabilities, verifies local policy, and
records evidence before an agent receives authority. Operators must still patch
hosts, review artifacts, protect signing keys, authenticate users at the local
service gateway, and choose an isolation level appropriate to the environment.

For the exact threat assumptions, see the [security model]({{ '/concepts/security-model/' | relative_url }}).
