---
title: Why Steward exists
description: "Steward's product direction: outcome-led signed agent releases, operator-controlled local admission, tenant-bound commands, independently witnessed evidence, and offline verification."
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

An agent can also receive attacker instructions through ordinary calendar, email,
web, document, memory, or tool content. Asking the same model to detect or review
the attack is not a complete authorization boundary. For managed connector calls,
Authorized Effects assumes the agent is compromised and requires an independently
signed exact request outside the workload.
For selected connectors, policy can also require that approval to name the current
signed history of completed connector responses. A later response invalidates the
old approval instead of letting it survive a change in the agent's managed
external context.

## The operator outcome

After preparing a Docker and gVisor host and importing the required artifacts, an
operator can:

1. authenticate a curator-signed offline catalog, search or compare outcome-led
   releases, and inspect the exact signed capsule resources, capabilities,
   validity, services, state, and companion artifact identities before selection;
2. self-host the bundled controller, create tenants and scoped operators, enroll
   nodes once, inspect secret-free inventories, and view deterministic
   action-required and capacity summaries without a vendor service;
3. optionally expose authenticated, fixed-cardinality operational metrics without
   exporting tenant, node, credential, or command identifiers;
4. deliver an exact tenant-signed command while keeping the signing key outside
   the controller and node;
5. select a publisher-signed qualified Hermes outcome, verify its exact offline
   archive, activate it through a fixed node-local state machine, authorize the
   deterministic canary with an off-node tenant key, and retain the correlated
   evidence for offline review;
6. admit a signed, immutable agent profile for one tenant, node, and instance;
7. require that profile to comply with site-root-signed policy, per-workload
   resource limits, and host/tenant aggregate memory, CPU, PID, and
   workload-count caps;
8. run the agent in a tenant-labelled, gVisor-sandboxed Docker workload with
   no default network access, while granting only approved state, inference,
   service, exact connector operations, or named HTTP(S) routes, and optionally
   require an off-node tenant authority to sign the exact request for selected
   agent-service operations, or require Authorized Effects for selected connectors
   with no generic egress, durable one-use spend before DNS, and credentials kept
   outside the workload; context-locked policy can additionally require every
   permit to match the grant's current signed connector-response history;
9. optionally compile a non-secret OpenBao KV v2 plan into exact read policy,
   fail-closed Agent templates, expected-version readiness, and a systemd sandbox,
   while keeping storage, bootstrap authentication, recovery, provider tokens, and
   rendered values outside the controller, MCP, evidence, and React surfaces;
10. publish bounded signed receipt deltas to the customer-owned controller on an
   independent loop, so the controller can retain one exact checkpoint and make an
   authenticated rollback or equivocation finding sticky without becoming a
   receipt warehouse; and
11. inspect or export the controller's witnessed state under a separate stable
   witness key, while retaining the full node-local receipt chain for detailed
   offline verification.

Tamper-evident means changes within a supplied chain can be detected. The
controller witness also detects a lower or conflicting head when the node next
reports relative to the exact head it retained. It does not prove that the host
was uncompromised when it signed a record or that evidence remains fresh when a
node stops publishing.

The operator keeps control of keys, policy, artifacts, infrastructure, and
evidence when external services are unavailable. Steward does not rely on the
agent's own account of its behavior.

The agent release makes a qualified outcome understandable and portable, but it
does not grant runtime authority. The activation plan and final proof are also
unsigned correlation records. Site policy, instance intent, live admission, task
permits, receipt chains, and the controller witness export remain the signed
authority and evidence. The append-only activation workspace prevents compliant
retries from rewriting generated history; it does not attest a hostile host.
The catalog adds local discovery and comparison, not another authority: its
curator signature authenticates descriptive inventory, while exact artifact
allowlists, site policy, tenant intent, and live admission decide what can run.
The current qualified Hermes and OpenClaw activation recipes require a dedicated host with exactly one
policy tenant because its persistent Docker volume has no hard byte or inode
quota. It does not weaken Steward's separate stateless shared-host boundary.

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
optional service-scoped task permit   -> Gateway durable authorization -> agent
authorized connector exact authority -> Gateway durable spend before DNS -> upstream
              |
              v
node-local signed, hash-linked enforcement receipt
              |
              +-- bounded signed evidence uplink (asynchronous)
                                      |
                                      v
                  controller checkpoint or sticky finding
                                      |
                                      v
                       witness-signed offline export
```

Each input has a separate purpose:

- A **profile capsule** is a publisher-signed description of an immutable image
  and the maximum capabilities of a reusable agent profile. It contains no secret,
  raw upstream URL, arbitrary host path, Docker option, or caller-selected
  privilege.
- A **site policy** is signed by the operator's site root key. It limits publishers,
  tenants, profiles, repositories or exact image digests, resources, inference
  routes, services, connector IDs, egress routes, publisher revocation state, and
  optional or required connector-scoped Authorized Effects keys and approval threshold.
- An **instance intent** is a separately authenticated command to run a profile for
  a tenant, node, and instance. A generation fence—an increasing counter keyed by
  `(tenant_id, instance_id)`—prevents an older command from replacing newer state.
- A **receipt identity** is a node-held Ed25519 key proven during one enrollment
  exchange and pinned to the controller, enrollment, and control-node identity.
  The controller rejects reuse of that receipt identity by another node.
- A **task permit** is a tenant-key-signed, short-lived statement for one exact
  configured service request. Signed site policy scopes that public key to explicit
  service IDs; the private key remains off-node. The permit cannot add a capability
  that the profile, site policy, intent, and active grant did not already allow.
- An **authorized-effects permit** is a tenant-key-signed statement for one exact
  connector request, or a bounded bundle of up to eight exact requests. Signed
  policy pins each key and the required approval count to connector IDs. Bundle
  signers must cover every named connector. Explicit intent selects the mode;
  Gateway forbids generic egress and spends each selected task before DNS. The
  bundle is an unordered set, not a workflow: the agent may use any subset in any
  order, but cannot invent or alter an effect.

Steward grants a workload only the intersection of the profile capsule, site
policy, and instance intent. A trusted publisher can authorize a profile and its
maximum capabilities, but cannot choose a tenant's schedule or identity. Receipt
identity authenticates evidence, while a task permit can narrow one already
granted operation but cannot add a capability.

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
agent, but that value is untrusted application output. Authorized connector
records additionally bind the explicit mode and exact operation policy in format
5. Format 6 also binds a multi-party threshold and canonical signer set. Both receipt chains exclude prompts, model
responses, agent logs, the meaning of agent actions, credentials, and bodies.

When evidence uplink is enabled, Executor publishes receipt checkpoints on a loop
independent from command polling. Each receipt-key proof binds the controller's
polled base, the reported head, and the exact submitted frame count and digest.
The controller verifies the bounded delta and retains only the last-good
coordinate, exact last batch identity, and first authenticated rollback or
equivocation finding. A site administrator can inspect that state or export it
under the controller's separate witness key. Full receipt records remain on the
node. The inspection state is exactly `unwitnessed`, `current`,
`rollback_detected`, or `equivocation_detected`; it is not a unified health,
freshness, or action-required status by itself. The controller's separate
operations view combines that retained state with in-memory report recency, node
contact, command delivery, and capacity thresholds. Those findings are derived
facts, not mutable tickets or automatic recovery decisions.

This gives an auditor a bounded question they can answer locally: *what did
this node accept and record?* It does **not** prove that a model was honest,
that an agent's explanation was true, that an upstream service behaved as
claimed, or that every semantic action inside a container was safe.

For exact service tasks, replay prevention is node-local and lasts only while the
same signed Gateway ledger and epoch are retained. It is an at-most-once dispatch
claim, not exactly-once execution across nodes or inside an upstream system. An
unknown outcome stays spent because a duplicate effect is worse than visible
ambiguity.

The receipt remains bounded by node trust. The host root user, host kernel, Docker,
gVisor, signing-key protection, and operator configuration are trusted. The
controller witness detects a lower or conflicting head when the node next reports
relative to the exact head it retained. It does not prove freshness when
publication stops, prove that a hostile host recorded true events, provide
hardware attestation (proof tied to hardware state), or detect different views
presented to independent controllers unless their exports are compared.

Executor holds the lifecycle receipt key. Gateway holds a different connector
receipt key and also performs the network effect that key records. Steward Control
holds a purpose-separated witness key used only for controller evidence exports.
These keys are software-held and are not isolated in separate signing services.

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
  can additionally require a short-lived permit signed by one or more
  tenant-scoped off-node action keys for the exact admitted instance, operation,
  task, and request bytes.
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
approval system, placement scheduler, desired-state reconciler, or general
fleet-management interface. Its embedded console is a bounded observation-first
projection of the control API with one exact signed-byte courier. It can transport
an already authorized command but cannot create, edit, sign, approve, or widen
authority, and it is not a remediation workflow. Steward does not host
models, inspect prompts, calculate token costs, design multi-agent workflows, or
make semantic claims about agent behavior.

Existing sandboxes and agent platforms can complement Steward. Steward addresses a
specific question: can a customer-operated node enforce a locally authorized
deployment, narrow selected external effects—including an agent-service task—to one
independently signed request, prevent a second node-local dispatch within the
retained ledger epoch, and let a separate customer-owned controller retain and
sign a bounded evidence checkpoint without becoming an enforcement dependency?

An open-source or self-hosted fleet controller is not unique to Steward. The
differentiator under evaluation is the complete authorization-to-enforcement path:
controller-blind tenant keys, receipt-key proof during enrollment, node-local
signed admission, durable replay fences, independent rollback/fork witnessing, and
evidence that remains verifiable offline.

Among the systems in the linked comparison, no reviewed product documents the same
combination of a customer-operated air-gapped fleet controller and nodes,
receipt-key-bound enrollment, publisher-signed artifacts, site-root-signed policy,
authenticated tenant intent,
controller-blind tenant signing keys, service-scoped off-node task keys,
exact-request dispatch, durable delivery and node-local replay control,
independently retained divergence findings, and offline-verifiable
authorization-to-outcome evidence. This is a limited statement about linked public
documentation, not a claim that Steward is first, unique, certified, or immune to
defects.
See the [market analysis]({{ '/product/market-analysis/' | relative_url }}) for a
source-backed comparison and its limits.

## Operator responsibilities

Steward identifies the artifact, limits capabilities, verifies local policy, and
records evidence before an agent receives authority. Operators must still patch
hosts, review artifacts, protect signing keys, authenticate users at the local
service gateway, and choose an isolation level appropriate to the environment.

For the exact threat assumptions, see the [security model]({{ '/concepts/security-model/' | relative_url }}).
