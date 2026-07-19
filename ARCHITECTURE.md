# Steward architecture

This document describes implementation boundaries for contributors. The
[user-facing architecture](docs/concepts/architecture.md) explains the same system
from an operator's perspective.

## Product contract

Steward is the open-source agent application runtime and enforcement plane between
an untrusted containerized AI agent and managed external authority. It owns:

- a portable, versioned application contract for qualified agent runtimes;
- deterministic, explainable agent placement artifacts;
- state-snapshot fork lineage and bounded lifetime declarations;
- signed workload and site-policy admission;
- Docker and gVisor workload execution;
- tenant and instance lifecycle fencing;
- mediated inference, service, connector, and HTTP(S) egress;
- exact one-use action and service-task permits;
- credential injection outside the workload;
- signed Executor and Gateway evidence;
- outbound node control through public protocols; and
- offline verification.

Steward does not own model serving, agent reasoning or prompt graphs,
general-purpose cluster scheduling, secret storage, single sign-on,
software-provenance issuance, or arbitrary computer use.

## Dependency invariant

The Go module has no third-party or private dependency. Every production binary is
built from this repository and the Go standard library:

```console
go list -m all
```

must print only `github.com/hardrails/steward`.

React and Vite are build-time dependencies for the embedded Control console. Their
compiled static output is committed and embedded into `steward-control`; Node.js
is not a production runtime dependency.

CUE and OPA are optional operator-side tools. `stewardctl agent` executes them as
separate bounded processes when a CUE definition or OPA bundle is explicitly
selected. Their JSON output is treated as untrusted. Neither tool is linked into
Executor, Gateway, Control, or the Go module, and neither can weaken native
admission or runtime safety floors.

## Processes

### steward-executor

Executor is the node's workload authority and the only long-running Steward
process with Docker-group membership.

Responsibilities:

- authenticate local and uplink callers;
- verify capsule, site policy, tenant intent, and OCI identity;
- enforce resource and tenant capacity;
- create, start, stop, destroy, and reconcile Docker workloads;
- require `runsc` and hardened container settings;
- maintain generation, sequence, policy-epoch, and admission fences;
- expose bounded status, logs, egress statistics, and evidence;
- sign hash-linked lifecycle receipts; and
- poll Steward Control for signed commands.

Executor must not become a general command runner. Docker operations are finite
typed protocol actions.

### steward-gateway

Gateway mediates all supported positive network capabilities.

Responsibilities:

- map admitted grants to inference, services, connectors, and egress policy;
- hold reusable upstream credentials outside workloads;
- verify service-task and action permits;
- maintain spend-before-network replay state;
- enforce request, response, concurrency, call, byte, and time limits;
- strip ambient authorization and proxy headers;
- prevent configured credential reflection;
- record signed action and task evidence; and
- expose a root-only Unix control socket plus workload-facing listeners.

Gateway is trusted. Its configuration and credential roots never enter the agent
container.

### steward-relay

Relay is a small fixed-destination helper placed in one workload capability
network. It contains no general proxy configuration, secret, signing key, or
policy engine. Executor builds or pins its image and fixes its destination.

### steward-control

Control is the optional customer-operated fleet plane.

Responsibilities:

- create tenant records and scoped operators;
- issue one-time node enrollment;
- authenticate outbound node polling;
- retain exact signed command envelopes and terminal projections;
- expose bounded node, command, credential, capacity, and attention inventory;
- retain bounded Executor evidence deltas;
- sign evidence checkpoints with a key distinct from node receipt keys; and
- serve the embedded React console.

Control does not need tenant command, task, or action private keys. It does not
have Docker authority, store Gateway credential plaintext, or select arbitrary
workload code.

### stewardctl

The CLI is the operator and offline-verification surface. Its top-level command
set is task-oriented; detailed protocol controls may remain as subcommands.

Private keys are accepted only by explicit local signing operations. Context files
store paths to token files, never token values.

The `agent` command compiles and validates Hermes or OpenClaw application
definitions, records optional OPA policy decisions, explains deterministic node
placement, and derives new state-fork lineage. These are portable authorization
inputs. They do not give the CLI Docker authority or bypass signed Executor
admission.

### steward-mcp

The MCP stdio process adapts selected public clients to a bounded Model Context
Protocol tool surface. It is not embedded in the untrusted workload and does not
create new authority: configured token files determine node/control scope, while
task operations accept only pre-signed bundles.

### steward compatibility supervisor

The `steward` binary and `internal/runtime`, `internal/server`, and
`internal/uplink` packages implement the original generic lifecycle and uplink
contract. They remain a compatibility surface. New Control deployments use
Executor's signed command uplink.

Do not add product features to this compatibility path. New workload execution,
authority, and evidence behavior belongs in Executor and Gateway.

## Public protocols

### Node HTTP API

Executor's local HTTP API is the direct lifecycle contract used by `stewardctl`,
MCP, node diagnostics, and trusted host integrations. Every request body is bounded.
Error responses use one JSON shape. Any API change must update the OpenAPI contract
in the same commit.

### Executor uplink

The node initiates authenticated polling to Control. A command is a tenant-signed
DSSE envelope that binds node, tenant, instance, runtime reference, claim
generation, instance generation, sequence, kind, payload, issuance, and expiry.

Control transports exact bytes. Executor authenticates and interprets them. Durable
delivery state prevents replay across restart.

### Gateway service and connector APIs

Workloads reach Gateway only through their private Relay route and an admitted
grant. Gateway resolves logical IDs to operator configuration; the workload does
not choose an upstream origin or credential.

Service-task lifecycle routes use a signed exact request and stable task/permit
digests for submission, status, observation, and evidence recovery.

Connector routes can require an action permit. Permit verification binds current
runtime state, signed site policy, action authority, operation-policy digest,
request digest, task identity, expiry, and optional influence context.

### Control API

Control exposes tenant, operator, enrollment, node, command, operations, attention,
credential-inventory, and evidence APIs. Operator bearer scope is enforced at the
server, not inferred by clients. Remote non-loopback listeners require TLS.

## Persistence

Steward uses bounded, purpose-specific files rather than a general database. Every
store has:

- a schema or format version;
- a maximum encoded size or record count;
- strict decoding;
- atomic replacement or append discipline;
- owner and mode validation where opened by path;
- explicit replay and rollback semantics; and
- tests for corruption and capacity exhaustion.

Do not replace a bounded store with an unbounded map, log, or request-controlled
path. Do not delete durable fences to recover availability without documenting the
security guarantee lost.

## Concurrency

The compatibility runtime tracker has one mutex protecting all indexes and
lifecycle transitions. Executor and Gateway stores use their own documented locks.
No protocol may perform a read-check-unlock-mutate sequence when a competing
request could invalidate the decision.

Run the race detector after touching runtime, dispatch, store, polling, or receipt
code:

```console
go test -race ./...
```

## Admission and isolation

Signed admission is the intersection of:

1. publisher capsule maximums;
2. site-root policy;
3. tenant and node-bound intent; and
4. current host capacity and runtime facts.

Executor never expands authority beyond those inputs. Admitted containers use
gVisor, fixed UID/GID, a read-only root, dropped capabilities,
`no-new-privileges`, bounded tmpfs, resource limits, no host mounts or devices,
and no published ports.

Network is `none` unless a positive capability requires a private isolated
network. Persistent Docker state requires an explicit dedicated-host compatibility
decision because portable local volumes have no reliable hard byte or inode quota.

## Authorized effects

Authorized Effects assumes the agent may be compromised.

The differentiating invariant is:

> Gateway performs no protected connector dispatch until it has authenticated
> exact authority for the current workload and durably spent the selected task.

The permit binds canonical request bytes rather than a natural-language summary.
Multi-party approval is a signature threshold over the same bytes. Context locking
can add the current connector-response history digest.

A dispatch with uncertain outcome is not retried as a new task. The same permit and
task identity are used for recovery, or the system reports `outcome_unknown`.

## Evidence

Executor and Gateway use independent Ed25519 receipt identities and hash-linked
chains. Content-free records bind decisions and canonical digests without retaining
raw prompts, request bodies, responses, result text, or secrets.

Offline verification authenticates the chain but requires an external last-good
checkpoint to detect presentation of an older valid prefix. Control's witness is a
separate trust domain and does not turn compromised node keys into hardware
attestation.

## React console

The console source is under `internal/controlplane/console/src`; compiled assets
under `dist` are embedded into Control.

Security invariants:

- no remote assets, fonts, analytics, or telemetry;
- a restrictive Content Security Policy;
- same-origin API paths only;
- operator bearer held only in JavaScript memory;
- automatic clearing on page hide and idle/absolute timeout;
- no secret plaintext or private signing key;
- GET operations plus the exact signed-command courier mutation; and
- bounded file parsing and explicit reauthentication for command transfer.

A browser extension or compromised operator device remains trusted.

## Secret materialization

Steward owns a provider-neutral filesystem handoff, not a vault client. The
`secretmaterial` package validates a non-secret manifest, protected directory and
file identity, permissions, stable reads, purpose, and expected rotation epoch.

Provider-specific authentication, storage, renewal, recovery, replication, and
audit belong to an operator-selected system. Avoid adding a provider SDK or
configuration compiler unless the generic handoff cannot express a demonstrated
enforcement need.

## Deferred decision: computer use is a separate worker, never in-process

Computer use is intentionally outside every Steward process.

First, desktop automation requires large platform-specific dependencies and broad
host access, which conflicts with the zero-dependency and closed-runtime
invariants. Second, a worker that can control a browser or desktop is itself a
powerful authority boundary. Embedding it in Executor, Gateway, Control, MCP, or
the compatibility supervisor would collapse isolation between protocol enforcement
and arbitrary effects.

A future computer-use integration must run as a separately isolated worker with a
finite public protocol. Steward may mediate exact task authority, credentials,
network access, and evidence around that worker, but must not execute arbitrary
desktop actions in-process.

## Buy-versus-build boundaries

Steward uses these ownership rungs:

- `in-house`: the portable agent contract, narrow explainable placement, fork
  lineage, exact workload admission, generation fences, exact permits, durable
  spend, credential mediation, and signed enforcement evidence. These are the moat.
- `native-platform`: Docker, gVisor, systemd, Linux users, filesystem permissions,
  TLS primitives, HTTP, JSON, and cryptography supplied by Go and the operating
  system.
- `open-source`: CUE, OPA, and operator-selected identity, secret storage,
  telemetry, provenance, and model-serving systems connected through narrow
  contracts.
- `do-nothing`: general-purpose scheduling, visual workflow builders, agent
  catalogs, release promotion
  coordinators, secret vaults, and workflow engines until a demonstrated customer
  enforcement requirement cannot be composed from existing systems.

## Verification before commit

```console
gofmt -l .
go vet ./...
go build ./...
go test ./...
go test -race ./...
go list -m all
bash scripts/check-docs-consistency.sh
```

The console also requires:

```console
cd internal/controlplane/console
npm run check
npm run build
```

Commit the rebuilt embedded assets whenever source changes.
