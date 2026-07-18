---
title: Steward capability boundaries
description: Exact Steward guarantees, signed HTTP(S) egress controls, residual risks, and deliberately unavailable authority.
section: Capability boundary
---

# Steward capability boundaries

Steward verifies profile capsules and site policy as Ed25519-signed DSSE (Dead
Simple Signing Envelope) documents. It binds commands to a tenant, node, and
instance; rejects stale policy and generations; durably journals host changes; and
creates signed, hash-linked receipts for offline verification. Optional capabilities
include inference, a private service, credential-brokered connector operations,
tenant-signed exact service tasks, deny-by-default HTTP(S) egress, command-line and Model Context Protocol (MCP)
operations, Terraform bootstrap, and a fixed proof-carrying activation path for
one qualified Hermes canary. An operator-side coordinator can apply that same
closed activation contract to an explicit remote node list with a first-node canary
and operator-approved later batches. Persistent
state is available only through the dedicated-host compatibility mode described
below.

## What a receipt means

A valid chain shows that the corresponding Executor or Gateway node key signed the
supplied Steward enforcement records. Verification detects internal gaps,
reordering, changes, and an incomplete final record. Executor records bind capsule
and policy digests, tenant, runtime reference, generation, decision type, and
outcome. Gateway service-task records bind the public task authority, exact permit
and request digests, service policy, dispatch result, and observed run ID.

It does not prove prompt meaning, model output, agent intent, tool meaning, useful
work, or upstream behavior. The service supplies its run ID, so that value is not
independent proof of execution. Raw prompts and request bodies are absent. The
chain also cannot reveal when someone removes every record
after an older valid point. To detect that rollback, store the last verified
sequence and chain hash separately. Without a Trusted Platform Module (TPM),
trusted execution environment (TEE), or external checkpoint, a hostile host root
user can replace the key, log, and software together. Receipts are tamper-evident
only within the documented node trust boundary.

Steward fully verifies the receipt chain when it opens the log. While that handle
remains open, it holds an exclusive writer lock, checks that the configured path
still names the same owner-only file, and authenticates the final sparse segment
before reading the head or appending. It does not reread every cold segment for
each operation. A process with the same host identity can bypass advisory locks,
rewrite old bytes, restore file metadata, and read the receipt key; protecting
against that actor requires a separate host identity, immutable storage, a TPM or
TEE, or an external checkpoint.

Executor holds Docker authority and its lifecycle receipt key. Gateway has a
separate Unix identity and connector receipt key but also performs the connector
network effect it records. A compromise of either service can forge that service's
node-local receipts; neither key is isolated in a separate signer.

## Steward Control is a bounded single-writer service

The bundled controller stores tenant records, operator and node credential
verifiers, one-time enrollment state, node inventory, exact signed command bytes,
delivery leases, and terminal reports. It has no tenant private signing key and no
Docker socket. Executor still verifies each signature, node identity, tenant
policy, generation, sequence, and validity window.

This separation limits authority but does not make the controller untrusted. A
compromised site administrator can create tenants and operators, enroll or revoke
nodes, read fleet metadata, deny service, and submit or repeatedly offer any valid
signed command it possesses. Node replay fences prevent a stale accepted command
from becoming new authority, but a controller can delay a still-valid command. A
tenant operator can do the corresponding operations only inside its tenant scope.

The built-in durable store supports one active process. It uses an exclusive file
lock, bounded hash-chained write-ahead log and snapshot, but has no multi-replica
consensus, automatic failover, external database adapter, point-in-time online
backup, or cross-site replication. Stop the service and copy the whole owner-only
state directory as one unit. Health and readiness report local process and store
state; they are not a high-availability guarantee.

Default ceilings retain 256 tenants, 4,096 nodes, 16,384 credentials, 4,096
enrollments, and 16,384 commands, with smaller per-tenant and per-node caps.
Expired enrollments are reclaimed when another enrollment needs capacity. A
command with a known terminal outcome may be reclaimed only after its configured
minimum retention period, and only when another command needs capacity. Pending or
leased commands and commands reported as `failed` or `outcome_unknown` are never
reclaimed automatically.

Tenant, node, and credential records have no delete or compaction operation.
Revoking a node or credential disables its authority but retains its record, so it
continues to count toward the configured ceiling. A command reported as `failed`
or `outcome_unknown` also continues to consume command capacity. These choices
preserve audit and replay state, but a long-lived site must monitor record counts
and raise its configured ceilings before exhaustion. The operations summary,
attention view, and opt-in authenticated metrics expose retained-state usage and
capacity warnings. They do not add a purge path. Exceeding a cap fails the affected
request; it does not evict live or ambiguous authority silently.

The action-required view is derived from retained facts. It is not an incident
tracker, approval queue, or automatic remediation engine. A caller cannot
acknowledge, dismiss, retry, or clear a finding through that view. Evidence-report
freshness is intentionally held in bounded process memory rather than the durable
control format. After a controller restart, evidence age is conservatively stale
or unknown until each node reports again. The signed checkpoint and sticky
rollback or equivocation finding remain durable.

Operator and node bearer credentials have no automatic expiry. Enrollment
capabilities expire and permit one logical exchange, with exact retries returning
the same node credential. Long-lived bearers must be rotated and revoked
explicitly. A site administrator can revoke one node credential during a staged
rotation without disabling the node or its replacement credential.

## The embedded console has one narrow mutation

`/console/` reads the existing control operations API and can submit one exact
offline-signed Executor command. The browser previews the envelope without
verifying its signature, calculates the exact file digest, requires a typed
confirmation and re-entry of the current bearer, and sends the unchanged bytes to
the existing bounded command endpoint. It cannot create or edit a command, sign,
hold a private key, create or widen policy, enroll, revoke, retry, acknowledge,
dismiss, export, or delete. It is not an incident tracker, approval workflow,
secret manager, or replacement for Executor verification or offline evidence
verification. Page limits also mean a visible table may be only the first bounded
page; the interface says when an API cursor has more records.

The static assets are available to anyone who can reach the control listener;
fleet data still requires the existing scoped operator bearer. The interface being
observation-first does not narrow that bearer's authority outside the interface. A browser
extension or compromised browser that steals a site-administrator credential may
use the control API directly for every operation that credential authorizes.
It may also replace a loaded file with another valid signed command it possesses.
Comparing the displayed digest with the signing station helps with accidental
substitution, but cannot make a compromised display trustworthy.

The bearer stays out of cookies and browser storage and is cleared from application
memory on lock, `pagehide`, 15 minutes idle, or the eight-hour absolute deadline.
Those client-side controls neither revoke the server credential nor protect it from
the browser process, extensions, host inspection, or screen capture. A dedicated
hardened operator profile remains required.

Embedded same-origin assets, restrictive response headers, and the automatic exact
Host gate reduce external asset, framing, and DNS-rebinding exposure. They do not
provide a second network or identity boundary and do not make a compromised
controller host safe. The committed bundle removes npm and Node.js from normal and
air-gapped Go builds, but maintainers who rebuild it still trust the lockfile-pinned
React, Vite, Node.js, and package-registry supply chain.

## Secret materialization composes with OpenBao; it is not a native vault

Steward does not store encrypted secrets, operate OpenBao, unseal it, manage its
high availability, deliver AppRole bootstrap material, configure production audit,
or recover its data. The optional compiler supports exact OpenBao KV v2 paths,
AppRole file auto-auth, Linux systemd, and owner-only Gateway value files. Other
engines, auth methods, init systems, and providers must implement the same
filesystem handoff independently.

Rendered values are plaintext in the protected destination and Gateway memory. The
materializer, Gateway, host root, node filesystem, and OpenBao transport remain
trusted. A single node materializer can read every exact path in its generated
policy; use narrower node or tenant service boundaries when compromise separation
requires them.

The value and version marker are separate Agent templates. Readiness verifies each
stable file and detects an unexpected marker, but it does not prove atomic render or
cryptographically bind value bytes to a KV version. Rotation requires an operator
to drain grants, use provider check-and-set, compile and review the new expected
version, wait for convergence, validate Gateway, and reload. Steward Control, MCP,
and the React console do not receive or mutate materializer state or secret values.

The hardened AppRole handoff removes a one-use SecretID after authentication.
Consequently, an Agent crash or planned restart needs a freshly issued SecretID;
the generated unit rate-limits failed restart attempts but cannot retrieve bootstrap
authority for itself. Persistent rendered values can keep Gateway available while
the materializer is down, but rotation stops until authentication is restored.

## Signed admission is opt-in

The host-control `/v1/workloads` endpoint is available only without signed
admission. Enabling signed admission disables all unsigned provisioning, including
legacy outbound `provision` commands. Executor enables `/v1/admissions` only with
complete signed policy, site-root public key, node identity, durable fence and
journal paths, and an evidence private key. Partial configuration stops startup.
An operator must initialize a fence once; startup never recreates a missing fence.

The packaged Executor exposes a bearer-protected loopback API for `stewardctl node`
and `steward-mcp`. A control plane can send `admit` through the authenticated
Executor uplink. Local admission and activation-checkpoint calls also require the
explicit host-admin-intent flag. The local token grants host-administrator
authority, not tenant authentication.

## Proof-carrying activation is deliberately narrow

The signed agent release and activation flow supports one closed, fresh-state
Hermes workspace-audit canary. It is not a hosted catalog, general workflow engine,
arbitrary command runner, or proof framework for user-defined prompts and hooks.

The offline agent catalog is a curator-signed descriptive index. It re-verifies
the exact embedded releases and exposes signed capsule metadata for local search
and comparison, but it does not grant deployment authority, install packages,
rank agents, detect malicious instructions, or prove a skill is safe. Steward does
not track the highest catalog revision in durable state. Operators must distribute
the curator public key independently and retain the accepted catalog ID, revision,
and envelope digest to detect rollback or conflicting revisions.

The recipe requires a dedicated host, a signed policy containing exactly one
tenant, `-admission-allow-host-admin-intent`, and
`-allow-unquotaed-state-on-dedicated-host`. The local token therefore has
host-administrator authority, and the Hermes state volume has no hard byte or
inode quota. The coordinator rejects a multi-tenant policy. Steward's stateless
shared-host isolation remains available outside this recipe.

The signed release binds outcome text, an embedded capsule, exact offline archive,
qualification-evidence digest, fixed canary, and limitations. It does not prove the
outcome occurred and grants no tenant, node, image-import, capability, or task
authority. The qualification evidence and exact skill manifest remain external
artifacts that the operator must authenticate and inspect.

The activation plan, canary challenge, state checkpoints, and final proof manifest
are bounded correlation records, not signatures. Authenticity comes from the
separately verified release, capsule, task permit, Executor and Gateway receipt
chains, controller witness export, and externally pinned public keys. A proof file
without those companions proves no execution or authority.

The `release_verified` state is only a local resumability checkpoint. It is not
historical authorization evidence. Final collection and offline verification
re-evaluate the release, capsule, site policy, retained intent, and exact task at
Gateway's signed authorization-receipt time.

The owner-only activation workspace creates generated artifacts once and appends
sequential state checkpoints. This prevents an ordinary retry or second compliant
coordinator from overwriting prior generated history. Its lock is advisory, and
the workspace is not protected from host root or another process with the same
operating-system authority. Verify authenticated copies on a separate trusted
system when node compromise is in scope.

Activation uses signed receipt order instead of comparing independent Gateway and
controller clocks. After authority, policy, and read-only admission preflights
pass, Executor records a content-free `activation_begin` marker before the
admission-allow receipt, mutation journal, or host mutation. After Steward
verifies Gateway's authorization, dispatch, and terminal receipts, it records a
content-free `activation_checkpoint`. The final controller witness must cover this
order:

`activation_begin` → fresh admission allow → admission commit → runtime start →
`activation_checkpoint` → final witness head

The live Executor log check allows unrelated tenant suffix receipts but rejects
later receipts for the same activation and matching lifecycle-invalidating
events. This causal join is not a cross-system trusted timestamp or hostile-host
attestation. Host root can still replace local logs and keys together before
evidence is copied off-node.

`activation run` is resumable and idempotent against retained checkpoints while
the applicable deadline remains open. Transient local file, Docker, Executor,
Gateway, network, and incomplete evidence-source errors remain retryable after
the operator corrects the condition. The canary has one absolute deadline
anchored to the `canary_authorized` checkpoint. Submission recovery and terminal
observation share it; a retry does not reset it. Expiry becomes sticky
`action_required` with reason `canary_timeout` and cannot resume. An attached task
that fails the full activation binding, a terminal canary failure, and invalid or
conflicting retained evidence also become sticky `action_required`. Terminal
canary failures include a terminal submit rejection, a non-completed Hermes state,
and a completed result that fails the closed recipe. Retained-evidence failures
use reason `evidence_invalid` because a retry cannot replace write-once bytes. The
coordinator does not clear those states, mint replacement authority, or destroy
the failed workload. Recovery requires the operator to stop and destroy that
workload, create a new activation ID, and use an instance generation greater than
the failed activation.

The portable Executor evidence delta spans signed receipt coordinates rather than
filtering away chain links. Although the current recipe admits only one policy
tenant, the range can include unrelated node receipts or older retained history.
Executor receipt frames exclude prompts, request bodies, result bodies, and
workspace content. The activation workspace separately retains the bounded canary
result and should still be handled as sensitive operational evidence.

The controller does not own end-to-end activation. The implemented remote fleet
path uses an operator-side coordinator, protocol-4 bounded admission and canary
projections, exact signed commands, and site-admin evidence capture. Steward
Control still does not select targets, hold either private signing key, mint
replacement authority, or choose promotion and rollback. See
[agent activation]({{ '/guides/agent-activation/' | relative_url }}) for the
implemented `create`, `run`, `attach`, `status`, and offline `verify` procedure.

## Proof-carrying fleet rollout is deliberately narrow

One rollout binds one verified release, one signed policy, one tenant, and from 1
through 64 explicitly ordered unique nodes. Target 0 is the canary. Later batches
contain from 1 through 16 targets, are processed sequentially, and require a new
operator invocation before each batch. The complete rollout window is at most 24
hours and cannot exceed the capsule expiry.

The operator-side coordinator holds the command and Hermes task private keys in
memory while running. It retains exact generated artifacts and append-only state in
an owner-only workspace; it does not put either private key in the workspace or
controller. One common policy-authorized command key signs the exact plan and a
contiguous promotion chain. Each promotion binds the preceding batch's ordered
passed state, activation proofs, controller captures, and the next batch boundary;
the new batch's commands bind that promotion digest. Deterministic command IDs bind
each command kind to the rollout, target position, and node.

The plan file, target state, status, and aggregate proof are still unsigned
correlation records. Offline `rollout verify` must authenticate their signed
authorization and evidence companions, the complete copied workspace,
independently pinned publisher, site-root, and controller witness keys, and the
separately transferred exact OCI archive. The unsigned aggregate proof binds the
signed envelopes through `plan_authorization_digest` and ordered
`batch_promotion_digests`. Each target entry additionally binds the exact raw signed
admit, start, and canary command envelopes through `admit_command_digest`,
`start_command_digest`, and `canary_command_digest`. Its digest therefore commits
the exact retained plan, promotion, and outer-command authorization envelopes. The
signed chain attests the command signer's authorization sequence. It is not an
independently witnessed clock or host timeline and does not record human reasoning,
a change ticket, or an external approval quorum.

The workspace's file modes and advisory locks prevent ordinary compliant
overwrite, not hostile root. Its crash-recoverable publication requires
same-filesystem POSIX hard links, reliable file and directory `fsync`, reliable
`flock`, and stable Unix ownership and link counts. An unsupported or ambiguous
filesystem fails closed; Steward does not use a weaker fallback. Verify an
authenticated copy on a separate trusted system when coordinator compromise is in
scope.

Every target must already have the exact image imported. The coordinator does not
perform remote image transfer, registry pulls, placement, labels or selectors,
parallel target execution, maintenance scheduling, desired-state reconciliation,
arbitrary canaries, model scoring, A/B selection, or automatic rollback. The
current qualified agent recipes also require a dedicated host, exactly one policy tenant,
host-administrator admission, and explicitly enabled unquotaed persistent state.
It is not the shared-host multi-tenant execution path.

The coordinator exports but does not delete sealed controller captures. Completed
rollouts therefore consume the controller's finite 256-capture inventory until a
site administrator preserves and verifies the proof set, manually inventories each
retained node and capture ID, and deletes those controller recovery copies.

The first target must pass before any later target starts, and every target in the
current batch must pass before the next operator boundary. A rejection, terminal
canary failure, expired authority, revoked node, `outcome_unknown`, evidence
overflow, rollback or equivocation finding, or invalid retained evidence becomes
sticky `action_required`. Steward does not clear it, skip the target, stop or
destroy a workload, or roll back passed targets. Recovery requires an explicit
operator decision, new authority, a new rollout workspace, and for a replaced
activation a new activation ID with a higher instance generation.

The aggregate proof is an unsigned correlation record. Its digest commits the exact
retained plan authorization, ordered batch promotions, and per-target signed outer
Executor command envelopes (`admit`, `start`, and `activation-canary`), but does not
make the aggregate a signature. Authenticity comes
from the plan authorization, batch promotions, release, capsule, commands, task permit,
Gateway and Executor receipt chains, controller capture, and externally pinned
public keys. The proof establishes only the fixed workspace-audit fixture within
the documented host trust boundary. It is not evidence of arbitrary prompt or skill
safety, semantic correctness, an uncompromised host, or hardware attestation. See
the
[fleet rollout guide]({{ '/guides/fleet-rollout/' | relative_url }}) for the exact
workflow and air-gap verification procedure.

## Durable control stores have fixed lifetime limits

Executor bounds every durable control file so a corrupt or attacker-controlled
input cannot force unbounded startup work or memory use. These bounds also limit
how many mutations and distinct instance identities one node can retain over its
lifetime:

| Store | Limit | What consumes it |
| --- | ---: | --- |
| `evidence.bin` | 64 MiB | Signed pre-effect, commit, compensation, recovery, and lifecycle receipts |
| `connector-receipts.ndjson` | 64 MiB | Signed connector and exact service-task authorizations and terminal outcomes; authorization tombstones also enforce replay and call budgets |
| `operation-journal.bin` | 16 MiB | Prepared and terminal host-mutation records |
| `admission-fences.bin` | 4 MiB and 65,535 records | One retained record for each tenant and instance pair, including destroyed tombstones |
| `uplink-state.json` | 1 MiB encoded | One retained anti-replay position for each tenant and instance pair seen through Executor uplink |
| `uplink-delivery-state.json` | 8 MiB and 4,096 records; 32 records and 1 MiB of reserved terminal encoding per verified tenant | Accepted, executing, unacknowledged, and ambiguous protocol-3 or protocol-4 deliveries |

These are retention limits, not live-workload limits. Destroying a workload does
not remove the history needed to reject replay. The evidence log and operation
journal are append-only, while the fence and lifecycle uplink files rewrite
bounded snapshots without discarding old identities. The delivery ledger removes
only acknowledged `done` and `rejected` records when it needs capacity; it retains
ambiguous history.

Steward currently has no supported command to manually compact, prune, or roll
over these stores. Monitor their file sizes and the number of tenant/instance identities
before they approach a limit. When a store cannot safely accept the next record,
the affected signed mutation fails closed. Do not truncate, replace, or restore
one file independently: doing so can remove evidence or replay protection. A
long-lived deployment must include these limits in node-lifecycle and capacity
planning.

## Egress boundary

Signed workloads can request 1–32 named routes. The publisher capsule must allow
egress, and tenant site policy must allow every route. Gateway maps each route to
hostname patterns, ports, and concurrency, byte, and time limits. The agent receives
an HTTP/HTTPS proxy, not raw Docker networking. Gateway connects to the exact
verified IP. It always rejects unspecified, multicast, and limited-broadcast
addresses. Private and IANA-designated special-purpose unicast ranges—including
loopback, link-local, benchmarking, documentation, and shared carrier-grade NAT
space—are denied by default. An explicit Classless Inter-Domain Routing (CIDR)
range may allow special-purpose unicast when that private destination is intentional.
Agent DNS is disabled.

HTTPS uses `CONNECT`. Steward requires the TLS ClientHello server name to match the
approved CONNECT hostname and enforces address, port, byte, time, and concurrency
limits. It does not intercept TLS, so it cannot enforce paths or methods inside an
HTTPS tunnel. JSON Lines (JSONL) audit omits paths, queries, headers, bodies, and
credentials. Generic egress has no credential-injection path. A named connector can
add one operator-owned Bearer or `X-API-Key` credential only for its exact HTTP
operation; it cannot add a credential inside an arbitrary HTTPS tunnel. If an
approved agent already stores a credential in its state, Steward does not hide that
credential from the agent.

For an unknown-length inference, service, or HTTP egress response, Gateway starts
forwarding before it can know the final size. It advertises an
`X-Steward-Stream-Status` trailer and aborts the HTTP stream if an upstream read
fails or another byte exists after the configured limit. Standard HTTP clients
surface that abort as a framing or body-read error. A clean stream ends with the
`completed` trailer. This mechanism proves that Gateway reached a clean protocol
boundary; it cannot prove that an upstream close-delimited application response was
semantically complete before the upstream chose to end it.

Route concurrency limits apply to allowed traffic. Gateway fails closed if it cannot
persist an allow decision before opening the route. It attempts synchronous audit
writes for denied requests and terminal outcomes, but those writes are best-effort:
a denial still returns and an existing stream still ends if the write fails. Denied
requests are admitted to that synchronous path through fixed one-minute limits: 30
per grant, 120 per tenant, and 480 across the host. After a layer is exhausted, a
request that fails egress policy returns HTTP 429 `egress_rate_limited` without
another denial write until the window resets. Requests that satisfy policy continue.
Inactive and revoked grants retain `grant_inactive` or `grant_revoked` even when
the limiter suppresses their denial record. This bounds audit amplification, but
all tenants still share Gateway CPU, memory,
the audit filesystem, and a host-wide limit. Host monitoring and external resource
controls remain necessary.

Docker selects each capability network from its daemon-wide default address pools.
Steward currently does not request a fixed prefix size. Docker commonly allocates
larger subnets than a two-container agent/relay network needs, so address-pool
exhaustion can occur before Steward reaches its workload-count cap. Configure and
capacity-test Docker's default address pools for the node's maximum network count.

Executor treats only Docker's `created` and `exited` states as exactly stopped.
`paused`, `restarting`, `removing`, `dead`, unknown, and unrecognized states are
ambiguous. A stop request attempts a bounded stop and then requires reinspection
to prove `created` or `exited`; otherwise the operation remains degraded and
requires reconciliation. Reconciliation applies the same classifier to the agent
and its relay.

## Connector boundary

A connector exposes exact node-configured HTTP operations through the trusted
Relay and Gateway. The workload cannot choose the upstream origin, method, path,
credential header, address policy, redirect, or limits. Gateway supports only
Bearer and `X-API-Key` injection, requires one bounded task ID, durably spends the
logical instance's task claim and the generation-bound grant's call budget before
the external request, and never returns spent authority after an upstream failure.
Replay namespaces are isolated by tenant and logical instance. Private or
special-purpose addresses require an explicit CIDR.

Gateway signs and fsyncs authorization before DNS, retains spend tombstones after
grant deletion, reconstructs them from the verified chain after restart, and
reserves terminal-record capacity before allowing an effect. It caps concurrent
connector calls at 32 per host and four per grant and rate-limits total attempts per
grant. These fixed caps protect Gateway resources; they are not a scheduler or a
fair-share guarantee across tenants.

A connector may opt into an additional action permit. One tenant-scoped Ed25519
key then signs a short-lived canonical DSSE envelope for the exact request. Gateway
checks node, tenant, instance, generation, artifact and policy digests, connector,
operation-policy digest, task, exact body digest and length, method-derived content
type, and time window against live state. The operation-policy digest commits to
the canonical origin, credential injection mode, credential epoch, connector and
operation IDs, method, and exact path. The permit cannot expand the outer workload
grant. A standard permit-backed call records the authority key, permit, and request
digests in receipt format 2 before the network effect.

Authorized Effects adds signed-policy continuity to this connector mechanism.
Site-root-signed tenant policy sets `authorized_effects` to `optional` or `required`
and pins each action public key and a one-through-eight approval threshold to
connector IDs. Authenticated intent explicitly
selects `effect_mode`; required policy rejects a standard or omitted mode. Authorized
mode rejects generic egress and requires every selected connector to have enough
exact policy-pinned key matches in Gateway. A one-approver policy accepts only a
version-2 action permit and records accepted events in receipt format 5. A
multi-party policy accepts only a version-3 permit with the exact number of
distinct valid signatures and records the canonical signer set and threshold in
receipt format 6. Gateway state format 5 preserves the mode and narrowed key scopes
across restart; format 6 also preserves a multi-party threshold.

Signed policy may additionally set `context_binding` to `required`. Gateway then
accepts only a version-5 permit that binds the grant's current signed
connector-response history, permits only one in-flight connector call for the
grant, and records format-7 authorization and terminal evidence. A completed call
invalidates permits issued against the prior history. This is not semantic
prompt-injection detection: task input, inference, local files or memory, browser
observations, generic egress, unmanaged channels, and upstream interpretation are
outside the history. Context-required grants do not accept exact-effect bundles.

The same policy can authorize a version-4 exact-effect bundle containing one
through eight requests. Every signer must be admitted and configured for every
connector in the bundle. Gateway validates every listed connector, operation
policy, content type, signer scope, and the shortest connector lifetime before it
accepts any selected step. Each task remains independently one-use. The bundle is
an unordered set, not a workflow: a compromised agent may execute any subset in
any order, omit steps, or stop. Steward does not provide dependencies, conditional
branches, compensation, rollback, or data flow from one step into another. Use a
bundle only when every subset and ordering is acceptable.

An invalid permit in authorized mode may create one stable
`action_permit_denied` record per retained grant. The denial binds the request
digest and operation policy without claiming a verified permit or authority key.
The cap prevents a compromised workload from converting unlimited bad permits into
unlimited evidence; if the bounded record cannot be persisted, the request fails
closed before the effect. This is first-observed, attacker-selectable evidence: the
workload chooses the task ID and request bytes accompanying the first invalid
permit, and later denials are not enumerated. The marker proves at least one denial,
not a complete denial history.

The connector ledger also has an explicit, non-borrowing byte budget for every
tenant that may receive a connector grant. Gateway rejects an unbudgeted grant
before creating its socket. A tenant's usage includes each durable signed line and
newline plus the pending worst-case terminal-record reservation for an authorized
call. Each budget is at least 262146 bytes, the table has at most 128 entries, and
the total is at most 64 MiB. A tenant with lifecycle service operations needs at
least 393219 bytes to reserve authorization, dispatch, and terminal records.
Exhaustion fails the call with HTTP 503 and
`connector_evidence_quota_exhausted`; unused capacity assigned to another tenant is
not available.

Without an action authority, the workload can mint task IDs until it exhausts its
admitted connector and node-configured call budget. A task ID is a replay and
correlation fence, not proof that a human or separate service approved the action.
With action authority, an accepted permit proves only that the required configured
keys signed those exact bytes and metadata within the validity window; it does not prove
the natural-language task's meaning or the signer's decision process. Connector
receipts omit credentials, headers, origins, paths, queries, and bodies. The signed
effective route-policy digest commits to those operator-controlled details without
disclosing them. The records do not prove that the upstream service applied a
request exactly once. A lost response remains an ambiguous external effect;
replaying the same task fails closed. If Gateway stops between authorization and a
terminal record, restart records `outcome_unknown`; the operator must treat the
upstream result as ambiguous.

Steward itself does not directly configure or give the connector credential or
private upstream origin to the workload. Gateway rejects an upstream response when
any header or decoded body stream contains the exact configured credential,
including a value split across body chunks. It does not detect an encoded or
transformed credential, private-origin disclosure, or application-specific secret
fields. Configure a narrow endpoint and tenant-specific credential, and continue to
treat the upstream as trusted.

Deleting the entire connector ledger is indistinguishable from first startup to
the node alone. Keep its verified head outside the node and compare that checkpoint
before accepting a replacement or empty chain. The ledger has no compaction or
rollover command. Changing a receipt identity or budget requires a restart, not a
reload. An in-place reduction is accepted only after retained connector grants are
drained and when the smaller allocation still covers that tenant's verified
historical usage and pending terminal reservations. Historical bytes are never
reclaimed. Removing a tenant that has history, or starting with a smaller empty
ledger, requires a new receipt file and epoch after the operator decides how to
retain and checkpoint the old chain; preserve its verification material. When a
tenant allocation is exhausted, new connector effects for that tenant fail closed.

These allocations isolate logical ledger capacity, not the underlying host. Host
root can replace or delete the ledger, and unrelated host data can fill its
filesystem. All tenants also share one ledger descriptor, mutex, and synchronous
`fsync` path, so disk latency and lock contention can affect other tenants even
when their byte allocations remain available.

The action-trust inventory exported for an off-node signer is non-secret but
unsigned. It can prevent accidental issuance for a mismatched node, tenant, key,
connector, operation, credential epoch, or lifetime only when the operator
authenticates its transfer. It is not a delegated grant and cannot prove Gateway's
current state; Gateway's live configuration is the final enforcement point.

Gateway configuration requires an explicit loopback service address with a numeric
port from 1 through 65535. Missing, zero, out-of-range, and named service ports fail
both `-check-config` and startup.

Authorized Effects assumes a fully compromised agent, but only for this completely
mediated connector boundary. It does not constrain credentials, browser sessions,
plugins, sockets, or other channels available outside Steward; inference
confidentiality; local filesystem or computer-use effects; host root, Gateway, or
signing-key compromise; an approver's misunderstanding; or the upstream service's
exactly-once behavior. A lost response remains ambiguous and does not restore the
spent permit.

## Tenant-signed service-task boundary

An ordinary service grant lets a host administrator reach one capsule-declared
agent port through Gateway. Its bearer token is host transport authority, not proof
that a tenant approved a prompt. Exact service tasks are opt-in and add a separate
tenant signature without exposing the private signing key to the node or agent.

Signed site policy may assign at most eight Ed25519 task public keys to one tenant
and scope each key to one through 32 service IDs. Executor admits only keys whose
scope includes the instance's exact `service_id` and projects those public keys into
the Gateway grant and retained state. Gateway state format 4 is required to preserve
that binding across restart. A private task key belongs on a separately controlled
signing station.

Gateway accepts at most 128 configured service operations. They are exact
`application/json` POSTs with canonical paths and no query, wildcard, alternate
percent encoding, transfer coding, WebSocket upgrade, or caller-selected upstream
headers. Hard ceilings are 64 KiB per request, 1 MiB per response, 120 seconds per
dispatch or status request, a 60-second polling interval, and 15 minutes per permit.
Every operation has one fixed status-path prefix. A smaller operation limit wins.

`stewardctl task issue` consumes the exact admission response, instance intent,
request bytes, and an authenticated but unsigned service-trust inventory. It writes
an owner-only bundle that contains the request, public authority, operation policy,
and signed permit, but no private key or Gateway token. Because the request can be a
sensitive prompt, treat the bundle as sensitive input even though it is not a
reusable signing credential. The inventory is mismatch preflight only; the live
Gateway configuration and active grant remain authoritative.

The permit binds node, tenant, logical instance, runtime, grant, generation,
capsule, site policy, effective route policy, service, exact operation-policy
digest, task ID, request digest and byte length, content type, and validity window.
Gateway validates all bindings against the live request, reserves replay identity,
and fsyncs a format-4 authorization record before contacting the service. It checks
expiry and grant activity again after the durable write and immediately before
dispatch.

Only HTTP 200, 201, and 202 with one bounded JSON run ID count as a successful
submission. Gateway does not relay the service's response headers or arbitrary
body. It records the observed status, byte count, and run ID in a distinct dispatch
record, then returns a canonical run-ID object. A later bounded observation can add
a terminal record with the agent-reported state, exact result digest, and byte
length. The run ID and result are untrusted application output and can be fabricated
by a hostile image. Receipts record what Gateway observed, not whether the agent
completed useful or correct work.

Task replay identity is `(tenant_id, instance_id, task_id)`. It deliberately omits
generation and grant ID, so replacement of one logical workload does not make the
same task ID spendable again. A concurrent replay cannot cross the in-memory
reservation. After restart, Gateway reconstructs spends and pending lifecycles from
the signed ledger. An exact successful replay can return the recorded run ID without
another dispatch. Pending, conflicting, rejected, malformed, or ambiguous outcomes
do not dispatch again automatically. A retained authorization with no safely
recoverable dispatch outcome is closed as `outcome_unknown`; a durable dispatch
remains observable through its configured status path.

An ambiguous authorization write happens before service dispatch. Gateway returns
`evidence_unavailable` and retains that task's process-local replay fence. Once the
ledger reports the failure, Gateway rejects new task authorizations without adding
new fences. Restart Gateway to verify the ledger: a complete authorization is closed
as `outcome_unknown`, while an absent authorization leaves the task available. This
fail-closed recovery can consume a permit without dispatch when the authorization
was durable but its sync result was ambiguous.

This guarantee is node-local at-most-once dispatch within one retained receipt file
and epoch. It is not exactly-once execution across a fleet, after ledger deletion or
replacement, after an epoch change, or inside the agent or an external system. A
control plane that can target multiple nodes must coordinate task identity outside
Steward if it needs fleet-wide replay prevention. Keep the verified ledger head
outside the node; host root can replace the ledger, key, and software together.

Service tasks share the Gateway signed ledger and its explicit non-borrowing tenant
budgets with connectors. Exhaustion fails before dispatch with
`task_evidence_quota_exhausted`. The allocation isolates ledger bytes, not shared
disk latency, CPU, memory, or the host filesystem. Receipt format 4 records no raw
prompt, request body, model output, workspace content, private key, Gateway bearer,
or arbitrary service response.

Generic `stewardctl task submit`, `status`, `observe`, and `wait` require an
owner-only version-2 lifecycle bundle, owner-only Gateway token, and
literal-loopback HTTP origin. Remote operators should execute them through SSH or
another authenticated private management path. Status is passive. Observation uses
the fixed operation policy and writes verified terminal bytes only to a new
owner-only result file or explicitly discards them; raw result bytes are removed
from standard output. The tenant permit authorizes only the exact POST. Model
inference remains separately configured and controlled.

## Hermes adapter qualification boundary

Steward's Hermes qualification applies only to upstream commit
`095b9eed3801c251796df93f48a8f2a527ff6e70`, the checked-in adapter definition, and
the documented runtime contract on `linux/amd64`. Other platforms are not yet
qualified. The harness ran a source-built, non-root image under
gVisor, submitted useful work through Hermes's run API, verified the signed
`steward.workspace-audit` result, changed persisted workspace state, restarted the
container with a fresh session, and required the changed result. The integration
qualification also required Hermes to discover and load the exact signed
`steward.connector-work` skill, verified one authenticated upstream effect, denied
task replay and an undeclared operation, scanned the fixed qualification material
for secret and origin leakage, and verified Gateway's separate signed receipt
chain. The exact service-task path additionally scoped a tenant key to
`hermes-api`, signed five exact run requests, dispatched them through Gateway, and
correlated format-4 authorization, dispatch, and terminal records offline.

The connector portion still uses the connector grant-and-task path. It does not
configure a connector action authority, issue `X-Steward-Action-Permit`, or exercise
receipt format 2. Do not cite the retained Hermes evidence as proof of the optional
connector action-permit path. The separate service-task qualification uses
`X-Steward-Task-Permit` and receipt format 4.

This does not qualify the official upstream image, another Hermes commit, arbitrary
plugins, channels, skills, MCP servers, or run event streams. The service bridge
allows only negotiation, health, `POST /v1/runs`, and `GET /v1/runs/{run_id}` on
port `8766`. Inference is fixed through
`http://steward-relay:8080/v1`.

Steward distributes the pinned build definition and builder, not a prebuilt Hermes
OCI archive. Dependency and base-image notices are incomplete, so redistribution
remains blocked. A locally produced archive and its metadata attestation still
require operator authentication, inspection, policy authorization, and signing.
The attestation records build inputs and output digests; it is not a signature or a
new runtime qualification.

Hermes state uses the same unquotaed Docker volume as any other persistent Steward
workload. It requires the explicit dedicated single-tenant host mode and does not
extend Steward's shared-host isolation claim to persistent state.

## Release transitions require a drained node

Steward does not upgrade or roll back in place while workloads or grants remain.
Before a release transition, destroy all managed agent and relay containers and
capability networks; stopped containers also count. No live admission fence,
pending journal entry, or retained Gateway grant may remain. Steward-managed state
volumes may remain. This interruption lets activation bind one relay image to the
release, inspect every durable format with services stopped, and avoid changing the
execution boundary beneath a retained workload.

## Not available

- Raw outbound TCP, UDP, ICMP, SOCKS, or arbitrary inference destinations
- Transparent interception for software that ignores `HTTP_PROXY`/`HTTPS_PROXY`
- TLS interception or application-layer (L7) path/method policy inside HTTPS tunnels
- Interactive dynamic approval of previously unlisted destinations
- Arbitrary state paths, host bind mounts, or automatic state deletion
- Raw published agent ports, public ingress, or tenant end-user authentication
- Secret, arbitrary environment-variable, or file injection
- Generic credential injection, caller-selected connector origins, dynamic paths,
  redirects, or credentials inside HTTPS `CONNECT` tunnels
- Per-workload UID/GID selection
- GPU or other device assignment
- Writable image root filesystems
- Interactive terminal/exec sessions
- Image pulling or registry authentication
- A prebuilt, Steward-redistributed Hermes adapter image
- OpenClaw Gateway, Control UI, channels, browser control, cron, plugins, nodes,
  discovery, arbitrary skills, or nested Docker sandboxes. The qualified OpenClaw
  adapter exposes only its documented one-shot run surface.
- Hermes run event streams or unqualified Hermes plugins, channels, skills, or MCP
  servers
- Multi-image archive selection, remote OCI descriptors, or mutable-tag admission
- Automatic recovery or a decision that marks an ambiguous journal operation
  committed or compensated. Degraded stop can narrow local authority, but the
  original operation still requires explicit operator recovery.
- A supported config-only purge or node-retirement workflow that preserves the
  receipt key and evidence chain as one identity
- Container checkpoint/restore, Kubernetes, or multi-host placement

The capsule contains maximum `state`, `inference`, `service`, `connector`, and `egress`
capabilities. State requires a Steward-owned Docker volume and the explicit
dedicated-host-only compatibility setting for volumes without enforced byte or inode
quotas. Inference, service, connector, and egress require the complete Gateway and relay
configuration. If a requested enforcement path is missing, Executor returns HTTP
501; a signed boolean alone is not an isolation control.

Steward reserves aggregate memory, CPU, PIDs, and workload counts for the host and
each tenant. It reconstructs those reservations from Docker after restart and
includes fixed relay overhead. These admission ceilings do not reserve disk bytes,
inodes, I/O bandwidth, or capacity used by trusted host services. Operators must
leave explicit headroom for Docker, gVisor, Gateway, the operating system, logs,
and bursts.

Persistent local Docker volumes have no portable hard byte or inode quota, so they
remain disabled on a shared host. Enabling
`-allow-unquotaed-state-on-dedicated-host` requires complete signed admission with a
verified policy containing exactly one tenant and moves storage exhaustion outside
Steward's isolation claim.

## Runtime hardening still ahead

Future hardening must preserve deny-by-default operation:

1. encrypted or externally managed state backends without caller-selected host paths;
2. stronger receipt-key isolation and optional external evidence anchoring;
3. finer authenticated service principals beyond the host-wide local token;
4. optional external signature, software bill of materials (SBOM), and provenance
   verification before the bounded local OCI import; and
5. a verified node-retirement and control-store rollover procedure that preserves
   receipt continuity and replay protection.

Each capability requires crash recovery, drift inspection, cross-tenant tests, and
Docker/gVisor acceptance. Host mounts, Docker socket exposure, default-allow routes,
implicit private-address access, and caller-selected privileges are not acceptable
substitutes.

## Trusted substrate

Host root, the Linux kernel, Docker, gVisor, the node's signing-key protection, and
operator configuration are trusted. Steward does not provide bare-metal bootstrap,
disk encryption, hardware attestation, vulnerability management, model inference,
or formal air-gap accreditation.
