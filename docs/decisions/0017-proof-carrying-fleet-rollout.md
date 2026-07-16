# 0017. Build proof-carrying fleet rollout without controller authority

- Status: Accepted
- Date: 2026-07-16
- Rung: in-house

## Context

Steward can verify and activate one qualified Hermes release on one node, and
its controller can deliver exact tenant-signed lifecycle commands to a fleet.
The missing product path is staged rollout: select explicit nodes, activate a
real agent on a canary node, prove the fixed qualification task, and advance in
bounded batches without giving the controller tenant signing keys.

General deployment systems provide rolling updates, health gates, and
background reconciliation. They do not preserve Steward's exact signed-command,
task-permit, admission, Gateway-receipt, Executor-evidence, and offline-proof
bindings. Adding Kubernetes, Argo Rollouts, Temporal, or a message broker would
also make those systems mandatory in disconnected installations.

The existing Executor uplink reports only a runtime reference and coarse status.
It discards the full signed-admission result needed to authorize and verify the
post-admission canary. The controller evidence witness verifies node receipt
deltas but normally retains only the latest checkpoint, so it cannot later
export the exact bounded activation range.

## Decision

Build one fixed proof-carrying rollout state machine around Steward's existing
contracts. A rollout has one verified agent release, one tenant, an explicit
ordered node list, one node-specific intent per target, one canary node, and
fixed-size later batches. Images must already be imported on every target.

The operator-side `stewardctl` coordinator owns rollout progress and private
keys. It uses an owner-only append-only workspace, submits exact tenant-signed
commands through the controller, and treats command submission as idempotent
only when the command ID and signed bytes are unchanged. The controller remains
a bounded delivery and evidence service. It does not select targets, mint
commands or task permits, choose winners, or retry an ambiguous external
effect.

Add a new immutable Executor uplink protocol version instead of widening the
strict existing version contextually. The new report can carry a bounded
`ExecutorAdmissionProjectionV1` copied from Executor's successful admission
response. It includes runtime, capsule, policy, generation, admitted task
authorities, service and route bindings, and activation markers, but no private
key, bearer credential, prompt, request body, result body, or arbitrary
metadata. Existing nodes and independently implemented controllers may continue
using the prior protocol unchanged. An explicitly configured new node fails
closed against an old controller; it never silently downgrades.

The node-side delivery ledger and controller store record the protocol version
and projection durably. Their formats advance with explicit read and write
ranges. Upgrade the controller before nodes. After either new writer persists
new-format state, rollback requires restoring the matching pre-upgrade state
backup rather than starting an older binary over unreadable authority records.

Remote admission carries the existing activation identity and begin digest.
After read-only admission checks pass, Executor records `activation_begin`
before host mutation and returns the complete admission projection. A later
finite `activation-canary` command may carry only the closed Hermes
workspace-audit task, its exact tenant-signed permit, the admitted binding, and
one absolute deadline. It cannot carry a URL, shell command, hook, free-form
prompt, or generic workflow step.

Gateway's local control interface exposes typed task submit, observe, and
task-local receipt export operations for this closed path. These operations
reuse the active grant, one-use permit spend, observation limits, and signed
ledger. After the fixed canary result verifies, Executor records the existing
`activation_checkpoint`.

The controller may retain a bounded, site-admin-armed capture of exact Executor
evidence frames that it already verified. Capture starts from a witnessed
checkpoint, has a hard byte limit and a small active-count limit, and seals only
at the checkpoint returned by the canary. Overflow, rollback, equivocation, or
coordinate mismatch fails the rollout but never blocks ordinary evidence
witnessing. Because the linear node range can contain unrelated tenant
metadata, capture mutation and export remain site-administrator operations.

A target passes only after offline verification authenticates the release,
capsule, commands, admission projection, task permit, Gateway task receipts,
Executor activation markers, captured receipt range, and controller witness.
The first node must pass before any later batch starts. Every target in a batch
must pass before the next batch starts.

Any rejection, terminal canary failure, revoked node, evidence conflict, expired
deadline, or `outcome_unknown` becomes sticky `action_required`. The
coordinator does not automatically stop, destroy, replace, or roll back a
workload. Recovery requires explicit new authority and, when replacing a failed
activation, a new activation identity and higher instance generation.

**Tradeoff:** Steward owns a narrow versioned protocol, bounded evidence capture,
and one fixed rollout coordinator. Operators gain an end-to-end fleet path that
works through an outbound-only controller and produces portable evidence. The
initial path is limited to pre-imported qualified Hermes images, explicit nodes,
sequential batches, and the built-in workspace-audit canary.

**Buy vs build:** build the Steward-specific binding in-house with the Go
standard library and existing packages. Reuse Docker, gVisor, systemd, HTTP,
Ed25519, DSSE, and Steward's current controller store and evidence chain.
Reject a workflow engine, Kubernetes control plane, deployment operator,
database, or broker because none replaces the authority and proof contract and
each adds a mandatory operational and supply-chain boundary.

## Consequences

Rollout is not placement, desired-state reconciliation, a generic scheduler, an
approval product, or model-based health scoring. Labels, selectors, cron,
maintenance windows, arbitrary canaries, A/B selection, automatic rollback,
remote image transfer, registry pulls, and controller key custody remain
outside this decision.

The admission projection is an authenticated node report retained by the
controller. It is not itself a signature, attestation, or proof that the
workload behaved correctly. The portable proof still depends on separately
verified signed Executor and Gateway evidence and externally trusted public
keys.

Existing command and task authorities have short validity windows. The initial
coordinator therefore uses a bounded rollout deadline and small explicit target
set; it does not extend, refresh, or reinterpret those authorities. Revisit
plan-bound continuation envelopes only after their delegation and replay
semantics receive a separate review.

The design follows the Relying Party separation described by
[RATS](https://www.rfc-editor.org/rfc/rfc9334.html) and can later consume
normalized external attestation results. It does not claim RATS, SCITT, SLSA,
SPIFFE, or hardware-attestation conformance merely because its evidence records
use similar identity and digest bindings.
