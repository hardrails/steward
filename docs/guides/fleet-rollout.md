---
title: Roll out a qualified Hermes release across a fleet
description: Stage one exact Hermes release across an explicit node list, require a verified canary before each operator-approved batch, resume safely after interruption, and verify the resulting evidence offline.
section: How-to guide
---

# Roll out a qualified Hermes release across a fleet

Steward can coordinate one qualified Hermes release across an ordered list of
remote nodes without placing a tenant signing key in Steward Control. The first
node is the canary. Each `rollout run` invocation advances one fixed batch,
sequentially verifies every target in that batch, and stops at the next operator
decision point. A target passes only after Steward correlates its signed admission,
fixed Hermes workspace-audit task, Gateway receipts, Executor activation markers,
controller evidence capture, and activation proof.

This closes a specific operational gap: a successful container start is not enough
to promote an agent across a fleet. The operator also needs evidence that the exact
release was authorized, the closed qualification task ran through the admitted
service path, and every promotion gate used the same retained authority.

This is a narrow rollout coordinator, not a general deployment system. It does not
select nodes, transfer images, pull from registries, schedule maintenance windows,
run arbitrary canaries, score model output, reconcile desired state, or roll back a
failed workload automatically.

## Security and authority model

The rollout deliberately keeps selection, signing, delivery, execution, and proof
in separate trust domains:

| Component | What it may do | What it does not establish |
| --- | --- | --- |
| Trusted operator workstation | Select the exact ordered targets, hold the command and Hermes task private keys, create the owner-only workspace, sign the exact plan and evidence-bound batch promotions, and decide when to start each batch. | A signer authorization records the approved bytes and sequence, not the operator's reasoning or an external approval ticket. |
| Steward Control | Deliver exact signed commands, report bounded terminal results, witness Executor evidence, and retain a site-admin-armed evidence capture. | It does not select targets, hold tenant signing keys, mint commands or tasks, choose a winner, or decide rollback. |
| Executor and Gateway on each node | Enforce signed admission, run the fixed activation canary, and sign the relevant evidence within the node trust boundary. | Their evidence is not hardware attestation and does not prove the host administrator or kernel was uncompromised. |
| Agent container | Return the bounded Hermes result through its admitted service. Treat the image and its configuration as untrusted. | Its run ID and work product are not trusted merely because Steward recorded them. |
| Offline verifier | Re-authenticate the signed plan authorization and promotion chain, exact archive, release, policy, commands, task permit, receipt chains, evidence capture, state history, and aggregate proof. | `proof.json` and rollout state files remain unsigned correlation records, not standalone proof. |

The controller evidence capture can contain interleaved receipt metadata from other
tenants because removing those frames would break the signed chain. Creating and
exporting a capture therefore requires a `site_admin` token, not a tenant operator
token. Treat the complete rollout workspace as sensitive operational evidence.

The fixed canary accepts no URL, shell command, hook, arbitrary prompt, or generic
workflow step. It demonstrates the qualified fresh-workspace Hermes fixture and
the recorded enforcement path. It does not demonstrate that arbitrary prompts,
skills, models, plugins, future runs, or agent output are safe or correct.

## Before you begin

Prepare a trusted coordinator host with `stewardctl` and an owner-only local
filesystem that provides same-filesystem POSIX hard links, reliable file and
directory `fsync`, stable Unix ownership and link counts, and reliable `flock`.
The rollout store has no unsafe rename or truncate fallback when those guarantees
are unavailable. The coordinator must be able to reach Steward Control. The nodes
may remain outbound-only because command delivery and evidence publication use
their existing controller uplinks.

The current rollout contract also requires all of the following:

- one publisher-signed Hermes agent release, the exact capsule envelope embedded
  in it, and its exact Open Container Initiative (OCI) archive;
- one site-root-signed policy containing exactly one tenant;
- from 1 through 64 explicit, unique target nodes in the intended order;
- a dedicated host for each target, configured with
  `--allow-host-admin-intent` and
  `--allow-unquotaed-state-on-dedicated-host`;
- a fresh-state Hermes instance intent for every target, with a positive new
  instance generation and the state and service capabilities enabled;
- the exact image already imported on every target node;
- an active controller enrollment for the tenant on every target;
- protocol-4 Executor delivery and the `admission-projection-v1`,
  `activation-canary-v1`, and `rollout-authorization-context-v1` node
  capabilities;
- an existing, finding-free Executor evidence checkpoint for every target;
- a command key authorized by the signed policy for `admit`, `start`, and
  `activation-canary` commands;
- a Hermes task key authorized by the signed policy for service `hermes-api`;
- the controller's witness public key, publisher public key, and site-root public
  key obtained through independent authenticated channels; and
- a site-administrator controller token. Evidence capture is site-wide authority.

Persistent Hermes state uses a Docker volume without a portable hard byte or inode
quota. The dedicated-host requirement is therefore material. Do not enable this
recipe on a shared multi-tenant host. Steward's stateless shared-host isolation is
available outside this rollout path.

Upgrade Steward Control before enabling protocol 4 on nodes. The controller and
node delivery stores have explicit format read and write ranges. After a new writer
persists a newer authority record, rollback requires restoring the matching
pre-upgrade state backup; do not start an older binary over that state. See the
[upgrade guide]({{ '/guides/upgrades/' | relative_url }}).

## 1. Verify and pre-import the release on every target

Authenticate the release and exact archive on the coordinator before preparing the
rollout:

```console
stewardctl agent-release verify \
  -in hermes-workspace-audit.release.dsse.json \
  -public-key publisher.public.pem \
  -key-id publisher-key-id \
  -archive hermes-agent-adapter.tar
```

Import that exact archive on every target before `rollout run`. Use the capsule
envelope originally supplied when the release was issued and the same authenticated
site policy. Before transfer, require its envelope digest to equal
`capsule_envelope_digest` in the `agent-release verify` output:

```console
sudo stewardctl image import \
  -archive hermes-agent-adapter.tar \
  -capsule capsule.dsse.json \
  -policy site-policy.dsse.json \
  -site-root-public-key site-root.public \
  -site-root-key-id site-root-1
```

`rollout create` inspects the local archive and retains its digest, byte length,
manifest, configuration, and platform identity. It does not copy the archive into
the rollout workspace. `rollout run` does not transfer or import an image. Remote
admission fails if the authenticated image is absent from a target.

The `-image-import-timeout` recorded in a rollout plan is a reserved ceiling for
the activation contract. It does not turn this workflow into remote image import.

## 2. Check each enrolled node

Confirm that every target is active, belongs to the rollout tenant, and reports
`admission-projection-v1`, `activation-canary-v1`, and
`rollout-authorization-context-v1` in its `capabilities` array:

```console
stewardctl control node status \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -tenant-id tenant-a \
  -node-id node-a
```

Confirm that its evidence checkpoint exists and has no finding:

```console
stewardctl control evidence status \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -node-id node-a
```

Repeat both checks for every node. `rollout run` repeats the security-relevant
preflight before it signs or submits the target's commands. Inspect the checkpoint
timestamp and apply your site's freshness requirement before continuing. The
controller requires an existing, finding-free witnessed head when the coordinator
arms the capture, but it does not enforce an evidence-age threshold at that step.
A revoked node, tenant mismatch, missing capability, finding, conflicting evidence
coordinate, or expired rollout authority prevents execution or promotion. After
arming, the bounded capture must reach the rollout's exact activation markers before its
deadline; otherwise it fails or expires and the target cannot pass.

## 3. Prepare the ordered target inputs

Create one exact instance intent per node by following the
[signed-admission guide]({{ '/guides/signed-admission/' | relative_url }}). Every
intent must name the same tenant and the corresponding target node. It must use:

- `state_disposition: "new"`;
- `capabilities.state: true` and `capabilities.service: true`;
- service ID `hermes-api`; and
- a positive instance generation that has not been superseded for that
  `(tenant_id, node_id, instance_id)` lineage.

Export the tenant-specific Hermes service trust inventory on each node:

```console
umask 077
sudo stewardctl gateway service trust \
  -config /etc/steward/gateway.json \
  -node-id node-a \
  -tenant-id tenant-a > node-a.service-trust.json
```

Authenticate that transfer. The inventory is unsigned and contains no credential,
but it fixes the exact `hermes.run` method, path, limits, lifecycle protocol, and
operation-policy digest that the coordinator will require.

Also copy `/etc/steward/connector-receipts.public` from each node through an
authenticated channel. Record the matching positive `connector_receipt_epoch` from
that node's trusted `/etc/steward/gateway.json`. A key rotation requires the new
key, a new empty ledger, and a higher epoch; never relabel an existing chain.

Place the target manifest and all companion files in one trusted directory. Each
companion reference must be a clean filename, not a path. The array order is the
rollout order: target 0 is always the canary.

```json
{
  "schema_version": "steward.rollout-inputs.v1",
  "targets": [
    {
      "intent_file": "node-a.intent.json",
      "service_trust_file": "node-a.service-trust.json",
      "gateway_receipt_public_key_file": "node-a.gateway-receipts.public",
      "gateway_receipt_epoch": 1,
      "claim_generation": 1,
      "activation_id": "hermes-audit-node-a"
    },
    {
      "intent_file": "node-b.intent.json",
      "service_trust_file": "node-b.service-trust.json",
      "gateway_receipt_public_key_file": "node-b.gateway-receipts.public",
      "gateway_receipt_epoch": 1,
      "claim_generation": 1,
      "activation_id": "hermes-audit-node-b"
    }
  ]
}
```

`claim_generation` is the positive tenant-signed command-claim fence that the node
echoes in each report. It is distinct from the instance generation in the intent,
which fences an old instance lineage. Choose one positive value under your command
authority process for each target's fixed command set; `1` is conventional for a
fresh set. The value becomes immutable when the rollout is created. Do not reuse a
generated command identity with changed bytes. `activation_id` is optional;
Steward derives a stable unique value when it is omitted.

Steward derives each target's `admit`, `start`, and `activation-canary` command ID
from the rollout ID, zero-based target index, and node ID. Plan validation rejects
an edited target order or command alias instead of accepting a different account of
the same signed commands.

Unknown JSON fields, duplicate members, unsafe filenames, duplicate nodes or
activation IDs, mixed tenants, and inconsistent service or receipt authority are
rejected.

## 4. Create the rollout workspace

Choose an absent path under a trusted, owner-only parent. `rollout create`
authenticates the release, capsule, policy, archive, target intents, service trust,
Gateway keys, and controller witness key before creating the workspace. It writes
immutable inputs once and starts every target at `planned`.

```console
umask 077
install -d -m 0700 "$HOME/.local/share/steward/rollouts"
ROLLOUT_DIR="$HOME/.local/share/steward/rollouts/hermes-audit-001"

stewardctl rollout create \
  -dir "$ROLLOUT_DIR" \
  -release hermes-workspace-audit.release.dsse.json \
  -policy site-policy.dsse.json \
  -archive hermes-agent-adapter.tar \
  -targets targets.json \
  -publisher-public-key publisher.public.pem \
  -publisher-key-id publisher-key-id \
  -site-root-public-key site-root.public \
  -site-root-key-id site-root-1 \
  -witness-public-key steward-control-witness.public.pem \
  -batch-size 4 \
  -valid-for 1h
```

Omit `-rollout-id` to generate a stable random identifier, or supply one explicit
bounded identifier. A rollout can contain at most 64 targets. `-batch-size` accepts
1 through 16 targets after the first single-target canary batch. Add `-json` to
emit the initial machine-readable status.

The optional timeouts are recorded in every target's activation plan:

| Flag | Default | Meaning |
| --- | ---: | --- |
| `-preflight-timeout` | `30s` | Create-time archive and policy preflight, and each target's controller node preflight when its batch begins |
| `-image-import-timeout` | `30m` | Reserved image-import ceiling; this runner does not import remotely |
| `-admission-timeout` | `2m` | Remote admission ceiling |
| `-startup-timeout` | `5m` | Remote startup ceiling |
| `-canary-timeout` | `5m` | Fixed Hermes canary ceiling |
| `-evidence-timeout` | `2m` | Controller evidence collection ceiling |

Timeouts must be whole seconds. The rollout window must be from one second through
24 hours and cannot extend beyond the authenticated capsule expiry. Admission,
startup, canary, and evidence timeouts are also added to derive one immutable
evidence-capture lifetime; their sum must fit the controller's one-second-to-one-hour
capture limit.

The workspace directory is mode `0700`; its regular files are mode `0600`. Steward
accepts only a bounded filename inventory and holds exclusive advisory locks on the
workspace directory and its lock file. It publishes each generated artifact with a
same-directory hard-link transaction: write and sync a private staging inode, link
the immutable final name without replacement, sync the directory, remove the
staging name, and sync again. On reopen, Steward removes a valid unpublished
staging inode or completes cleanup of a valid two-link publication. Any other
staging shape fails closed for operator inspection. This recovery requires the
filesystem guarantees listed above; Steward does not fall back to an operation
with weaker replacement or durability semantics. The locks do not protect against
root or another process with the same operating-system authority.

## 5. Inspect status without treating it as proof

```console
stewardctl rollout status -dir "$ROLLOUT_DIR"
```

Add `-json` for the stable machine-readable view. Status reports the current batch,
zero-based target index, node, target phase, passed count, and any
`action_required` reason. It validates local state shape and ordering but does not
authenticate signatures or evidence. Its output therefore says
`unverified_workspace`. Use `rollout run` for authenticated online progress and
`rollout verify` for the final offline trust decision.

## 6. Run the canary batch

The coordinator needs one command private key authorized for all three rollout
command kinds and one Hermes task private key authorized for `hermes-api`. Keep
both owner-only on the trusted coordinator. The controller token must have the
`site_admin` role because the coordinator arms and exports evidence captures.

```console
stewardctl rollout run \
  -dir "$ROLLOUT_DIR" \
  -publisher-public-key publisher.public.pem \
  -publisher-key-id publisher-key-id \
  -site-root-public-key site-root.public \
  -site-root-key-id site-root-1 \
  -witness-public-key steward-control-witness.public.pem \
  -command-private-key tenant-a-commands.private.pem \
  -command-key-id tenant-a-commands \
  -task-private-key hermes-task-approver.private.pem \
  -task-key-id hermes-task-approver \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA"
```

`-control-url` defaults to `http://127.0.0.1:8443`. A non-loopback controller
origin must use HTTPS. `-ca-file` is optional when the controller certificate
chains to the system trust store. `-token-file` is always required. Add `-json`
for machine-readable authenticated retained progress. Its `verified: true` and
`verification: "authenticated_retained_progress"` fields mean the coordinator
authenticated the retained artifacts needed for this online step against the
supplied trust and keys. They are not the final offline proof verdict and do not
replace `rollout verify` with the exact archive.

Before making any controller request, `rollout run` authenticates every retained
target and reconstructs every generated artifact that already exists. While every
target is still `planned`, it creates `plan-authorization.dsse.json`: a Dead Simple
Signing Envelope (DSSE) record signed by the common rollout command key over the
exact plan digest, rollout, tenant, and authorization time. The signer must be the
same site-policy key authorized for `admit`, `start`, and `activation-canary`. Its
signed statement uses
schema `steward.rollout-plan-authorization.v1` and DSSE payload type
`application/vnd.steward.rollout-plan-authorization.v1+json`. The first invocation
then advances only target 0. For that target it:

1. rechecks the active node, tenant membership, protocol capability, plan deadline,
   authenticated release and policy, and retained target trust bindings;
2. arms one bounded controller evidence capture from the existing finding-free
   witnessed head;
3. creates and retains the exact signed `admit` command before submitting it; the
   command's `authorization_context_digest` identifies the plan-authorization
   envelope;
4. verifies that the protocol-4 admission projection binds the exact capsule,
   policy, imported image, runtime, generation, and activation-begin marker;
5. creates and retains the exact signed `start` command with the same authorization
   context before submitting it;
6. derives one closed workspace-audit task and tenant permit from the authenticated
   admission, then retains the signed `activation-canary` command with the same
   authorization context before submission;
7. verifies the bounded terminal Hermes result and Gateway authorization, dispatch,
   and terminal receipts;
8. requires Executor's activation checkpoint, seals and exports the exact controller
   evidence range, and authenticates the controller witness signature; and
9. writes the target activation proof and marks the canary `passed` only after the
   complete binding verifies.

Executor verifies `authorization_context_digest` as signed command data. It does
not receive the referenced rollout envelope; the coordinator authenticates that
relation before submission and `rollout verify` repeats it offline.

The task private key stays on the coordinator. Steward Control receives only exact
signed command bytes and bounded evidence; it never receives either private key.

After the canary invocation returns, inspect its authenticated retained-progress
output and the local status. Do not start the next batch until your own promotion
criteria accept the fixed canary result, evidence boundary, resource state, and
current fleet conditions.

## 7. Advance one later batch at a time

Run the exact same `rollout run` command again when you approve promotion. Each
invocation advances one configured batch, processes its targets sequentially, and
stops before the next batch. Every target in the current batch must pass before a
later batch can start.

```console
stewardctl rollout status -dir "$ROLLOUT_DIR"

# After explicit operator approval, repeat the exact rollout run command.
stewardctl rollout run \
  -dir "$ROLLOUT_DIR" \
  -publisher-public-key publisher.public.pem \
  -publisher-key-id publisher-key-id \
  -site-root-public-key site-root.public \
  -site-root-key-id site-root-1 \
  -witness-public-key steward-control-witness.public.pem \
  -command-private-key tenant-a-commands.private.pem \
  -command-key-id tenant-a-commands \
  -task-private-key hermes-task-approver.private.pem \
  -task-key-id hermes-task-approver \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA"
```

Before any controller request for a later batch, the coordinator writes one
contiguous `batch-promotion-NNN.dsse.json` record, where `NNN` is that nonzero
batch number. The same command key signs the exact plan and plan-authorization
digests, previous promotion digest, completed batch boundary, ordered digests of
each completed target's final state, activation proof, and controller capture, and
the next batch boundary. Its statement uses schema
`steward.rollout-batch-promotion.v1` and DSSE payload type
`application/vnd.steward.rollout-batch-promotion.v1+json`. Every command for the
new batch sets
`authorization_context_digest` to that promotion envelope's digest. Promotion
times are nondecreasing, must follow the completed local state checkpoints, and
command issue times cannot precede their applicable authorization.

This is a signer-attested authorization sequence, not an independently witnessed
wall-clock or host-execution timeline. It also does not record the human reason,
change ticket, quorum, or external approval workflow behind the signature. Preserve
that evidence separately when policy requires it.

When the final target passes, the coordinator writes `proof.json`, an unsigned
aggregate manifest that correlates the exact plan, ordered final target states,
and every target's activation proof. Its `plan_authorization_digest` and ordered
`batch_promotion_digests` bind the signed plan and promotion envelopes. Each target
also records `admit_command_digest`, `start_command_digest`, and
`canary_command_digest` for the exact raw DSSE command envelopes retained in the
workspace. The emitted proof digest therefore commits the exact retained plan,
promotion, and outer-command authorization envelopes. `proof.json` is still not a
signature; the referenced signed
companions remain authoritative.

## Resume after a crash or transport failure

Rerun the exact same `rollout run` command with the same workspace, trust inputs,
private keys, key IDs, controller origin, and credentials. Do not delete a retained
artifact, edit a state file, change a command ID, or create semantically equivalent
replacement authority.

The coordinator stores each authorization and exact command before submission.
After restart it first reconciles the bounded hard-link staging state, authenticates
the retained authorization chain and commands, queries the same controller command
identity, and resumes from the next durable checkpoint. A transport error before a
fixed phase deadline returns without converting the target to a permanent failure,
so a corrected network, controller, or node condition can be retried. Retrying does
not extend the rollout deadline, command validity, canary deadline, or
evidence-capture deadline.

A target that is still `planned` has not started a persistent short preflight
timer. `-preflight-timeout` bounds each controller node-preflight attempt when that
target's batch begins or is retried after a transport failure. Waiting for an
operator to approve a later batch therefore consumes only the rollout's global
deadline; it does not make untouched planned targets fail after 30 seconds.

This makes an interruption recoverable; it does not make an ambiguous external
effect safe to repeat. If the node or controller reports `outcome_unknown`, Steward
fails closed instead of issuing replacement authority.

## Recover from `action_required`

`action_required` is terminal and sticky for that rollout workspace. It can result
from a rejected or failed signed command, revoked or incompatible node, terminal
canary failure, expired authority, `outcome_unknown`, evidence overflow, rollback or
equivocation finding, coordinate conflict, or invalid retained evidence. The
coordinator does not clear the state, skip the target, roll back an earlier target,
or automatically stop or destroy a workload.

Use this recovery sequence:

1. Preserve the complete workspace, controller command records, node evidence, and
   current controller witness information.
2. Inspect `stewardctl rollout status -dir "$ROLLOUT_DIR" -json` for the bounded
   reason, then investigate the controller, Executor, Gateway, and host state.
3. Determine whether the failed target created or started a workload. Do not infer
   absence from a timeout, missing capture, or `outcome_unknown`.
4. Under new explicit authority, stop and destroy the failed workload if your
   recovery decision requires it. Steward does not do this automatically.
5. Create a new rollout workspace. For every replaced activation, use a new
   activation ID and an instance generation greater than the failed activation.
   Issue new bounded command and task authority rather than editing retained bytes.
6. Decide separately what to do with targets that already passed. Steward does not
   implement automatic fleet rollback.

Never remove `action_required` by editing checkpoint files. That destroys the audit
trail and causes authenticated verification to fail.

## Transfer the proof set across an air gap

Run the online rollout inside the disconnected site against its local Steward
Control instance. After the rollout finishes, ensure no rollout command is active
and copy these items to approved media:

- the complete rollout workspace, including its hidden lock file and every target
  artifact and state checkpoint;
- the exact OCI archive supplied to `rollout create`;
- the publisher public key and expected key ID;
- the site-root public key and expected key ID; and
- an independently authenticated copy of the controller witness public key.

Do not copy the command or task private keys to the audit system. The signed command
and permit companions in the workspace are sufficient for verification. Per-target
Gateway receipt public keys and epochs are retained in the workspace, but the
verifier still authenticates their bindings to the plan and signed receipts.

Use an approved byte-preserving transfer. Extract or copy as an unprivileged audit
account into a new trusted parent; do not extract an archive from removable media as
root. Preserve only regular files, reject links and devices, set the copied rollout
directory to mode `0700`, and set its files to mode `0600`. Steward then rejects
unknown filenames, unsafe paths, wrong ownership or permissions, missing artifacts,
and changed bytes when it opens the copy.

The rollout workspace retains a bounded raw canary result and a linear Executor
evidence range that can include unrelated tenant metadata. Protect the media and
audit copy according to the most sensitive tenant represented in those frames.

## Verify the complete rollout offline

On the trusted audit system, point `-archive` at the separately transferred exact
OCI archive:

```console
stewardctl rollout verify \
  -dir "$ROLLOUT_DIR" \
  -archive hermes-agent-adapter.tar \
  -publisher-public-key publisher.public.pem \
  -publisher-key-id publisher-key-id \
  -site-root-public-key site-root.public \
  -site-root-key-id site-root-1 \
  -witness-public-key steward-control-witness.public.pem
```

Add `-json` for machine-readable output. `rollout verify` has no control URL,
bearer token, private-key, Docker, network, or node-socket flag. It verifies the
archive because the workspace retains only its signed identity, not its bytes.

The verifier checks:

- the exact rollout plan, target order, canary-first progression, batch boundaries,
  deterministic target command IDs, and every append-only target checkpoint;
- the common policy-authorized signer's exact plan authorization, contiguous
  evidence-bound batch-promotion chain, authorization order, and the
  `authorization_context_digest` in every retained rollout command;
- the publisher-signed release, embedded capsule, site-root-signed policy, and
  exact archive bytes at the retained plan time;
- each target intent, activation plan, signed `admit`, `start`, and
  `activation-canary` command under the authenticated policy;
- the protocol-4 admission projection, runtime and generation binding, service
  trust, task authority, fixed request, and tenant-signed permit;
- the bounded terminal canary result and signed Gateway authorization, dispatch,
  and terminal receipt chain under the retained per-target Gateway key and epoch;
- Executor's activation-begin and activation-checkpoint order, the exact captured
  receipt range, and the controller witness signature under the independently
  pinned witness key; and
- each target activation proof and the final unsigned aggregate `proof.json`, whose
  `plan_authorization_digest`, ordered `batch_promotion_digests`, and per-target
  `admit_command_digest`, `start_command_digest`, and `canary_command_digest` bind
  the exact signed authorization and outer-command envelopes.

A successful verification establishes that the retained signed authorities and
Steward evidence agree on this exact rollout within the documented host trust
boundary. It does not establish useful behavior beyond the fixed canary, semantic
correctness of agent output, prompt-injection resistance, exactly-once execution
outside one retained Gateway ledger epoch, an uncompromised host, or hardware-backed
attestation. The promotion chain proves what the common command signer authorized
from the retained evidence; it is not independent proof of wall-clock ordering,
host integrity, or the human reasoning behind a promotion.

## Remove retained controller captures after preservation

The runner exports and verifies each sealed controller capture but does not delete
it. Steward Control retains at most 256 captures across all states, so completed
rollouts consume that finite inventory until a site administrator removes them.

First preserve the complete workspace and exact archive, transfer them when
required, and complete `rollout verify` against independently pinned trust. There
is no rollout cleanup or capture-inventory extraction command. Manually inventory
`statement.node_id` and `statement.capture_id` from every
`target-NNN-capture-export.json` in the authenticated workspace, then delete each
retained controller copy:

```console
stewardctl control evidence-capture delete \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -node-id node-a \
  -capture-id capture-id-from-that-target-export
```

Deletion is irreversible. It does not change the already copied rollout proof,
node evidence, command state, or workload, but it removes the controller's recovery
copy. Do not delete a capture until your retention policy accepts the preserved and
authenticated proof set.

## Operational limits

- One rollout binds one release, one policy, one tenant, and one explicit ordered
  node list.
- Target 0 is the fixed canary. Later batches contain at most 16 targets and are
  processed sequentially.
- A plan contains at most 64 targets and lasts at most 24 hours.
- Images must already exist on every target; there is no registry pull, remote
  transfer, or import step in the runner.
- The only accepted canary is the qualified fresh-state Hermes workspace audit.
- The coordinator is invoked by an operator. It is not a daemon, scheduler,
  desired-state controller, or automatic rollback engine.
- The coordinator workspace requires same-filesystem POSIX hard links, reliable
  `fsync` and `flock`, and stable Unix ownership and link-count semantics.
  Unsupported or ambiguous filesystem behavior fails closed; there is no weaker
  fallback.
- Sealed controller captures are not deleted automatically; preserve and verify the
  proof set before manually reclaiming the controller's finite capture inventory.
- A passed workload keeps running. A failed rollout does not stop it or previously
  passed targets.
- The owner-only workspace protects against accidental compliant overwrite, not a
  hostile root user. Verify an authenticated copy on a separate system when node or
  coordinator compromise is in scope.
- Steward evidence proves recorded enforcement within trusted node and controller
  key boundaries. It does not claim RATS, SCITT, SLSA, SPIFFE, or hardware
  attestation conformance.

For the one-node contract underlying each target, read
[proof-carrying agent activation]({{ '/guides/agent-activation/' | relative_url }}).
For controller enrollment, witnessing, and capture capacity, read
[Operate the bundled Steward control plane]({{ '/guides/control-plane/' | relative_url }}).
