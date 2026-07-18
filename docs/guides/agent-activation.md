---
title: Activate a qualified agent release
description: Verify a signed Hermes or OpenClaw release, keep tenant task authority off-node, run its deterministic canary, and retain evidence for offline review.
section: Agent compatibility
---

# Activate a qualified agent release

Steward turns agent deployment into a fixed operator journey:

**choose → configure → preflight → activate → canary → prove → monitor**

Here, a **canary** is one small, tightly specified task run before normal use. It
checks a known path with a known result so failure is easier to interpret than a
free-form agent task.

The journey is intentionally familiar. The trust boundary is not. A hosted
account does not hold the publisher key, tenant task key, site policy, workload,
or final evidence. Steward performs the activation on the customer-owned node and
retains the artifacts needed for independent offline review.

The product principle is simple: **borrow the journey; own the proof**.

Steward has two built-in activation recipes: the qualified Hermes
`steward.workspace-audit` skill and the qualified OpenClaw
`steward-workspace-audit` skill. Both operate on a new workspace. They are closed
recipes, not a general workflow engine. Arbitrary commands, hooks, prompts,
canaries, and automatic winner selection are not accepted.

This recipe is also deliberately limited to a dedicated host whose signed site
policy contains exactly one tenant. Both agents need persistent Docker state, and the
portable local volume driver does not enforce hard byte or inode quotas. The
node-local coordinator also uses the explicitly enabled host-administrator
admission path. Do not enable either compatibility setting on a shared host.

## What each stage means

| Stage | Operator decision | Steward binding |
| --- | --- | --- |
| Choose | Select a release by its useful outcome, required capabilities, qualification evidence, platform, and known limits. | A publisher signature binds the display text, embedded workload capsule, exact offline image archive, fixed canary, qualification digest, and limitations. |
| Configure | Approve the tenant, node, instance generation, site policy, Gateway operation, and task authority. | The release grants no runtime authority. Site policy, instance intent, live Executor admission, and a tenant-signed task permit remain authoritative. |
| Preflight | Authenticate the publisher key and inputs, verify the exact archive, and check the node. | An unsigned plan binds the exact input-file digests, archive digest and size, canary kind, local transport, and finite step timeouts. |
| Activate | Permit Steward to import, admit, and start the exact workload. | After authority, policy, and read-only admission preflights pass, Executor signs an activation-begin marker before the admission-allow receipt, mutation journal, or host mutation. A fixed state machine records each completed phase in an owner-only, append-only activation workspace. |
| Canary | Approve one exact post-admission agent request. | The flow emits an unsigned challenge derived from the real admission response, then waits for a matching bundle signed by the off-node tenant key. |
| Prove | Review the deterministic result and signed enforcement evidence. | After verifying Gateway's authorization, dispatch, and terminal receipts, Steward writes a causal checkpoint into Executor evidence. The proof correlates both activation markers with the release, plan, final state, task and permit, result digest, signed receipt heads, and controller witness export. |
| Monitor | Watch the running workload and evidence state. | Activation ends in `passed`; an invalid canary authorization, terminal canary failure, expired absolute canary deadline, or invalid retained evidence becomes sticky `action_required`. |

## Before you begin

Prepare these inputs through authenticated channels:

- a configured Steward node that passes
  `sudo /usr/local/libexec/steward/node-doctor`;
- a dedicated host with a signed site policy containing exactly one tenant,
  configured with both `--allow-host-admin-intent` and
  `--allow-unquotaed-state-on-dedicated-host`;
- the publisher's Ed25519 public key and expected key ID, obtained separately
  from the release files;
- the signed agent release and the exact offline Open Container Initiative (OCI)
  archive it identifies;
- the publisher's qualification evidence and exact skill manifest identified
  by the release;
- a signed site policy and exact instance intent for a new Hermes or OpenClaw instance;
- a Gateway configuration that exposes only the selected release operation;
- a tenant task-signing station whose private key is not copied to the node; and
- configured Executor evidence publication and controller evidence witnessing,
  plus authenticated receipt and witness public keys for the final proof.

The retained Steward qualifications apply to the documented pinned Hermes and
OpenClaw adapters on `linux/amd64`. A release for another platform needs its own
qualification evidence. Read the [Hermes adapter guide]({{ '/guides/hermes-agent/' | relative_url }})
or [OpenClaw adapter guide]({{ '/guides/openclaw/' | relative_url }}) before
approving the selected image or its requested capabilities.

## 1. Read the release as a decision record

An agent release is outcome-led so an operator can decide what useful work is
being proposed before reasoning about container details. It includes:

- a short title, summary, and observable outcome;
- the publisher-signed workload capsule;
- the SHA-256 digest and byte length of the exact offline archive;
- the archive's image manifest, configuration, and platform identity;
- the selected fixed workspace-audit canary;
- the skill-manifest digest covered by the release signature;
- the qualification-evidence digest and completion time; and
- one to eight explicit limitations.

Display text is signed publisher metadata, not proof that the claimed outcome
occurred. Qualification metadata identifies evidence; it does not independently
establish that the publisher performed the qualification honestly. Authenticate
and inspect the referenced evidence under your own promotion policy.

## 2. Verify the publisher and exact archive

Run verification on a trusted workstation or on the node before activation:

```console
stewardctl agent-release verify \
  -in hermes-workspace-audit.release.dsse.json \
  -public-key publisher.public.pem \
  -key-id publisher-key-id \
  -archive hermes-agent-adapter.tar
```

The filenames in this guide use a Hermes release as the concrete example. For
OpenClaw, use the signed OpenClaw release and its exact `bundle/image.tar`; the
commands and workspace format are otherwise the same.

The command requires the release and embedded capsule to use the same publisher
key and key ID. It validates the capsule at the current time, checks every finite
release field, and verifies that the supplied archive has the signed digest, byte
length, image identity, and platform. It does not import or run the image.

Without `-archive`, verification authenticates the release but reports the archive
as `not_requested`. Do not treat that result as verification of separately
transferred archive bytes.

## 3. Configure authority without widening it

Follow the [signed-admission guide]({{ '/guides/signed-admission/' | relative_url }})
to prepare the site policy and instance intent. The policy must permit the selected
agent profile, required state and service capabilities, and the public task key
for the release service. Its publisher and tenant rules must also allow the release
capsule's exact skill-manifest `{kind, digest}` artifact pair. The intent must bind
the intended tenant, node, instance, lineage, and generation.

Configure the dedicated activation boundary in the same signed-admission
transaction:

```console
sudo /usr/local/libexec/steward/configure-admission \
  --policy /root/steward-trust/site-policy.dsse.json \
  --site-root-public-key /root/steward-trust/site-root.public \
  --site-root-key-id site-root-1 \
  --allow-host-admin-intent \
  --allow-unquotaed-state-on-dedicated-host
```

The installer and `configure-node` accept the same two compatibility flags. The
configuration check rejects the state flag unless the verified policy contains
exactly one tenant. `--allow-host-admin-intent` lets the host-admin loopback credential
select that tenant's signed intent and later append the activation checkpoint; it
is not tenant authentication.
`--allow-unquotaed-state-on-dedicated-host` permits a persistent local Docker
volume without a hard storage quota. Together these settings make this a
dedicated-host workflow, not a shared-host isolation mode.

Configure the release's one qualified operation. The shortest safe setup is:

```console
sudo stewardctl gateway service set \
  -config /etc/steward/gateway.json \
  -agent openclaw \
  -tenant-budget tenant-a=4194304
```

Use `-agent hermes` for Hermes. The preset fixes the service ID, operation,
`POST /v1/runs` path, lifecycle status prefix, content type, and hardened limits.
It cannot be combined with manual service, operation, or lifecycle flags.
The release does not authorize:

- a tenant, node, or instance;
- image import or workload admission;
- inference, connector, egress, or private-service access;
- a task-signing key; or
- the canary request.

Those decisions remain separate so a compromised publisher cannot deploy itself
and a compromised node cannot manufacture tenant approval.

## 4. Capture a baseline witness

Activation needs a controller-signed Executor evidence checkpoint from before the
workload is admitted. On a trusted operator workstation, first confirm the
controller reports `current` with no finding, then export a new owner-only file:

```console
stewardctl control evidence status \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -node-id node-a

stewardctl control evidence export \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -node-id node-a \
  -out node-a.activation-baseline.json

stewardctl control evidence verify \
  -in node-a.activation-baseline.json \
  -witness-public-key steward-control-witness.public.pem
```

Transfer the verified export to the node through an authenticated channel and
keep it mode `0600`. The baseline must be a current, finding-free checkpoint for
the activation's exact node and enrolled receipt identity.

## 5. Create the owner-only activation workspace

Create a trusted parent directory and an absent activation path. `activation
create` verifies the signed trust bindings, snapshots the release, policy, intent,
archive, and baseline witness into the new workspace, then verifies the copied
archive before it publishes the unsigned plan and first state checkpoint:

```console
sudo install -d -o root -g root -m 0700 /var/lib/steward-node/activations
ACTIVATION_DIR=/var/lib/steward-node/activations/hermes-audit-001

sudo stewardctl activation create \
  -dir "$ACTIVATION_DIR" \
  -release /root/steward-activation-inputs/hermes-workspace-audit.release.dsse.json \
  -policy /root/steward-activation-inputs/site-policy.dsse.json \
  -intent /root/steward-activation-inputs/instance-intent.json \
  -archive /root/steward-activation-inputs/hermes-agent-adapter.tar \
  -publisher-public-key /root/steward-activation-inputs/publisher.public.pem \
  -publisher-key-id publisher-key-id \
  -site-root-public-key /root/steward-activation-inputs/site-root.public \
  -site-root-key-id site-root-1 \
  -baseline-witness /root/steward-activation-inputs/node-a.activation-baseline.json \
  -witness-public-key /root/steward-activation-inputs/steward-control-witness.public.pem
```

Omit `-activation-id` to generate a random stable ID, or set one bounded ID
explicitly. The optional timeout flags and defaults are:

| Flag | Default |
| --- | ---: |
| `-preflight-timeout` | `30s` |
| `-image-import-timeout` | `30m` |
| `-admission-timeout` | `1m` |
| `-startup-timeout` | `2m` |
| `-canary-timeout` | `5m` |
| `-evidence-timeout` | `1m` |

Every timeout must be a whole number of seconds from one second through 24 hours.
The plan records these values. Most timeouts bound one command attempt.
`-canary-timeout` is different: once the runner records `canary_authorized`, it
creates one absolute deadline for submission, lost-response recovery, and
terminal observation. Rerunning does not reset that deadline. If it expires, the
runner records sticky `action_required` with reason `canary_timeout`; that
activation cannot resume. The workspace path must not already exist; its existing
parent and ancestors must be directories owned by root or the effective user. A
user-owned ancestor cannot be group- or world-writable. A writable root-owned
ancestor is accepted only when it has the sticky bit, as `/tmp` normally does.

The coordinator holds an exclusive advisory workspace lock for each command
invocation, accepts only a bounded allowlist of artifact names, creates generated
files once, and writes state as new sequential checkpoints. It never overwrites or
deletes a generated artifact.

## 6. Run to the off-node signing handoff

Run the activation with the same publisher, site-root, and controller-witness
trust inputs:

```console
sudo stewardctl activation run \
  -dir "$ACTIVATION_DIR" \
  -publisher-public-key /root/steward-activation-inputs/publisher.public.pem \
  -publisher-key-id publisher-key-id \
  -site-root-public-key /root/steward-activation-inputs/site-root.public \
  -site-root-key-id site-root-1 \
  -witness-public-key /root/steward-activation-inputs/steward-control-witness.public.pem
```

The default local runtime paths are:

| Flag | Default |
| --- | --- |
| `-node-url` | `http://127.0.0.1:8090` |
| `-node-token-file` | `/etc/steward/executor-token` |
| `-gateway-config` | `/etc/steward/gateway.json` |
| `-docker-socket` | `/var/run/docker.sock` |
| `-executor-evidence-log` | `/var/lib/steward-executor/evidence.bin` |

Pass an explicit override only when the installed node uses another trusted local
path. The command verifies the retained inputs again, imports the exact archive,
creates a canonical activation-begin assertion, and submits its digest with the
signed admission request. Executor appends that digest to its signed receipt
stream after authority, policy, image, capacity, and other read-only preflights
pass, but before the admission-allow receipt, mutation journal, or host mutation.
It then persists the activation identity with the runtime. The command starts
the selected agent, derives the tenant-specific service policy from the current Gateway
configuration, and writes the canary request and challenge.

The `release_verified` state is a local resumability checkpoint. It is not
historical proof that the release, capsule, site policy, or task was valid. Live
preflight, image import, and fresh admission use current-time checks. Final
evidence collection and offline verification independently re-evaluate the exact
release, capsule, site policy, retained intent, and task at the signed timestamp
of Gateway's authorization receipt. Recovery can finish after an input expires
only when that signed receipt proves it was valid when Gateway authorized the
canary.

At the first handoff, the JSON result has phase `canary_challenge_ready`,
`waiting_for: "canary_task"`, and `verified: true`. Copy these exact files from
the activation workspace to the trusted signing station:

- `canary.challenge.json`
- `admission.json`
- `intent.json`
- `service-trust.json`
- `canary.request.json`

The challenge grants no authority and is not self-authenticating. It lets the
signer review the activation, release, admission, intent, service-policy, request,
runtime, grant, and public-authority digests together. `task issue` does not consume
the challenge directly; the next verified `activation run` checks that the
returned task matches every challenge binding.

On the signing station, issue and verify one short-lived task with the admitted
tenant key:

```console
AGENT_OPERATION=openclaw.run # use hermes.run for a Hermes release
stewardctl task issue \
  -admission admission.json \
  -intent intent.json \
  -trust service-trust.json \
  -request canary.request.json \
  -operation-id "$AGENT_OPERATION" \
  -valid-for 5m \
  -clock-skew 5s \
  -key agent-task-approver.private.pem \
  -key-id agent-task-approver \
  -out canary.task.json

stewardctl task verify \
  -in canary.task.json \
  -public-key agent-task-approver.public \
  -key-id agent-task-approver \
  -request canary.request.json
```

The task must expire no later than the embedded workload capsule. Choose
`-valid-for` so the resulting expiry stays within that signed validity window.
This prevents a canary authorization from extending the release's workload
authority.

Transfer only `canary.task.json` back to the node, preserve mode `0600`, and attach
it once:

```console
sudo stewardctl activation attach \
  -dir "$ACTIVATION_DIR" \
  -kind canary-task \
  -in /root/steward-activation-inputs/canary.task.json
```

The attachment command validates the bundle's strict signed shape. The next run
performs the complete release, admission, service, request, and challenge binding.
Run the same `stewardctl activation run` command again.

The effective tenant-specific service policy derived from
`/etc/steward/gateway.json` must remain byte-for-byte consistent while live
submission, observation, or Gateway receipt collection remains necessary. Do not
change or reorder that configuration during those phases. If the derived bytes
differ, restore the exact policy and rerun.

## 7. Require the deterministic agent result

Both canaries use session ID `steward-activation-<activation-id>`, a newly admitted
state lineage, and the exact skill-manifest digest from the release. Hermes uses
input `STEWARD_WORKSPACE_AUDIT` and must return its canonical empty-workspace
manifest. OpenClaw uses message `Run the Steward workspace audit.` and must return
one sanitized success payload, exactly one `exec` tool call, no media or tool
failure, and the descriptor-verified qualification workspace digest. The OpenClaw
terminal also binds the activation session and an independently recomputed digest
of the sanitized result.

Agent-reported completion is insufficient. Steward selects the verifier from the
signed release, rejects every other canary kind, and requires the exact canonical
terminal shape and qualified workspace identity.

This canary demonstrates that the admitted agent service accepted the exact
tenant-authorized request and returned the one qualified fresh-state result while
Steward recorded the dispatch path. It does not prove arbitrary prompts, models,
plugins, skills, workspace contents, or future agent behavior are safe or correct.

If the submit response is lost after Gateway durably records dispatch, Steward
queries the exact task and permit identity. A durable dispatch or completed status
creates `canary.submit.json` with receipt marker `recovered`, the original run ID,
and the Gateway receipt node, epoch, and public key. Observation then resumes
without authorizing another dispatch.

Before reporting `waiting_for: "final_witness"`, `activation run` verifies the
three signed Gateway receipts for authorization, dispatch, and the terminal
result. It re-evaluates the exact task and retained activation inputs at Gateway's
signed authorization time, then asks Executor to append a content-free
`activation_checkpoint` receipt. The request carries the activation ID and
checkpoint digest, not the begin digest. Executor matches the begin digest
persisted with the runtime to its earlier signed marker, requires ready
reconciliation, and proves the exact runtime topology remains running. This
node-local request uses the explicitly enabled host-administrator authority; the
loopback bearer is not tenant authentication. The checkpoint digest binds the
exact activation, release, Gateway receipt slice and terminal coordinate, canary
result digest, and Gateway-signed authorization and terminal times. Only after
that causal join is durable does the command stop with phase
`agent_reported_terminal` and `verified: true`.

If the coordinator stops after recording the terminal state but before retaining
the Executor checkpoint, `activation status` reports
`waiting_for: "activation_checkpoint"` and tells the operator to rerun
`activation run`. Steward rejects a final-witness attachment until the local
checkpoint assertion exists, preventing an early write-once witness from becoming
an unrecoverable stale input.

## 8. Attach a post-checkpoint final witness

Wait for the node's asynchronous evidence uplink to advance the controller
checkpoint beyond the signed `activation_checkpoint` receipt, then create a new
export:

```console
stewardctl control evidence status \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -node-id node-a

stewardctl control evidence export \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -node-id node-a \
  -out node-a.activation-final.json

stewardctl control evidence verify \
  -in node-a.activation-final.json \
  -witness-public-key steward-control-witness.public.pem
```

The final export must be current, finding-free, use the same controller,
enrollment, receipt, and witness identities as the baseline, and have a greater
receipt sequence. During live collection, the local Executor log must contain the
witnessed coordinate and prove this order:

`activation_begin` → fresh admission allow → admission commit → runtime start →
`activation_checkpoint` → final witness head

This signed sequence, rather than a comparison between Gateway and controller
clocks, proves that the final witness followed verified terminal Gateway evidence.
Unrelated tenant receipts may follow the witnessed head in the live log, but any
later receipt for this activation makes the witness stale. Matching stop, destroy,
revocation, state purge, drift, post-start compensation, or unresolved workload
or state-purge preparation evidence inside the witnessed slice also blocks
`passed`. A fully compensated failure before the proven successful start remains
retryable. Do not attach the export until these conditions hold because
attachments are write-once.

Transfer the final export to the node as an owner-only file, attach it, and rerun
the exact activation command:

```console
sudo stewardctl activation attach \
  -dir "$ACTIVATION_DIR" \
  -kind final-witness \
  -in /root/steward-activation-inputs/node-a.activation-final.json

sudo stewardctl activation run \
  -dir "$ACTIVATION_DIR" \
  -publisher-public-key /root/steward-activation-inputs/publisher.public.pem \
  -publisher-key-id publisher-key-id \
  -site-root-public-key /root/steward-activation-inputs/site-root.public \
  -site-root-key-id site-root-1 \
  -witness-public-key /root/steward-activation-inputs/steward-control-witness.public.pem
```

The coordinator verifies the complete local Executor evidence log, extracts the
signed frame range between the baseline and final witness coordinates, verifies
the exact Gateway task receipts and canary result, writes `proof.json`, and
advances to `passed`. The proof includes the exact activation-begin and
activation-checkpoint digests so an offline verifier can require both signed
markers and their causal order.

The portable Executor delta preserves every signed receipt frame needed to span
the two witness coordinates, including unrelated node receipts interleaved with
the activation. The current recipe requires one policy tenant, but older retained
history or other node operations can still appear in the signed range. Executor
receipt frames exclude prompts, request bodies, result bodies, and workspace
content. The activation workspace separately retains the bounded canary result
and should be handled as sensitive operational evidence.

## 9. Verify the portable proof offline

A completed activation retains the exact plan and final state, the bounded raw
canary result, the task and permit identities, the relevant Executor and Gateway
evidence coordinates, the matching controller witness coordinate, and a proof
manifest that correlates them.

Copy the complete workspace and public keys to a trusted audit system while
preserving the exact artifact bytes and owner-only directory boundary. The
packaged Gateway receipt public key is normally
`/etc/steward/connector-receipts.public` on the node.

Run the complete verifier:

```console
stewardctl activation verify \
  -dir "$ACTIVATION_DIR" \
  -publisher-public-key publisher.public.pem \
  -publisher-key-id publisher-key-id \
  -site-root-public-key site-root.public \
  -site-root-key-id site-root-1 \
  -witness-public-key steward-control-witness.public.pem \
  -gateway-receipt-public-key connector-receipts.public
```

`activation verify` is fully offline and has no network, client, Docker, or socket
flags. It authenticates and correlates the release and capsule, exact archive,
site policy and intent, complete state chain, admission, challenge, tenant task,
deterministic result, portable Executor delta, Gateway task receipts, baseline and
final controller witnesses, and final proof. Executor's receipt public key is
derived from the enrolled identity proof in the signed baseline witness; Gateway's
separate public key must be supplied explicitly.
The verifier requires that key to match the historical public key retained in
`canary.submit.json` byte for byte and checks its node, epoch, and proof key hash.
After a Gateway receipt-key rotation, use the dispatch-time key retained by the
operator, not merely the current packaged key.

The proof records identities, digests, sizes, timestamps, and receipt coordinates.
It does not place prompts, request bodies, result bodies, or agent logs in the
manifest. The raw canary result remains a separate bounded companion.

The proof manifest itself is unsigned. `activation verify`, rather than parsing
`proof.json` alone, establishes authenticity from the signed companions and pinned
keys. Use a verifier that recognizes the closed `activation_begin` and
`activation_checkpoint` Executor event types. An older verifier rejects those
event types instead of silently ignoring evidence it does not understand.

## Monitor and recover

| State or event | Operator response |
| --- | --- |
| `passed` | Retain the complete activation workspace and continue normal node, workload, and evidence monitoring. Passing the canary is an activation gate, not permanent health proof. |
| Local file, Docker, Executor, Gateway, network, or incomplete evidence-source error | Correct the transient condition and rerun the exact same `activation run` command while the applicable deadline remains open. The last completed checkpoint remains resumable and completed steps are revalidated rather than repeated with new authority. |
| Executor readiness is degraded while writing the activation checkpoint | Reconcile the node until `GET /v1/readiness` returns ready, then rerun. Executor does not append a checkpoint while reconciliation is degraded. |
| Invalid attached canary authorization or binding | The runner records sticky `action_required` with reason `canary_authorization_invalid`. Preserve the workspace and follow the replacement procedure below. |
| Canary submission is terminally rejected, the agent reports a non-completed terminal state, or the completed result fails the closed recipe | The runner records sticky `action_required` with reason `canary_terminal_failure`. Do not replace the task or clear the checkpoint; follow the replacement procedure below. |
| Retained evidence is invalid or conflicts with already published bytes | The runner records sticky `action_required` with reason `evidence_invalid`. Preserve the workspace for investigation and follow the replacement procedure below; retry cannot change write-once evidence. |
| Timeout after task submission, before the absolute canary deadline | The task may have reached the agent. Rerun the same activation with the same retained bundle; Gateway recovers or replays its durable task identity without another authorized dispatch. |
| Absolute canary deadline expired | The runner records sticky `action_required` with reason `canary_timeout`. Retry cannot extend or resume that activation. |
| Current Gateway service policy differs | Restore the exact byte-consistent tenant service policy and rerun. The mismatch does not silently widen or replace the retained policy. |
| Sticky `action_required`, or changed policy, intent, release, or archive | Correct or investigate the failure, stop and destroy the failed workload, then start a distinct activation with a new activation ID and an instance generation greater than the failed activation. Do not rewrite or resume the old evidence history. |
| Suspected node compromise | Stop trusting the node-local workspace. Quarantine the host and verify authenticated copies on a separate trusted system; rebuild the node before reuse. |

`activation run` is resumable and idempotent against its retained checkpoints and
write-once artifacts. `passed` and `action_required` are terminal; phases cannot be
skipped or reordered.

For a quick local progress view:

```console
sudo stewardctl activation status -dir "$ACTIVATION_DIR"
```

`activation status` and `activation attach` return only unsigned local workspace
summaries and always report `verified: false`. A run that performs live
verification or advances a nonterminal phase reports `verified: true`; replaying
an already terminal `passed` or `action_required` workspace reports
`verified: false` because it does not repeat complete proof verification. Use
`activation verify` for authenticated final assurance.

Append-only storage prevents ordinary retries and a second compliant coordinator
from silently rewriting history. It is not hardware-backed attestation or a
host-compromise defense. Host root or another process with the same operating
system authority can bypass an advisory lock or corrupt local bytes.

The `stewardctl activation` flow documented here remains node-local. For remote
nodes, the separate operator-side rollout coordinator uses protocol-4 bounded
admission and canary projections, a signed exact plan, chained evidence-bound batch
promotions, exact signed commands, and controller evidence capture without moving
either private signing key into Steward Control. See
[Proof-carrying fleet rollout]({{ '/guides/fleet-rollout/' | relative_url }}).

## Publisher-only: issue an agent release

Publishers create a release only after building and qualifying the exact archive.
Use the same Ed25519 publisher key and key ID that signed the embedded capsule:

```console
stewardctl agent-release issue \
  -capsule hermes.capsule.dsse.json \
  -archive hermes-agent-adapter.tar \
  -skill-manifest steward.workspace-audit.manifest.json \
  -qualification-evidence hermes-qualification.json \
  -release-id hermes-workspace-audit-site-build-001 \
  -title "Audit a Hermes workspace" \
  -summary "Run the signed Steward workspace-audit skill in a newly admitted Hermes instance." \
  -outcome "Return the canonical empty-workspace manifest through one tenant-authorized Hermes run." \
  -completed-at 2026-07-16T12:00:00Z \
  -limitation "Qualified only for the exact documented linux/amd64 adapter under runsc." \
  -key publisher.private.pem \
  -key-id publisher-key-id \
  -out hermes-workspace-audit.release.dsse.json
```

Replace the completion time with the actual qualification completion time in
canonical UTC `YYYY-MM-DDTHH:MM:SSZ` form. Repeat `-limitation` for every material
known limit, up to eight entries. The command inspects and binds the supplied
files; it does not perform the qualification or establish the truth of its
evidence.
