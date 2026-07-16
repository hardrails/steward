---
title: Local operator tools
description: Issue and verify signed agent releases, inspect OCI archives, create control TLS material, verify evidence, and check durable-state compatibility with stewardctl.
section: Reference
---

# Local operator tools

`stewardctl agent-release` issues and verifies outcome-led signed agent releases,
`stewardctl image` inspects and imports image media, `stewardctl permit` signs and
audits exact connector authority, `stewardctl task` signs and audits exact
agent-service requests, and `stewardctl evidence` verifies receipts without a
registry, transparency service, or vendor control plane. Within those command
groups, the signing, verification, audit, and archive-inspection operations use only
local files; `image import` contacts Docker after offline verification. Commands
under `stewardctl node` contact the local Executor API. `stewardctl task submit`,
`status`, `observe`, and `wait` contact an explicit literal-loopback Gateway origin;
task issue, verify, and audit remain offline. `stewardctl control evidence export`
contacts the customer-owned controller, while `stewardctl control evidence verify`
checks that portable export entirely offline against a separately pinned witness
public key.

## Signed agent releases

An agent release is a publisher-signed description of one qualified outcome. It
binds an embedded signed capsule, the exact offline archive digest and byte length,
the archive's image identity, one fixed Hermes canary, the qualification-evidence
digest, and explicit limitations. It grants no tenant, node, image-import,
capability, or task authority.

Issue a release with the same Ed25519 publisher key and key ID that signed the
embedded capsule:

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

`-completed-at` must be the real qualification completion time in canonical UTC
`YYYY-MM-DDTHH:MM:SSZ` form. Supply one through eight distinct `-limitation`
values. The command reads at most 1 MiB for the skill manifest and 4 MiB for
qualification evidence, inspects the bounded archive, creates a new mode-`0600`
DSSE envelope, and refuses to overwrite an existing output.

The command hashes the supplied skill manifest and qualification evidence. It does
not parse those files, perform the qualification, or prove their claims. The
embedded capsule must already identify the same skill-manifest digest and exact
image tuple, use the built-in Hermes service profile, and be valid at issuance.

Verify a release with a publisher public key obtained through an independent
authenticated channel:

```console
stewardctl agent-release verify \
  -in hermes-workspace-audit.release.dsse.json \
  -public-key publisher.public.pem \
  -key-id publisher-key-id \
  -archive hermes-agent-adapter.tar
```

Verification checks the release signature, the embedded capsule under the same key
and key ID, all duplicated bindings, the capsule validity period, and the closed
Hermes canary. With `-archive`, it also verifies the exact archive digest, length,
manifest, configuration, and platform identity without importing the image.
Without that flag, the JSON output reports `archive.status` as `not_requested`.

Both commands emit bounded JSON containing the release identity, publisher key,
release and capsule digests, outcome display, archive and image identity, canary,
qualification, and verification status. See
[agent activation]({{ '/guides/agent-activation/' | relative_url }}) for the
authority boundary and the complete operator journey.

## Proof-carrying agent activation

`stewardctl activation` coordinates one fixed Hermes workspace-audit activation.
It retains exact inputs, write-once handoff artifacts, sequential state
checkpoints, and the final portable proof in an owner-only workspace. The
coordinator does not hold the tenant task-signing key.

The current recipe requires a dedicated host, a signed site policy with exactly
one tenant, and Executor configured with both
`-admission-allow-host-admin-intent` and
`-allow-unquotaed-state-on-dedicated-host`. The packaged configuration helpers
expose these as `--allow-host-admin-intent` and
`--allow-unquotaed-state-on-dedicated-host`. The persistent volume has no hard
byte or inode quota, and the local token has host-administrator authority for
both admission and the later activation checkpoint. It is not tenant
authentication. Do not use this recipe on a shared host.

Create a new workspace from the signed release, exact archive, site authority,
instance intent, and a current finding-free controller witness captured before
admission. Steward snapshots the archive into the workspace and verifies that
copy before publishing the activation plan:

```console
stewardctl activation create \
  -dir "$ACTIVATION_DIR" \
  -release hermes-workspace-audit.release.dsse.json \
  -policy site-policy.dsse.json \
  -intent instance-intent.json \
  -archive hermes-agent-adapter.tar \
  -publisher-public-key publisher.public.pem \
  -publisher-key-id publisher-key-id \
  -site-root-public-key site-root.public \
  -site-root-key-id site-root-1 \
  -baseline-witness node-a.activation-baseline.json \
  -witness-public-key steward-control-witness.public.pem
```

`-activation-id` is optional. If omitted, Steward generates a stable random ID.
The plan records these optional timeout flags:

| Flag | Default |
| --- | ---: |
| `-preflight-timeout` | `30s` |
| `-image-import-timeout` | `30m` |
| `-admission-timeout` | `1m` |
| `-startup-timeout` | `2m` |
| `-canary-timeout` | `5m` |
| `-evidence-timeout` | `1m` |

Each timeout must be a whole number of seconds from one second through 24 hours.
Most values bound one command attempt. The canary timeout becomes one absolute
deadline when `canary_authorized` is recorded. Submission, lost-response
recovery, and terminal observation share that deadline, and rerunning does not
reset it. Expiry records sticky `action_required` with reason `canary_timeout`;
the activation cannot resume.
The workspace path must not exist. Its existing parent and ancestors must be
directories owned by root or the effective user. A user-owned ancestor cannot be
group- or world-writable; a writable root-owned ancestor is accepted only with the
sticky bit.

Advance the activation with the same pinned trust inputs:

```console
stewardctl activation run \
  -dir "$ACTIVATION_DIR" \
  -publisher-public-key publisher.public.pem \
  -publisher-key-id publisher-key-id \
  -site-root-public-key site-root.public \
  -site-root-key-id site-root-1 \
  -witness-public-key steward-control-witness.public.pem
```

The local runtime flags have these packaged defaults:

| Flag | Default |
| --- | --- |
| `-node-url` | `http://127.0.0.1:8090` |
| `-node-token-file` | `/etc/steward/executor-token` |
| `-gateway-config` | `/etc/steward/gateway.json` |
| `-docker-socket` | `/var/run/docker.sock` |
| `-executor-evidence-log` | `/var/lib/steward-executor/evidence.bin` |

Override a flag only when the installed node uses a different trusted local path
or literal-loopback Executor origin. The `release_verified` state is a local
resumability checkpoint, not historical authorization evidence. Live preflight,
image import, and fresh admission use current-time checks. Final evidence
collection and offline verification re-evaluate the exact release, capsule, site
policy, retained intent, and task at the signed timestamp in Gateway's
authorization receipt.

Gateway configuration is loaded only while live preflight, submission,
observation, or receipt collection remains necessary. A workspace with a complete
retained terminal result and status, complete retained evidence,
or `evidence_collected` can continue without a usable Gateway config, receipt
private key, ledger, Executor endpoint, Docker socket, or live evidence source.
Terminal `passed` and `action_required` workspaces can be reopened for status
without those live dependencies, but `action_required` cannot resume.

The first handoff stops at `canary_challenge_ready` with
`waiting_for: "canary_task"`. Copy these files to the tenant signing station:

- `canary.challenge.json`
- `admission.json`
- `intent.json`
- `service-trust.json`
- `canary.request.json`

After reviewing the unsigned challenge and authenticated companion files, issue
one task with the tenant key:

```console
stewardctl task issue \
  -admission admission.json \
  -intent intent.json \
  -trust service-trust.json \
  -request canary.request.json \
  -operation-id hermes.run \
  -valid-for 5m \
  -clock-skew 5s \
  -key hermes-task-approver.private.pem \
  -key-id hermes-task-approver \
  -out canary.task.json

stewardctl task verify \
  -in canary.task.json \
  -public-key hermes-task-approver.public \
  -key-id hermes-task-approver \
  -request canary.request.json
```

The canary task must expire no later than the embedded workload capsule. Set
`-valid-for` so the issued permit remains inside that signed validity window.

Return the owner-only bundle to the node, attach it once, and rerun the same
`activation run` command:

```console
stewardctl activation attach \
  -dir "$ACTIVATION_DIR" \
  -kind canary-task \
  -in canary.task.json
```

The next `run` performs the complete activation and challenge binding. The
tenant-specific service policy derived from the current Gateway configuration
must remain byte-for-byte consistent while live submission, observation, or
Gateway receipt collection remains necessary. If it changes during those phases,
restore the exact configuration and rerun.

After Hermes reports a verified terminal result, the coordinator verifies
Gateway's signed authorization, dispatch, and terminal receipts; re-evaluates the
task and retained activation inputs at Gateway's signed authorization time; and
asks Executor to append a content-free signed activation checkpoint. That request
contains the activation ID and checkpoint digest, not the begin digest. Executor
matches the persisted begin digest to its earlier signed marker, requires ready
reconciliation, and proves the exact runtime topology is still running. The
node-local request uses the explicitly enabled host-administrator authority. It
then stops at `agent_reported_terminal` with `waiting_for: "final_witness"`.
Obtain a signed controller evidence export after the evidence uplink has published
that checkpoint:

If a crash leaves the phase at `agent_reported_terminal` before the checkpoint
artifact is retained, `activation status` reports
`waiting_for: "activation_checkpoint"`. Rerun `activation run`; `activation
attach -kind final-witness` remains blocked until the checkpoint exists.

```console
stewardctl control evidence export \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -node-id node-a \
  -out node-a.activation-final.json
```

Verify that the export is current, finding-free, later than the baseline, and
includes this signed order:

`activation_begin` → fresh admission allow → admission commit → runtime start →
`activation_checkpoint` → final witness head

The local Executor log must contain that coordinate. This receipt order provides
the causal link; Gateway and controller clocks are not compared. Unrelated tenant
receipts may follow the witnessed head in the live log, but a later receipt for
this activation or a matching lifecycle-invalidating event fails the activation.
Verify before attachment because attachments are write-once:

```console
stewardctl control evidence verify \
  -in node-a.activation-final.json \
  -witness-public-key steward-control-witness.public.pem

stewardctl activation attach \
  -dir "$ACTIVATION_DIR" \
  -kind final-witness \
  -in node-a.activation-final.json
```

Rerun the same `activation run` command to collect the bounded Executor evidence
delta, verify Gateway receipts, write `proof.json`, and reach `passed`. The proof
records the exact activation-begin and activation-checkpoint digests so offline
verification requires both signed markers and their order.

`activation run` is resumable and idempotent against retained checkpoints while
the applicable deadline remains open. Transient local file, Docker, Executor,
Gateway, network, and incomplete evidence-source errors remain retryable after
the operator corrects the condition. Degraded Executor readiness blocks the
activation checkpoint until reconciliation succeeds. An attached task that fails
the full activation binding records sticky `action_required` with
`canary_authorization_invalid`; a terminal submit rejection, non-completed Hermes
state, or completed result that fails the closed recipe records
`canary_terminal_failure`; an expired absolute canary deadline records
`canary_timeout`; invalid or conflicting retained evidence records
`evidence_invalid`. These terminal states cannot resume. Preserve the failed
workspace, stop and destroy its workload, then create a new activation ID with an
instance generation greater than the failed activation. The coordinator does not
mint replacement task authority.

Inspect local progress with:

```console
stewardctl activation status -dir "$ACTIVATION_DIR"
```

This status command intentionally verifies only unsigned workspace consistency
and always reports `verified: false`. Do not treat it as authenticated evidence.

On a disconnected audit system, verify the complete copied workspace and its
signed companions:

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

`activation verify` has no network, Docker, client, or socket dependency.
Executor's receipt public key comes from the enrolled identity proof in the
baseline witness. Gateway's receipt public key is separate; the packaged copy is
normally `/etc/steward/connector-receipts.public`.
`canary.submit.json` retains the exact task and permit digests, run ID, dispatch
receipt marker, receipt node, epoch, and Gateway public key. Offline verification
requires the supplied historical Gateway key to match those bytes and the proof;
the current packaged key may differ after rotation.

Use a verifier that reads Executor evidence formats 1 through 2 and recognizes
the closed `activation_begin` and `activation_checkpoint` event types. Older
format-1-only verifiers reject those event types rather than silently skipping
evidence they do not understand.

The portable Executor delta spans the signed receipt coordinates between the two
controller witnesses. The current recipe requires one policy tenant, but the range
can still include unrelated node receipts or older retained history. Executor
receipt frames exclude prompts, request bodies, result bodies, and workspace
content. The activation workspace separately retains the bounded canary result and
remains sensitive operational evidence.

See [Activate a qualified Hermes release]({{ '/guides/agent-activation/' | relative_url }})
for input preparation, the baseline-witness procedure, phase semantics, and proof
limits.

## Controller TLS material

`stewardctl control pki create` generates an ECDSA P-256 local certificate
authority and one server certificate without contacting a network service. Supply
one comma-separated, canonical set of DNS names and IP addresses through
`-server-names` plus four distinct new output paths:

```console
stewardctl control pki create \
  -server-names control.customer.example,10.20.0.10 \
  -ca-cert-out ca.crt \
  -ca-key-out ca.key \
  -server-cert-out control.crt \
  -server-key-out control.key
```

The CA has a path-length-zero constraint and certificate-signing use only. The
server certificate has server-authentication use only. Private keys are PKCS#8 PEM
files created mode `0600`; certificates are mode `0644`. No output may already
exist or be a symbolic link. The command reserves all four names before writing,
syncs each file and parent directory, and removes the set if a write or summary
fails. Standard output contains only certificate fingerprints, canonical names,
and expiry times as JSON.

The default CA lifetime is five years and the default server lifetime is one year.
`-ca-valid-for` accepts 30 days through 10 years;
`-server-valid-for` accepts one hour through 398 days and cannot exceed the CA.
This tool creates files, not an online CA or rotation service. Protect the CA key
offline when practical and issue a new bounded server certificate before expiry.

## Controller evidence witness exports

A site administrator can create one portable checkpoint from a connected operator
workstation:

```console
stewardctl control evidence export \
  -control-url https://control.customer.example:8443 \
  -token-file /secure/steward-control/site-admin.token \
  -ca-file /secure/steward-control/ca.crt \
  -node-id node-a \
  -out node-a.evidence-witness.json
```

The command creates an absent mode-`0600` file and never overwrites an existing
path or symbolic link. The export contains the enrollment-time receipt-key
proof, the controller's latest last-good checkpoint, any sticky rollback or
equivocation finding, the exact historical checkpoint used to classify that
finding, and the export time. It does not contain the full receipt log, prompts,
request bodies, or agent output.

Verify it on a disconnected audit station:

```console
stewardctl control evidence verify \
  -in node-a.evidence-witness.json \
  -witness-public-key steward-control-witness.public.pem
```

The verifier reads only local files. It checks the receipt identity, current and
historical checkpoint ordering, rollback or equivocation semantics, controller
witness signature, and exact match with the supplied Ed25519 public key. The key
embedded in the export is not trusted by itself. Copy the controller's
`witness.public.pem` through an independent authenticated channel and record its
SHA-256 digest when establishing the audit identity. A wrong key, changed signed
field, duplicate or unknown JSON field, or inconsistent node identity fails
verification. Reformatting equivalent JSON does not change the signed statement.

## Upgrade inspection

After stopping Steward's node services, inspect retained workload state and verify
that the target manifest can read every observed durable format:

```console
TARGET_RELEASE="<release-tag>"
sudo "/opt/steward/releases/$TARGET_RELEASE/stewardctl" upgrade check-drained \
  -signed-admission configured \
  -gateway-config /etc/steward/gateway.json \
  -release-manifest "/opt/steward/releases/$TARGET_RELEASE/release.json"
```

Use `-signed-admission unconfigured` only when signed admission is intentionally
disabled. Configured mode requires the fence, journal, and evidence files to exist.
Both modes validate any file that is present. Packaged paths are defaults; explicit
flags can select the admission fence, operation journal, Executor evidence log,
Executor lifecycle uplink fence, Executor delivery ledger, supervisor state, and
Gateway files.

The bounded JSON result reports active fences, pending journal operations, retained
Gateway grants, eight observed format versions, target compatibility, and
`drained`. The inventory includes the Gateway connector receipt log. A `null`
format means the file is absent or, for the Executor evidence log, has no record
header yet. Tombstone fences preserve replay history but do not count as active.
The command exits nonzero when workload or grant state remains, a file is malformed
or missing when required, or the target reader/writer range is unsafe.

Connector receipt format 1 contains ordinary connector records. Format 2 adds
connector action permits. Format 3 is the historical two-record service-task
contract. Current lifecycle service tasks use format 4, with task-local sequence
and hash links across authorization, dispatch, and terminal records. One verified
chain may contain all four formats. The observed format is the highest schema
present. It is at least 2 when Gateway configures an action authority and 4 when it
configures a current service-task operation, even before the receipt file exists or
that operation is used, because live configuration can write that format. A target
whose manifest cannot read and preserve the observed format is incompatible.

Executor evidence format 1 contains the original closed event vocabulary. Format 2
adds `activation_begin` and `activation_checkpoint`. A signed evidence chain may
contain both versions; the observed format is the highest receipt version present.
The begin marker is fsynced after read-only admission preflights and before the
admission-allow receipt, mutation journal, or host mutation. Its format 2 receipt
therefore remains an upgrade boundary even after the workload is destroyed. A
target whose evidence reader stops at format 1 is incompatible with that log.

Gateway state format 4 retains the service ID and public tenant task authorities of
task-enabled grants. A target release must read and preserve that state even if the
receipt ledger has not yet recorded a service task. Keep state and receipt-format
compatibility checks together; neither file can be downgraded safely in isolation.

`upgrade inspect-formats` returns the same eight format observations without
requiring a drained node. Activation uses it after a failed target start to decide
whether the prior release can safely read the state before restoring the old
active-release symlink and relay binding.

## Exact-request action permits

`stewardctl permit` signs and verifies short-lived permission for one exact
connector request. It does not contact Gateway, a control plane, or a hosted signer.
Keep the action private key on an operator-controlled signing station, not on the
Steward node.

Before issuance, export Gateway's non-secret view:

```console
sudo stewardctl gateway connector trust \
  -config /etc/steward/gateway.json \
  -tenant-id tenant-a > action-trust.json
```

The required tenant filter excludes other tenants' action-authority and connector
metadata. The `steward.action-trust.v1` inventory contains the selected tenant,
node ID, tenant-scoped key digests, connector origins, credential modes, exact
operation methods, paths and policy digests, credential epochs, and lifetime
limits. It is unsigned. Authenticate the transfer from the intended node. `permit
issue` uses it to catch mismatches before signing; Gateway's current validated
configuration is still the final authority.

Issue a canonical single-signature DSSE permit:

```console
stewardctl permit issue \
  -admission admission.json \
  -intent instance-intent.json \
  -trust action-trust.json \
  -request exact-request.json \
  -connector-id ticketing \
  -operation-id create-ticket \
  -task-id task-4bd6ce188f8b4e09a92af56d59a5df0e \
  -valid-for 5m \
  -clock-skew 5s \
  -key approver-a.private.pem \
  -key-id approver-a \
  -out action-permit.dsse.json \
  -header-out action-permit.header
```

Required inputs bind the admitted node, tenant, instance, generation, capsule,
policy, route policy, connector, operation, operation-policy digest, task, request
digest and byte length, outbound content type, and validity interval. The
operation-policy digest commits to the exported canonical origin, credential
injection mode, credential epoch, connector and operation IDs, method, and exact
path without credential bytes. The non-secret mode identifies whether Gateway uses
the `Authorization` or `X-API-Key` header. For POST, PUT, and PATCH, `-request` must
contain one strict JSON value and binds
`application/json`. For GET, HEAD, and DELETE, omit it; the permit binds an empty
request and empty content type. Exact bytes are hashed without reserialization. The
envelope is limited to 16 KiB and the request to 4 MiB, while the connector may set
a smaller body ceiling. Validity is whole seconds from one second through 24 hours
and may not exceed the connector's exported maximum.

`-clock-skew` defaults to five seconds, is limited to five minutes, and must be
shorter than `-valid-for`. It shifts the start earlier but does not lengthen the
signed interval. The private key must be an owner-only PKCS#8 Ed25519 PEM file.
Outputs are owner-only and must be different new paths. If multi-output publication
fails, the command attempts to remove previously written outputs and reports any
rollback failure; an operator may then need to remove a leftover file. Standard
output is the exact permit-envelope SHA-256 digest. `-header-out` contains the
canonical unpadded base64url value for `X-Steward-Action-Permit`.

Verify the signature, statement, current time, and optional request bytes:

```console
stewardctl permit verify \
  -in action-permit.dsse.json \
  -public-key approver-a.public \
  -key-id approver-a \
  -request exact-request.json
```

The JSON output contains `valid`, `evaluated_at`, `key_id`, `envelope_digest`, and
the complete `statement`. `-at` accepts canonical UTC RFC 3339 whole seconds for a
historical evaluation. `-max-validity` applies a stricter local ceiling.

Audit the permit against a copied Gateway connector chain:

```console
stewardctl permit audit \
  -in action-permit.dsse.json \
  -public-key approver-a.public \
  -key-id approver-a \
  -request exact-request.json \
  -receipts connector-receipts.ndjson \
  -receipt-public-key connector-receipts.public \
  -receipt-node-id steward-0123456789abcdef0123456789abcdef/gateway \
  -receipt-epoch 1 \
  -expected-sequence '<retained-sequence>' \
  -expected-chain-hash 'sha256:<retained-chain-hash>'
```

The command verifies the whole signed chain, correlates the exact authority key,
permit, request, grant, policy, connector operation, and stable task-based call
digest, and re-evaluates the permit at the authorization receipt's signed
observation time. Output contains `valid`, `permit_digest`, `request_digest`,
`permit_key_id`, the signed `statement`, matching `authorization`, optional
`terminal`, and final `head`. Supply both expected-head fields to compare with an
independently retained checkpoint. An absent terminal means the outcome is still
unknown; it is not evidence that no upstream effect occurred.

## Exact tenant-signed service tasks

`stewardctl task` signs one exact JSON request to one configured agent-service
operation. It uses only local files and never contacts Gateway or a hosted signer.
Keep the task private key on an operator-controlled signing station. Signed site
policy places only its public half in one tenant's `task_keys` and scopes it to
explicit `service_ids`.

Export Gateway's strict, non-secret service-operation inventory for the intended
node and tenant:

```console
sudo stewardctl gateway service trust \
  -config /etc/steward/gateway.json \
  -node-id node-a \
  -tenant-id tenant-a > service-trust.json
```

The `steward.service-trust.v2` inventory contains service and operation IDs; exact
method, submission path, content type, and status-path prefix; request, response,
dispatch, status, permit, and polling limits; the fixed lifecycle protocol; and the
operation-policy digest. It contains no token, private key, or task body. The file
is unsigned; authenticate its transfer from the intended node. It is a signing
preflight, not authority. Gateway's active configuration and grant make the final
decision.

Issue a task bundle from the exact Executor admission response, the exact instance
intent used for that admission, and the exact request bytes:

```console
stewardctl task issue \
  -admission admission.json \
  -intent instance-intent.json \
  -trust service-trust.json \
  -request exact-task.json \
  -operation-id hermes.run \
  -valid-for 5m \
  -clock-skew 5s \
  -key task-approver.private.pem \
  -key-id task-approver \
  -out exact-task.bundle.json
```

`task issue` verifies that the admission response, intent, task public key, service
inventory, and operation agree before signing. The statement binds node, tenant,
logical instance, runtime, grant, generation, capsule, site policy, effective route
policy, service and operation-policy digest, task ID, exact request digest and byte
length, `application/json`, and validity interval. Omit `-task-id` to generate
`task-` plus 32 random lowercase hexadecimal characters. A supplied ID must be a
bounded Steward identifier. Task replay identity excludes generation, so never
reuse one ID for a different intended effect or after replacing the workload.

The request must contain one strict JSON value and fit both the operation limit and
the 64 KiB task hard ceiling. Validity uses whole seconds, defaults to five minutes,
and cannot exceed the operation limit or the 15-minute hard ceiling. Clock skew
defaults to five seconds, may be at most five minutes, and must be shorter than the
validity interval.

The output is a new mode-`0600` `steward.task-bundle.v2` file capped at 128 KiB. It
contains the exact request bytes as canonical base64, the canonical DSSE permit, the
public authority, service path, lifecycle status policy, and operation limits. It
contains no private key or Gateway bearer, but it may contain a sensitive prompt
and must remain owner-only. Standard output reports the bundle path, task ID, permit
digest, and request digest.

Verify the bundle against an external key and, optionally, a separately retained
copy of the request:

```console
stewardctl task verify \
  -in exact-task.bundle.json \
  -public-key task-approver.public \
  -key-id task-approver \
  -request exact-task.json
```

The result includes `valid`, `evaluated_at`, `key_id`, `envelope_digest`, service
path, operation, and the complete signed statement. `-at` accepts canonical UTC RFC
3339 whole seconds for historical verification. `-max-validity` can impose a
stricter local ceiling.

## Submit and recover a service task

The lifecycle client is agent-independent. Submit the exact version-2 bundle once:

```console
sudo stewardctl task submit \
  -bundle exact-task.bundle.json \
  -gateway-url http://127.0.0.1:8091 \
  -token-file /etc/steward/gateway-service-token
```

The Gateway URL must be HTTP with a literal loopback IP address, explicit port, and
no path, query, user information, or fragment. The token and bundle must be
owner-only. Submit validates the bundle and permit at the current time, makes one
dispatch attempt, and returns the task digest, permit digest, untrusted service run
ID, and durable receipt marker. It does not automatically retry an ambiguous
transport result.

If submit times out or loses its response, keep the exact bundle. Do not issue a new
task ID or choose another node: the first dispatch may already have happened. Read
the durable status without contacting the agent:

```console
sudo stewardctl task status \
  -bundle exact-task.bundle.json \
  -gateway-url http://127.0.0.1:8091 \
  -token-file /etc/steward/gateway-service-token
```

Status and recovery authenticate the historical bundle at its signed start time,
so permit expiry does not erase the durable lookup identity. Expiry still prevents
a new dispatch.

Use `observe` for one bounded agent-status request. Choose exactly one result policy:

```console
sudo stewardctl task observe \
  -bundle exact-task.bundle.json \
  -gateway-url http://127.0.0.1:8091 \
  -token-file /etc/steward/gateway-service-token \
  -result-out exact-task.result.json
```

Replace `-result-out FILE` with `-discard-result` only when the result bytes are not
needed. A result path must be new; Steward creates it mode `0600`. Gateway returns
raw agent bytes only with a terminal observation. The client verifies their digest
and length, writes or discards them, and removes the raw base64 field from standard
output. A nonterminal observation leaves no result file.

`wait` combines passive status reads with bounded observations, using the signed
operation's polling interval:

```console
sudo stewardctl task wait \
  -bundle exact-task.bundle.json \
  -gateway-url http://127.0.0.1:8091 \
  -token-file /etc/steward/gateway-service-token \
  -result-out exact-task.result.json \
  -wait-timeout 3m
```

The wait limit defaults to three minutes and cannot exceed 15 minutes. The command
honors Gateway retry intervals and exits nonzero for a terminal state other than
`agent_reported_completed`. Status JSON distinguishes durable phases such as
`authorization_recorded`, `dispatch_accepted`, and the terminal agent-reported or
failure state. `failed_without_dispatch_evidence` does not mean the service was
never contacted; it means no dispatch receipt exists. For Gateway failures,
`retry_safety` is either `replacement_safe_after_new_authority` when Gateway knows
it did not contact the service, or `replacement_unsafe` when the service may have
processed the request. The former still requires a different task and new signed
authority. Neither value is approval to retry. These names describe observed
evidence, not semantic success.

If Gateway returns `evidence_unavailable`, restart Gateway so it can reconcile the
ledger. A retained authorization without a complete outcome is closed as
`outcome_unknown`; treat the external effect as possibly completed and do not mint
replacement authority. If no authorization was retained, the same bundle may be
submitted again while its permit is still valid. Use status or wait with that exact
bundle to resolve the case.

Audit a task against a copied mixed-format Gateway receipt ledger:

```console
stewardctl task audit \
  -in exact-task.bundle.json \
  -public-key task-approver.public \
  -key-id task-approver \
  -request exact-task.json \
  -receipts connector-receipts.ndjson \
  -receipt-public-key connector-receipts.public \
  -receipt-node-id node-a/gateway \
  -receipt-epoch 1 \
  -expected-sequence '<retained-sequence>' \
  -expected-chain-hash 'sha256:<retained-chain-hash>'
```

The command verifies formats 1 through 4 in one chain, finds the exact service-task
permit, re-evaluates it at the signed authorization time, and checks every available
tenant, runtime, grant, policy, service, operation, task, authority, permit, and
request binding. For a format-4 task it also verifies the task-local sequence and
hash chain. A normal accepted lifecycle is authorization → dispatch → terminal; a
failure before dispatch has authorization → terminal. The receipt node ID must
equal the permit's signed node ID followed by `/gateway`; this prevents a valid
chain from another node from being associated with the task by mistake. Output
includes the authorization, optional dispatch, terminal, and final head. A missing
terminal is an unknown outcome, not evidence that no dispatch occurred.

Service-task receipts record digests, byte counts, bounded status, error, and the
run ID observed from the service. They do not contain the raw request, prompt,
response, workspace content, or private key. The run ID is untrusted service output.
The chain lets an auditor verify what Gateway signed within the host trust boundary;
it does not establish useful work, semantic correctness, upstream exactly-once
behavior, or an uncompromised host. Replay prevention is node-local within one
retained ledger epoch.

## Image archives

Inspect a candidate archive without mutating Docker:

```console
chmod go-w agent-approved.tar
stewardctl image inspect -archive agent-approved.tar
```

The JSON result contains manifest and config digests, platform, media types, layers,
optional repository tags, and blob counts. Default limits are a 20 GiB archive,
40 GiB of uncompressed content, 4,096 archive entries, 256 layers, 4 MiB of
metadata, and at most 1 MiB of trailing zero data. Steward accepts one unambiguous
Docker or Open Container Initiative (OCI) image in a regular file not writable by
group or other users. It rejects unsafe paths, links/devices, duplicate paths or
JSON keys, missing or mismatched blobs, remote descriptors, multiple manifests,
unsupported layers, platform conflicts, non-zero or over-limit trailing data, and
declared writable volumes.

After the publisher signs those values and site-root policy authorizes the
publisher, repository, profile, and manifest, import on the Linux node:

```console
sudo stewardctl image import \
  -archive agent-approved.tar \
  -capsule capsule.dsse.json \
  -policy site-policy.dsse.json \
  -site-root-public-key site-root.public \
  -site-root-key-id site-root-1
```

`-docker-socket` and `-timeout` select the Unix socket and positive timeout; defaults
are `/var/run/docker.sock` and 30 minutes. Import authorizes the capsule and matches
signed manifest, config, and platform before Docker. It snapshots the source once
to an owner-only private file, then builds a read-only sanitized archive. Steward
unlinks that archive—removes it from the filesystem namespace while keeping it
open—so later path replacement cannot alter the bytes Docker loads. Docker receives
no tags, legacy `repositories`, or unreferenced blobs. Post-load inspection checks
the exact config. An already valid image makes import idempotent. JSON reports
`imported`, repository, capsule/policy digests, key IDs, and image identity.

Import authorizes media, not a tenant or instance. It consumes no generation and
does not replace the required tenant intent.

Preparation uses the operating system's temporary directory (`TMPDIR`, or the
platform default). At the default limits, it can briefly hold both a 20 GiB source
snapshot and a sanitized archive approaching 40 GiB, plus tar framing. Steward does
not reserve free space or place a separate quota on that temporary directory. Run
large imports with `TMPDIR` on a dedicated, quota-backed filesystem with at least
the expected source-plus-sanitized peak and an operator-defined safety reserve.

## Evidence verification

Verify a binary log or newline-delimited JSON (NDJSON) export against its node key
and expected identity. Format detection is automatic:

```console
stewardctl evidence verify -in evidence.bin \
  -public-key node-receipts.public -node-id node-a -epoch 1
```

Add `-json` for `{ "valid": true, "head": ... }`. The head contains node ID, key
epoch, final sequence, `sha256:` chain hash, and key ID. An empty valid chain has an
explicit head.

A hash chain cannot reveal removal of a valid suffix. Keep the accepted head in an
independent store and require it when verifying that checkpoint:

```console
stewardctl evidence verify -in evidence.bin \
  -public-key node-receipts.public -node-id node-a -epoch 1 \
  -expected-sequence "<retained-sequence>" \
  -expected-chain-hash "sha256:<retained-chain-hash>"
```

Sequence is an unsigned decimal; hash is `sha256:` plus 64 lowercase hexadecimal
characters. A mismatch reports rollback. Values assert the exact head, not a lower
bound; retain a new head after legitimate growth.

Connector receipts are already portable DSSE NDJSON. Verify them with the separate
Gateway public key and the node identity from `connector_receipt_node_id`:

```console
stewardctl evidence verify -kind connector \
  -in /var/lib/steward-gateway/connector-receipts.ndjson \
  -public-key /etc/steward/connector-receipts.public \
  -node-id steward-0123456789abcdef0123456789abcdef/gateway \
  -epoch 1
```

`-expected-sequence` and `-expected-chain-hash` provide the same external rollback
check. Retain that head outside the node. Connector evidence does not need an
export step; `evidence export -kind connector` is rejected.

## Evidence export

Convert a verified stable native chain to newline-delimited JSON:

```console
stewardctl evidence export -in evidence.bin \
  -public-key node-receipts.public -node-id node-a -epoch 1 \
  -expected-sequence "<retained-sequence>" \
  -expected-chain-hash "sha256:<retained-chain-hash>" > receipts.ndjson
```

The export is independently verifiable with the trusted node public key, node ID,
and key epoch. Each receipt has `signed_frame`: canonical base64 of the native
length-prefixed envelope containing the payload and Ed25519 signature. The signed
frame is the source of truth; reserializing the JSON does not prove authenticity.
The sequence links, event, outcome, tenant, runtime, capsule and policy digests,
generation, grant, and bounded errors are a human-readable copy verified against
that signed frame. Verification rejects any difference. A required final line
contains the complete chain head.

The native log is capped at 64 MiB. Portable evidence input is capped at 256 MiB,
each portable line at 128 KiB, and each signed envelope at 64 KiB. The verifier
rejects unknown or duplicate fields, non-canonical base64, inputs above those
limits, bad signatures, sequence gaps, reordering, altered readable fields,
content after the head, or a missing final newline. Verify an export like a native
log:

```console
stewardctl evidence verify -in receipts.ndjson \
  -public-key node-receipts.public -node-id node-a -epoch 1 \
  -expected-sequence "<retained-sequence>" \
  -expected-chain-hash "sha256:<retained-chain-hash>"
```

Export verifies before and during owner-only staging and releases only an unchanged
source. Corruption or a concurrent write therefore cannot produce an apparently
complete partial stream. A signed prefix is valid by itself; only an independently
retained sequence and hash detect suffix removal. `export` produces NDJSON; `-json`
applies only to `verify`.

See [signed admission]({{ '/guides/signed-admission/' | relative_url }}) for the
end-to-end authority workflow and
[air-gapped installation]({{ '/guides/air-gapped/' | relative_url }}) for
controlled-media transfer. The native log is append-only and has no supported
rollover or compaction command; see
[durable control-store limits]({{ '/limitations/' | relative_url }}#durable-control-stores-have-fixed-lifetime-limits).
