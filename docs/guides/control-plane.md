---
title: Operate the bundled Steward control plane
description: Install Steward Control, manage tenants and nodes, deliver signed commands, inspect fleet attention and safe metrics, use MCP, and protect durable state.
section: How-to
---

# Operate the bundled Steward control plane

`steward-control` is Steward's optional self-hosted fleet service. It gives a site
one bounded place to create tenants, issue scoped operator credentials, enroll
nodes, retain desired agent deployments, inspect secret-free inventory and
action-required facts, lease exact signed commands to Executor, record terminal
delivery status, and optionally expose authenticated aggregate metrics.

The controller cannot decide what a tenant may run. Tenant and site private signing
keys remain on a trusted signing station or in a separately operated signing
service. For durable deployments, a tenant signs a short-lived delegation to the
controller's separate online key. Control can then sign only the exact lifecycle
commands that delegation permits. Executor verifies the tenant delegation, the
controller command, and local site policy before changing Docker. A compromised
controller can exercise active delegated verbs until expiry, but cannot mint new
tenant authority or add an undeclared instance, node, generation, resource,
capability, route, or connector.

Control has two authority modes:

- `bounded-autonomous` is the default. It loads the online controller key and
  reconciles desired deployments only within a tenant-signed delegation.
- `strict-sovereign` refuses to start while that online key exists and does not run the
  desired-state reconciler. It can still observe the fleet and courier an exact
  command signed outside Control. Desired-deployment mutations return
  `409 autonomous_reconciliation_disabled` instead of silently remaining pending.

Use strict mode when compromise of the Control host must not expose an online key
that can change instances. This mode trades automatic rollout, replacement,
scaling, and fork cleanup for a smaller online authority boundary. Removing the
key from Control is only one part of the boundary: do not issue an active tenant
delegation to that key, and expire or revoke old delegations before treating a
site as strict. The installer never deletes signing keys for you.

## Choose a deployment shape

Use a dedicated Linux management host. The packaged controller and Executor node
installers reject co-location because they maintain separate immutable release
selectors and must be independently upgradable. The controller needs no
Docker socket, agent image, inference endpoint, Kubernetes cluster, external
database, or message broker. A loopback listener is useful for evaluation and for
sites that place their own authenticated reverse proxy on the same host. A direct
remote listener requires a TLS certificate and owner-only private key.

The built-in store has one active writer. Do not run two controller processes over
the same directory or copy live files independently. The service takes an
exclusive lock and fails closed when another writer owns it. This design keeps an
air-gapped installation small and auditable; it does not provide automatic
failover or multi-replica consensus.

## Install the controller

On a systemd Linux host, run the dedicated controller installer:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/hardrails/steward/releases/latest/download/install-control.sh | sudo /bin/bash -p
```

Keep `/bin/bash -p` in online, offline, and unattended commands. Privileged Bash
mode prevents the root installer from loading user-controlled startup files or
imported shell functions before its own checks run. The installer refuses an
explicit non-privileged Bash invocation.

Piping a script to a root shell trusts GitHub's TLS delivery and the Steward
release account. The archive checksum downloaded by that script comes from the
same release, so it detects transfer corruption but is not an independent release
signature. For higher assurance, inspect and pin the installer and checksum
manifest through a separate trust channel, or use the verified offline workflow.

The default binds `127.0.0.1:8443` without TLS. Plain HTTP is accepted only on a
literal loopback address. The installer creates a dedicated non-root service user,
an owner-only state directory, a versioned immutable release, and a hardened
systemd service. It does not install Docker or modify a Steward node installation.
It also does not install `stewardctl` or `steward-mcp`. Run those clients from a
trusted operator workstation using the matching full Steward release archive; do
not move an administrator bearer onto an agent workload node merely to obtain a
client.

When HTTPS is configured, Steward Control accepts TLS 1.3 only. The Steward Control
client shared by `stewardctl control` and `steward-mcp` also rejects HTTPS servers
that cannot negotiate TLS 1.3.

To install the strict profile, make the choice explicit:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/hardrails/steward/releases/latest/download/install-control.sh | \
  sudo /bin/bash -p -s -- --authority-mode strict-sovereign
```

The installer preserves the chosen mode on upgrade unless
`--authority-mode` is supplied again.

The guided first install asks for a path for the first site-administrator bearer.
For unattended installation, make that choice explicit:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/hardrails/steward/releases/latest/download/install-control.sh | \
  sudo /bin/bash -p -s -- --non-interactive \
    --admin-token-out /root/steward-control-admin.token
```

Operational metrics are opt-in and authenticated. Enable them during install, and
set explicit attention thresholds when the defaults do not fit the site's expected
report and delivery cadence:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/hardrails/steward/releases/latest/download/install-control.sh | \
  sudo /bin/bash -p -s -- --non-interactive \
    --admin-token-out /root/steward-control-admin.token \
    --enable-metrics \
    --node-stale-after 3m \
    --evidence-stale-after 7m \
    --command-overdue-after 10m \
    --capacity-warning-percent 80
```

An upgrade preserves these settings unless replacement options are supplied.
`--disable-metrics` returns to the secure default. Durations accept positive
canonical `s`, `m`, or `h` values no greater than 8760 hours.

The installer publishes that file with exclusive, no-symlink semantics and mode
`0600`, then proves the bearer against a temporary loopback controller before it
activates the service. The token's parent directory must be root-owned and must not
be writable by a group or other users. The installer prints only the path, never
the secret. Move the token into your protected operator credential store after
confirming access; do not place it in shell history, Terraform state, cloud-init,
an agent prompt, or an MCP configuration readable by an untrusted account.

First-bootstrap recovery is intentionally narrow. If an interrupted prepared
transaction exists, rerun the installer with the same command. Recovery removes
only the journal-bound unpublished or newly published token, restores the prior
controller state, and then begins a new transaction with the same absent output
path. If commit completed before interruption, the retry instead verifies the
existing owner-only token against durable state without overwriting it. If durable
bootstrap exists without either a transaction journal or handoff file, rerun with a
new absent output path. The controller can reproduce the first credential only
while the store has no tenant, node, enrollment, or command records and at most one
valid, unrevoked bootstrap credential. The installer refuses an incomplete or
unrecognized state tree, unsafe ownership, or an attempt to mint a replacement
administrator for a populated store. Inspect or restore that state rather than
deleting files individually.

The installer records active links, configuration, TLS, token handoff, controller
state, and service enablement or activity in an owner-only transaction journal.
Service-identity creation, protected directories, and immutable release staging
occur before that transaction; they are inert, validated, and reused on retry. If
the process is killed or the host
loses power, rerun the same install command before relying on the service. The next
invocation restores the previous installation before starting a new transaction.
There is no boot-time recovery unit, so system startup alone does not complete or
roll back an interrupted installation. Do not remove
`/var/lib/steward-control-installer/transaction` by hand.

Every first installation creates an evidence-witness Ed25519 identity:

- private key: `/var/lib/steward-control/witness.private.pem`, mode `0600`;
- public key: `/var/lib/steward-control/witness.public.pem`, mode `0644`.

Both files are inside the service's mode-`0700` state directory. The public file is
therefore stable but not directly readable by ordinary host users. Copy only the
public key to an offline verifier or auditor from a root session:

```console
sudo install -o root -g root -m 0644 \
  /var/lib/steward-control/witness.public.pem \
  /secure/steward-control-witness.public.pem
```

The installer never prints, passes on the command line, rotates, or overwrites the
private key. On an upgrade from a controller that predates this identity, it
creates the pair only if both paths are absent. A partial pair, unsafe metadata,
symlink, or mismatch stops the upgrade so an operator can investigate instead of
silently accepting a new audit identity.

In `bounded-autonomous` mode, installation also creates the online
controller-signing identity:

- private key: `/var/lib/steward-control/controller.private.pem`, mode `0600`;
- public key: `/var/lib/steward-control/controller.public.pem`, mode `0644`;
- key ID: `controller-default`.

Copy only its public key to a tenant signing station when issuing a bounded
controller delegation. This key is not the TLS identity, evidence-witness identity,
or tenant authority. An upgrade from older state creates the pair only when both
paths are absent and preserves it on later runs. A partial, linked, mismatched, or
unsafe pair stops installation.

A fresh strict-mode installation leaves both controller-key paths absent.
Switching an existing controller to strict mode requires you to expire every
delegation that names the key, archive any required public identity, and remove
both key files. The installer refuses the switch instead of destructively deleting
them. `control-doctor` treats absence as required while still checking the witness
key and all other service boundaries.

Verify the installed service:

```console
sudo /usr/local/libexec/steward-control/control-doctor
sudo systemctl status steward-control
```

The default doctor can make a readiness request to a loopback or exact-address
listener. For a TLS listener bound to `0.0.0.0` or `::`, it can only
confirm that the local TCP port accepts a connection because a wildcard address is
not a certificate identity. Supply the real origin and private CA to verify the
certificate name and HTTP readiness:

```console
sudo /usr/local/libexec/steward-control/control-doctor \
  --probe-url https://control.customer.example:8443 \
  --ca-file /secure/steward-control-pki/ca.crt
```

For a remote listener, first create or supply a certificate whose Subject
Alternative Names contain the exact DNS names and IP addresses operators and nodes
will use. On a trusted workstation with `stewardctl` from the full release archive,
Steward can create a small local public-key infrastructure (PKI) without a network
service:

```console
sudo install -d -o root -g root -m 0700 /secure/steward-control-pki
sudo stewardctl control pki create \
  -ca-cert-out /secure/steward-control-pki/ca.crt \
  -ca-key-out /secure/steward-control-pki/ca.key \
  -server-cert-out /secure/steward-control-pki/server.crt \
  -server-key-out /secure/steward-control-pki/server.key \
  -server-names control.customer.example,10.20.0.10
```

The command creates a certificate authority (CA), server certificate, and their
private keys without overwriting existing paths. Protect both private keys. If the
administration system is not the controller host, transfer the server certificate
and server key through an authenticated channel before installation; keep the CA
key in protected signing storage. Before invoking the installer, stage the
certificate and key as root-owned, single-link regular files no larger than 1 MiB
under a directory chain that is root-owned and not group- or world-writable. The
private key must be owner-only. The `/secure/steward-control-pki` directory and
outputs created above already satisfy those rules. Nodes and operators receive only
the CA certificate. Configure the installer on the controller host with the staged
server certificate and key:

```console
curl --proto '=https' --tlsv1.2 -fsSLo install-control.sh \
  https://github.com/hardrails/steward/releases/latest/download/install-control.sh
less install-control.sh
sudo install -d -o root -g root -m 0700 /root/steward-control-install
sudo install -o root -g root -m 0700 install-control.sh \
  /root/steward-control-install/install-control.sh
sudo /bin/bash -p /root/steward-control-install/install-control.sh \
  --addr 0.0.0.0:8443 \
  --tls-cert /secure/steward-control-pki/server.crt \
  --tls-key /secure/steward-control-pki/server.key \
  --admin-token-out /root/steward-control-admin.token
```

The installer copies trust material to `/etc/steward-control`, validates the
candidate configuration before switching the service, and refuses a remote
listener without both TLS inputs. Then use
`https://control.customer.example:8443` as the control origin.

When `stewardctl`, `steward-mcp`, or a Steward uplink receives an explicit CA file,
that file replaces the host's system root set for that connection. It is not added
to the public Web PKI roots. This makes the selected private CA the only trust
anchor for the controller. Omit the CA option only when the controller certificate
chains to the host's intended system roots.

## Create the first tenant and a least-privilege operator

The examples below assume a remote private-CA deployment:

```bash
CONTROL_URL=https://control.customer.example:8443
ADMIN_TOKEN=/secure/steward-control/site-admin.token
CONTROL_CA=/secure/steward-control-pki/ca.crt
```

Save those repeated connection settings in a CLI context:

```console
stewardctl context set site-admin \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA"
```

The context stores file paths, not the bearer value. Commands in this section can
now omit `-control-url`, `-token-file`, and `-ca-file`. The longer forms remain in
later recovery and automation examples when showing every input is useful. See
[Make stewardctl easier to use]({{ '/guides/cli/' | relative_url }}) for multiple
environments, explicit overrides, and shell completion.

Create a tenant:

```console
stewardctl control tenant create -tenant-id tenant-a
```

Use the site administrator only for site-wide changes. Issue a tenant-scoped
operator for routine work. `request-id` is a caller-chosen idempotency key: reuse
the same value after an ambiguous timeout instead of requesting another secret.
The output path must not already exist.

```console
stewardctl control operator issue \
  -request-id tenant-a-operator-20260713 \
  -role tenant_operator \
  -tenant-id tenant-a \
  -token-out /secure/steward-control/tenant-a-operator.token
```

The command prints the non-secret credential ID. Record it so the site
administrator can revoke the credential later. Before rotating a site
administrator, issue and verify a replacement site-administrator token. The
controller refuses to revoke the last live site administrator because a
populated store cannot recreate the bootstrap credential safely.

```console
stewardctl control operator revoke \
  -credential-id cred-EXAMPLE
```

After issuing the tenant operator, create a daily-use context. Add a default node
when it is enrolled:

```console
stewardctl context set tenant-a \
  -control-url "$CONTROL_URL" \
  -token-file /secure/steward-control/tenant-a-operator.token \
  -ca-file "$CONTROL_CA" \
  -tenant-id tenant-a
```

## Enroll a node once

Create an enrollment capability for one stable node identity and one or more
existing tenants. The capability expires and is spendable once. The output file
contains a bearer secret, so transfer it through an authenticated temporary
channel and remove it after exchange.

```console
stewardctl control enrollment create \
  -control-url "$CONTROL_URL" \
  -token-file /secure/steward-control/tenant-a-operator.token \
  -ca-file "$CONTROL_CA" \
  -request-id node-a-enrollment-20260713 \
  -node-id node-a \
  -tenant-ids tenant-a \
  -valid-for 15m \
  -out /secure/enrollment/node-a.enrollment.json
```

If the response is lost, repeat the command with the same request ID, scope,
lifetime, operator token, and a new absent output path. The controller returns the
same enrollment capability. A changed request conflicts instead of leaving a
second live secret. Once the capability has expired, use a new request ID.

On the staged node, create the receipt key that will sign local enforcement
evidence. Keep the private key on the node. The exchange proves possession of this
key and emits a protected evidence-config sidecar that binds the controller, node,
receipt epoch, and public key.

```console
sudo stewardctl keygen \
  -key-id node-a-receipts \
  -private-out /secure/enrollment/node-receipts.private.pem \
  -public-out /secure/enrollment/node-receipts.public
sudo stewardctl control enrollment exchange \
  -control-url "$CONTROL_URL" \
  -ca-file /secure/enrollment/control-ca.crt \
  -enrollment /secure/enrollment/node-a.enrollment.json \
  -request-id node-a-first-exchange \
  -executor-evidence-private-key /secure/enrollment/node-receipts.private.pem \
  -credential-out /secure/enrollment/executor-node.json \
  -executor-evidence-config-out /secure/enrollment/executor-evidence.env
```

The request ID makes a retry deterministic if the first response is lost. Reuse the
same receipt key and request ID, but choose new absent paths for both outputs.

The resulting credential is an owner-only Executor transport credential. It
identifies the node, not a tenant. The evidence sidecar is non-secret authority
metadata, but keep it owner-only so another local user cannot alter the controller
binding before installation. Configure the node with both files, the exact receipt
key pair, the controller CA, and a site-root-signed policy that contains the public
command keys for every bound tenant. The private command and site-root keys must
not enter the node or controller. Follow the
[node enrollment procedure]({{ '/getting-started/enroll/' | relative_url }}) for
the complete transaction.

The exchange command prints the non-secret node credential ID. Record it for
rotation and targeted revocation. To rotate, a site administrator issues and
exchanges a new enrollment for the existing node. Apply the replacement through
the node configurator, which validates the complete node configuration, atomically
replaces the credential, and restarts the node services:

```console
sudo /usr/local/libexec/steward/configure-node \
  --control-plane-url "$CONTROL_URL" \
  --executor-credential /secure/enrollment/executor-node-rotated.json \
  --ca-file /secure/enrollment/control-ca.crt \
  --admission-policy /secure/enrollment/site-policy.dsse.json \
  --site-root-public-key /secure/enrollment/site-root.public \
  --site-root-key-id site-root-1 \
  --node-id node-a \
  --executor-evidence-config /secure/enrollment/executor-evidence-rotated.env \
  --executor-evidence-private-key /secure/enrollment/node-receipts.private.pem \
  --executor-evidence-public-key /secure/enrollment/node-receipts.public
```

Confirm that `last_seen_at` advances while the replacement is installed. Only then
revoke the old bearer by the credential ID printed during its exchange:

```console
stewardctl control node-credential revoke \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -credential-id node-cred-EXAMPLE
```

Targeted revocation leaves the node and any replacement credential active. A
tenant operator may create a new node, but only a site administrator may issue a
replacement enrollment for an existing global node ID. This prevents a tenant
operator from attaching itself to another tenant's node identity.

Operator and node bearer credentials do not expire automatically. Rotate
operators by issuing a replacement with a new request ID, verifying it, and
revoking the old credential ID. Rotate node bearers through the staged procedure
above. Enrollment capabilities expire and allow one logical exchange; an exact
retry reproduces the same node credential rather than creating another one.

Revocation also fences requests that authenticated before their bodies arrived.
The controller rechecks the credential under the durable operation lock, so a
slow or interrupted request cannot finish a mutation after its operator or node
credential has been revoked.

Once Executor polls successfully, inventory reports its capabilities and last
contact time:

```console
stewardctl control node status \
  -control-url "$CONTROL_URL" \
  -token-file /secure/steward-control/tenant-a-operator.token \
  -ca-file "$CONTROL_CA" \
  -tenant-id tenant-a \
  -node-id node-a
```

Node revocation is site-wide and revokes every retained credential for that node.
It does not stop workloads already running on a disconnected node. Use a signed
site cleanup command before revocation when containment is required.

## Inspect and verify the evidence witness

The evidence publisher runs independently from command polling. A controller
outage does not stop local admission or agent work; the node keeps its signed
receipt log as the durable outbox. When connectivity returns, Executor submits a
bounded contiguous batch that signs both the controller checkpoint it observed
and the exact native frames it sends.

A site administrator can inspect the retained checkpoint without reading the full
node receipt log:

```console
stewardctl control evidence status \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -node-id node-a
```

The response uses these implemented states:

- `current`: the controller has a valid last-good checkpoint for the enrolled
  receipt identity. This is not a liveness signal and does not prove the host was
  uncompromised when it created a receipt.
- `unwitnessed`: a legacy node has no receipt-key proof. A site administrator can
  issue and exchange a replacement enrollment for that active node before relying
  on controller witnessing.
- `rollback_detected`: the node signed a head below the checkpoint named in
  `finding.compared_head`.
- `equivocation_detected`: the node signed a head or branch that conflicts with
  `finding.compared_head`.

Rollback and equivocation findings are sticky. Later reports cannot clear the
finding or advance the checkpoint, and Steward has no evidence-reset endpoint.
The status `head` is the latest retained last-good checkpoint. It normally
equals `finding.compared_head`, but it can be later when another valid report
advances the checkpoint while a historical conflict is being verified. The
finding retains both the exact comparison checkpoint and the conflicting
`observed_head`, so an inspection or signed export remains unambiguous. In that
historical case, `finding.detected_at` can be earlier than the `witnessed_at`
time attached to the later status head.
Preserve the node receipt log, controller state, and a signed export for
investigation. If the node must be replaced, revoke it, create a new global node
ID with a new receipt key, and enroll that replacement. A revoked node ID is not
reused; this preserves the old forensic record.

Create a portable export on a trusted operator workstation:

```console
stewardctl control evidence export \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -node-id node-a \
  -out node-a.evidence-witness.json
```

The output file is created once with mode `0600`. The export contains the
enrolled receipt-key proof, latest last-good checkpoint, any sticky finding and
its exact comparison checkpoint, and export time. The controller signs those
fields with its separate witness key. The public key embedded in the export is
descriptive, not trusted by itself.

Verify offline with the witness public key copied through an independent trusted
channel:

```console
stewardctl control evidence verify \
  -in node-a.evidence-witness.json \
  -witness-public-key /secure/steward-control-witness.public.pem
```

Verification makes no controller request. It fails if a signed export field
changed, the receipt identity and checkpoint disagree, or the pinned witness key
does not match. Reformatting equivalent JSON does not change the signed statement.
An `unwitnessed` legacy node cannot produce an export because there is no receipt
identity to bind; the controller returns a conflict instead.

The controller signs outside the store lock, then confirms that the witness state
is still current. If three consecutive witness updates prevent that confirmation,
the export returns `409 Conflict` with `Retry-After: 1`. Wait at least that long,
add client-side jitter when many operators may retry together, and request a new
export. A 409 without `Retry-After` is a retained-state conflict such as an
unwitnessed legacy node; repeating the same request will not repair it.

## Capture one activation evidence range

A normal evidence export proves the controller's retained checkpoint. An
activation evidence capture additionally preserves the exact signed Executor
frames for a complete evidence-report suffix containing one matching activation
begin followed by one matching checkpoint. The suffix can contain later
unrelated frames before its signed final head. Steward then binds that range to a successful,
retained activation-canary command. This produces a portable record that an
auditor can replay without contacting the controller or node.

Every capture operation requires a site-administrator credential. The controller
will arm a capture only for an active, finding-free, witnessed node that belongs
to the named tenant. Arm it before submitting the activation command. This is a
required operating procedure; the proof establishes controller observation
after the armed baseline, not when the node generated a receipt:

```console
stewardctl control evidence-capture arm \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -node-id node-a \
  -capture-id activation-a-evidence-0001 \
  -request-id activation-a-evidence-arm-0001 \
  -tenant-id tenant-a \
  -runtime-ref executor-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  -generation 7 \
  -activation-id activation-a \
  -activation-begin-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  -ttl 10m
```

The TTL is the window in which the matching activation checkpoint must be
observed. It must be a whole number of seconds from `1s` through `1h`. The first
successful request fixes an absolute expiry; an exact retry with the same IDs,
target, and TTL returns the retained capture without extending that expiry. One
node can have only one `armed` capture.

Inspect progress without returning the captured frames:

```console
stewardctl control evidence-capture status \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -node-id node-a \
  -capture-id activation-a-evidence-0001
```

The `state` field has these meanings:

- `armed`: the controller is preserving valid contiguous frames after the
  baseline, but has not observed the complete target pair. After it sees the
  begin, status also reports that receipt's sequence, capsule digest, and policy
  digest.
- `observed`: the range contains exactly one allowed, error-free begin followed
  by exactly one committed, error-free checkpoint for the named tenant, runtime,
  generation, and activation.
- `sealed`: the controller also verified that the named protocol-4
  `activation-canary` command completed successfully and matches the checkpoint.
  Only a sealed capture can be exported.
- `expired`: the checkpoint was not observed before the fixed deadline. Expiry is
  durable but lazy: there is no background timer, so the controller records the
  transition on the next evidence report or capture operation after the deadline.
- `failed`: the controller could not preserve a coherent bounded proof. The
  `failure` field explains why.

Failure reasons are precise evidence-collection results:

- `capture_overflow`: reaching the checkpoint would exceed 128 frames or 512 KiB
  of decoded native frames.
- `coordinate_changed`: the next report did not continue from the exact retained
  capture head.
- `evidence_finding`: receipt verification produced or encountered a rollback,
  equivocation, or other blocking evidence finding.
- `target_contradiction`: a target checkpoint or its signed report contradicted
  the requested activation binding or success requirements.
- `storage_capacity`: retaining the captured frames would exceed controller
  state or write-ahead-log capacity. Steward preserves ordinary evidence
  witnessing and retains a small failed capture when capacity permits; otherwise
  it drops that optional capture.

After the status becomes `observed` and the matching canary command is terminal
and successful, seal the capture:

```console
stewardctl control evidence-capture seal \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -node-id node-a \
  -capture-id activation-a-evidence-0001 \
  -canary-command-id activation-a-canary-0001
```

Sealing checks retained evidence and command state. A matching successful canary
is protected from age-based capacity pruning while the capture is armed or
observed. Sealing does not run the canary or change the workload. Export the
sealed range to a new owner-only file:

```console
stewardctl control evidence-capture export \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -node-id node-a \
  -capture-id activation-a-evidence-0001 \
  -out activation-a.evidence-capture.json
```

The node evidence chain can interleave receipts from several tenants. Steward
cannot remove those frames without breaking signature continuity, so a capture
may contain tenant IDs and digests unrelated to its target. Treat the export as
sensitive site-wide evidence. It contains at most 128 frames, 512 KiB of decoded
frame data, and 1 MiB of JSON.

Verify the copied file on a disconnected audit system:

```console
stewardctl control evidence-capture verify \
  -in activation-a.evidence-capture.json \
  -witness-public-key /secure/steward-control-witness.public.pem
```

Verification uses only local files. It checks the purpose-separated controller
witness signature, enrollment-time Executor receipt identity, every native frame
from the signed baseline to the final head, exactly one matching allowed begin,
and exactly one later matching committed checkpoint. It also rejects matching
lifecycle invalidation within the signed suffix. The embedded controller key is descriptive; pin the witness public
key through an independent trusted channel. Steward requires this witness key to
be distinct from the Executor receipt key.

A valid capture proves the signed chain and what the controller attested when it
sealed the range. It does not prove that the host or controller was uncompromised,
that the agent's output was semantically correct, or that the canary result was
independently replayed by the offline verifier.

An `expired` or `failed` capture is not evidence that the activation did not run,
and it does not establish that retry is safe. A workflow that requires portable
proof should treat either state as `action_required`, meaning an operator must
intervene: preserve the record and node evidence, investigate the cause, and make
an explicit recovery decision. `action_required` is workflow guidance, not a
sixth capture state. Steward does not automatically retry, roll back, stop,
destroy, or remediate a workload; capture failure also does not block ordinary
evidence witnessing.

Delete a retained capture only after preserving everything required for audit:

```console
stewardctl control evidence-capture delete \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -node-id node-a \
  -capture-id activation-a-evidence-0001
```

Deletion is irreversible. It changes neither node evidence nor command or
workload state. The controller retains at most 16 active captures, 256 captures
across all states, and 16 MiB of reserved or captured frame data. An armed capture
reserves its full 512 KiB allowance, so delete obsolete records deliberately when
the site approaches a fixed limit.

## Sign, submit, and observe one command

Create commands only on the trusted signing station. The public half of
`tenant-a-commands` must already be allowed by the node's signed site policy. For a
`start` operation, the payload is an empty JSON object:

```console
printf '{}\n' > start-payload.json
stewardctl executor-command issue \
  -command-id start-agent-1-0001 \
  -tenant-id tenant-a \
  -node-id node-a \
  -instance-id agent-1 \
  -kind start \
  -claim-generation 1 \
  -instance-generation 1 \
  -sequence 2 \
  -payload start-payload.json \
  -key /secure/signing/tenant-a-commands.private.pem \
  -key-id tenant-a-commands \
  -out start-agent-1-0001.dsse.json
```

Submit the exact envelope. The controller parses only enough signed payload to
bind the tenant, node, and command identity to the route. It stores and later
delivers the original bytes.

```console
stewardctl control command submit \
  -control-url "$CONTROL_URL" \
  -token-file /secure/steward-control/tenant-a-operator.token \
  -ca-file "$CONTROL_CA" \
  -tenant-id tenant-a \
  -node-id node-a \
  -command start-agent-1-0001.dsse.json
```

The embedded React console can courier the same exact file. Select `tenant-a`,
open **Commands**, load the DSSE JSON, compare its SHA-256 digest with the signing
station, type the exact confirmation phrase, and re-enter the current operator
bearer. The browser does not sign or verify the command. The controller strictly
binds its signed route and retains the original bytes; Executor verifies command
authority before acting. See [Operate a fleet with the embedded React console]({{ '/guides/operator-console/' | relative_url }}).

Inspect delivery without creating a replacement command:

```console
stewardctl control command status \
  -control-url "$CONTROL_URL" \
  -token-file /secure/steward-control/tenant-a-operator.token \
  -ca-file "$CONTROL_CA" \
  -tenant-id tenant-a \
  -node-id node-a \
  -command-id start-agent-1-0001
```

`pending` means no live lease exists. `leased` means a node poll claimed the exact
command for a bounded interval. `terminal` means the controller durably accepted a
node report. A terminal response includes `terminal_status`, the signed
`claim_generation`, and bounded `result` details such as `runtime_ref`, replay or
absence markers, and a safe error string. `terminal_status: outcome_unknown` means
the node cannot prove whether the local effect completed; do not automatically
issue a semantically equivalent replacement. `terminal_status: failed` is retained
with the same fail-closed rule for compatibility. Current nodes report a proven
pre-effect failure as `rejected`, which is safe to retire after acknowledgement.

## Limit one tenant across the whole fleet

Executor enforces workload and tenant limits on each node. A tenant-wide resource
quota adds the missing fleet boundary: the tenant cannot consume a full node-local
allowance again on every additional server.

Inspect the selected tenant's current quota and reserved usage:

```console
stewardctl control quota status -tenant-id tenant-a
```

A tenant operator can inspect its own quota. Only a site administrator can set or
clear it. This example allows up to 8 GiB of requested memory, 8 CPUs, 2,048
processes, and 16 admitted agent workloads across all nodes:

```console
stewardctl control quota set \
  -tenant-id tenant-a \
  -memory-mib 8192 \
  -cpu-millis 8000 \
  -pids 2048 \
  -workloads 16
```

The CLI reads the retained revision before a change. Automation that already read
the record can pass `-revision` so a stale writer receives `409` instead of
overwriting a newer decision. Clear the fleet ceiling without changing Executor's
node-local safety limits:

```console
stewardctl control quota clear -tenant-id tenant-a
```

Quota measures raw requests from signed admission intent. It does not include the
fixed relay and runtime overhead that Executor separately reserves on each node.
An instance reserves quota atomically when admission is queued. Pending work that
has never won admission does not consume quota; admitting, running, stopping,
destroying, or ambiguous failed work keeps its reservation until Steward observes
removal or absence.

Lowering a ceiling below current use does not evict an agent or claim that it
stopped. Status becomes `over_quota`, new admissions receive the stable blocked
reason `tenant_quota_exhausted`, and the attention feed emits
`tenant_quota_exceeded` for each exceeded resource. At the configured capacity
threshold it emits `tenant_quota_warning` before the ceiling is crossed.

The React console shows this boundary and live usage when one tenant is selected.
Quota changes stay in the CLI/API so the browser remains a read-only policy view.
This quota does not cover disk bytes or inodes; see
[Current limitations]({{ '/limitations/' | relative_url }}#persistent-docker-state-is-dedicated-host-only).

## Freeze new command delivery during an incident

Use an operational freeze when new lifecycle commands must stop while responders
investigate. A site freeze covers every tenant. A tenant freeze covers only that
tenant, and a tenant operator can inspect and change only its own tenant freeze.

With a saved tenant context, these commands act on that tenant:

```console
stewardctl control freeze status
stewardctl control freeze set -reason "suspected credential compromise"
stewardctl control freeze clear
```

A site administrator can act on one named tenant with `-tenant-id tenant-a`, or
override a tenant saved in the current context and act on the whole site with
`-site`:

```console
stewardctl control freeze set -site -reason "site incident investigation"
stewardctl control freeze status -site
stewardctl control freeze clear -site
```

The CLI reads the current revision before changing the record. The controller
rejects a stale concurrent change instead of overwriting it. Automation that has
already read the retained revision can pass it explicitly with `-revision`.
Freeze and clear transitions, including exact retries, remain durable across a
controller restart.

A freeze blocks new command creation and delivery at command boundaries. It also
pauses deployment reconciliation before the next lifecycle command. It does not
recall a command already leased to a node, terminate a running workload, revoke a
credential, cancel an external effect, or invalidate authority already accepted
by Executor. Node heartbeats, terminal reports, and evidence continue so incident
responders retain visibility.

Use the narrower control that matches the incident:

- Freeze the tenant or site when the controller must stop sending new work.
- Quarantine a suspected node to stop placement and command delivery to that node.
- Quarantine one snapshot when its state may be contaminated but its source node
  should otherwise remain usable.
- Revoke a credential or delegated authority when that authority must no longer be
  usable; do not treat a freeze as revocation.
- Preserve evidence before destructive recovery work.

The React console shows the effective site or tenant freeze at the top of every
view. Freeze changes remain CLI/API operations so the browser does not gain a new
incident-response mutation path.

### Prevent new forks from a suspect snapshot

Snapshot quarantine is the narrowest containment control for persistent state.
It binds the tenant, source node, and snapshot identity, so a snapshot with the
same name in another tenant or on another node is unaffected.

```console
stewardctl control snapshot status \
  -tenant-id tenant-a -node-id node-a -snapshot-id snapshot-a

stewardctl control snapshot quarantine \
  -tenant-id tenant-a -node-id node-a -snapshot-id snapshot-a \
  -reason "untrusted content may have entered agent state"
```

The CLI reads the retained revision before changing the record. A new fork from
that exact snapshot then fails with `snapshot_quarantined`. Existing forks and
running workloads are unchanged because their admission and cloned state already
exist. Preserve evidence and use node quarantine, freeze, revocation, or workload
cleanup separately when the incident is broader.

After investigation, clear the gate explicitly:

```console
stewardctl control snapshot unquarantine \
  -tenant-id tenant-a -node-id node-a -snapshot-id snapshot-a
```

The cleared record remains durable with a higher revision. This prevents an old
operator view from silently restoring an earlier decision after restart.

### Read the current incident chronology

Use the incident timeline to see current containment, evidence divergence,
credential revocation, and failed-workload facts in one newest-first view:

```console
stewardctl control incident timeline
```

With a tenant context, the result is automatically limited to that tenant. A
site administrator can select one tenant with `-tenant-id tenant-a` or omit it
for the site-wide view. Narrow the result when investigating one system:

```console
stewardctl control incident timeline \
  -node-id node-a \
  -kind containment \
  -severity critical
```

Categories are `containment`, `evidence`, `access`, and `workload`. Severities
are `info`, `warning`, and `critical`. The output contains bounded metadata only;
it never contains command envelopes, command results, credentials, prompts,
request or response bodies, or logs.

This chronology shows the latest retained facts, not every historical change. A
later state transition replaces the earlier retained transition, and bounded
records can eventually disappear. Use signed Executor and Gateway evidence plus
an external log or security information and event management (SIEM) system when
you require complete historical reconstruction.

### Preserve a metadata-only support bundle

A site administrator can capture the whole-site incident context in one owner-only
JSON file before making destructive changes. A tenant operator can use the same
command with `-tenant-id` for only their tenant:

```console
stewardctl control support-bundle create \
  -out ./steward-support.json
```

Add `-tenant-id tenant-a` to restrict the bundle to one tenant. A bundle includes
the operations summary, attention findings, current incident timeline, freeze and
quota records, node and deployment state, agent and command metadata, credential
metadata, and, for a site-admin bundle, the last controller evidence checkpoint
for each visible node. Tenant bundles omit the site-wide freeze record and those
site-admin-only checkpoints rather than widening access or failing after the
tenant-scoped reads succeed.
Collection is read-only and bounded. It does not acknowledge a finding, retry a
command, stop an agent, or change incident state.

The format cannot represent raw prompts, request or response bodies, signed
command envelopes, credential values, private keys, agent result text, or logs.
The output file is created with owner-only permissions and the command prints a
`sha256:` digest. Preserve that digest through a separate authenticated channel;
keeping it beside the bundle does not establish provenance. Treat the remaining
metadata as sensitive: tenant, node, connector, and deployment names can still
disclose operational details.

Verify the strict format and recalculate the digest without contacting Control:

```console
stewardctl control support-bundle verify \
  -in ./steward-support.json \
  -expected-sha256 sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Verification requires the separately retained digest, rejects a byte mismatch,
then checks unknown fields, canonical JSON, the exclusion contract, evidence
checkpoints, tenant scope, and deployment identities. The bundle is not signed;
the trusted digest authenticates only the exact bytes you retained, not that
Control or the host was uncompromised or that the recorded facts were true.

## Inspect fleet operations and action-required findings

The operations view combines retained controller facts into a bounded,
tenant-projected status. It does not run commands, clear ambiguity, acknowledge
findings, or approve remediation.

Read the summary:

```console
stewardctl control operations status \
  -control-url "$CONTROL_URL" \
  -token-file /secure/steward-control/tenant-a-operator.token \
  -ca-file "$CONTROL_CA"
```

A tenant operator is always projected to its own tenant. A site administrator can
omit `-tenant-id` for the site-wide view or select one exact tenant.

List actionable facts, optionally filtering by stable reason:

```console
stewardctl control attention list \
  -control-url "$CONTROL_URL" \
  -token-file /secure/steward-control/tenant-a-operator.token \
  -ca-file "$CONTROL_CA" \
  -reason evidence_stale \
  -limit 100
```

Reasons cover node contact, evidence witnessing and freshness, retained rollback
or equivocation, overdue or expired command delivery, failed or unknown command
outcomes, retained-record capacity, and tenant resource-quota pressure. Threshold
equality is actionable. Evidence
freshness is process-local, so every node is conservatively stale or unknown after
a controller restart until it reports again. The durable checkpoint and sticky
finding do not reset.

List observed agent runtimes for the current tenant projection:

```console
stewardctl control agent list \
  -control-url "$CONTROL_URL" \
  -token-file /secure/steward-control/tenant-a-operator.token \
  -ca-file "$CONTROL_CA" \
  -status running
```

Each record separates the last successful workload observation from the latest
signed operation. A failed stop can therefore appear beside an observed
`running` status without falsely claiming that the workload stopped. The list is
read-only and excludes command bodies, task authority, relay endpoints, errors,
and secret values.

Inspect command metadata across a scope without returning signed command bytes,
terminal result bodies, reported status text, or error codes:

```console
stewardctl control command list \
  -control-url "$CONTROL_URL" \
  -token-file /secure/steward-control/tenant-a-operator.token \
  -ca-file "$CONTROL_CA" \
  -state terminal \
  -terminal-status outcome_unknown
```

Inspect non-secret credential metadata without returning bearer material or token
verifiers:

```console
stewardctl control credential list \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -kind node \
  -revoked any
```

When metrics are enabled, configure the scraper to read a least-privilege operator
bearer from an owner-only file and send it as the `Authorization: Bearer` header to
`/metrics`. Do not put the bearer directly in a command line or world-readable
scraper configuration. Metrics use only fixed labels for scope, resource, state,
status, reason, and severity. They omit tenant, node, credential, and command IDs,
prompts, bodies, results, and credentials.

Tenant query parameters are not part of Prometheus series identity. If one
Prometheus server scrapes several tenant projections from the same controller,
give each target a distinct trusted label or job. For example:

```yaml
scrape_configs:
  - job_name: steward-control-tenants
    scheme: https
    metrics_path: /metrics
    params:
      tenant_id: [tenant-a]
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/steward-tenant-a.token
    tls_config:
      ca_file: /etc/prometheus/pki/steward-control-ca.crt
    static_configs:
      - targets: [control.customer.example:8443]
    relabel_configs:
      - source_labels: [__param_tenant_id]
        target_label: steward_tenant
```

`steward_tenant` is added by the trusted scraper, not emitted by Steward. It
prevents tenant projections from colliding, but it also places the tenant ID in
Prometheus labels and storage. Use opaque operator-approved aliases or separate
jobs when tenant names are sensitive, and keep the number of configured
projections bounded.

## Give a trusted MCP client fleet tools

`steward-mcp` can expose controller tools independently of node tools:

```json
{
  "mcpServers": {
    "steward-control": {
      "command": "/usr/local/bin/steward-mcp",
      "args": [
        "-control-url", "https://control.customer.example:8443",
        "-control-token-file", "/home/alice/.config/steward/tenant-a-operator.token",
        "-control-ca-file", "/home/alice/.config/steward/control-ca.crt"
      ]
    }
  }
}
```

Control-plane MCP exposes tenant list/create, node list/status/revoke, signed
command submit/status, operations summary, attention, command and credential
inventory, and read-only `steward_control_evidence_status`. The
evidence tool projects the checkpoint and finding without returning raw proof
signatures or export files, and the controller authorizes it only for a site-admin
credential. Do not place a site-admin token in an MCP client that an untrusted
model or user can drive; a tenant-scoped token is the safer default for ordinary
fleet work.

MCP deliberately omits operator and enrollment credential issuance so a
model-facing tool cannot return new bearer secrets. Mutation tools require
explicit model-visible acknowledgments, but those booleans are not human approval
or authorization. The configured operator token and the node-verified signature
remain the security boundary.

## Back up, restore, and upgrade

The state directory contains the authentication key, witness private and public
keys, credential verifiers, tenants, node bindings, exact signed commands,
delivery state, and terminal reports. Treat a backup as a sensitive control-plane
artifact even though bearer tokens are not stored in plaintext. The authentication
key and retained request metadata are sufficient to reproduce credentials that use
deterministic retry. The witness private key can sign exports under the controller's
established audit identity.
The controller exposes bootstrap recovery only under the narrow conditions above,
but possession of a backup still carries authentication authority, not just
inventory.

1. Stop `steward-control` and confirm it is inactive.
2. Copy the entire owner-only state directory as one unit while preserving owner,
   modes, and its regular-file, single-link layout.
3. Protect the backup with the same controls as the live management host.
4. Restore only the entire directory to a stopped controller of a compatible
   release. On a replacement host, verify that it contains only single-link regular
   files, set the directory to mode `0700`, set
   `witness.public.pem` and `controller.public.pem` to mode `0644`, and set every
   other file to mode `0600`
   under the target `steward-control` user and group. Start the service, then run
   the controller doctor to verify configuration and readiness. The doctor
   deliberately reports an inactive service as a failure, even when its
   stopped-state validation succeeds.

Never restore only the write-ahead log, snapshot, manifest, authentication key, or
one key file. Restore the witness pair and controller-signing pair together or the
controller will fail closed. Restoring an older controller identity also requires
new tenant delegations before reconciliation can resume.
The write-ahead log is a hash-chained durable transaction file. Startup repairs
only an incomplete final frame, which is the expected shape of a crash during one
append; a malformed complete frame or broken chain stops startup.

The installer stages a new immutable release, validates configuration and durable
state, and switches the service only after those checks pass. If activation fails,
it restores the prior release. Back up before an upgrade, and do not delete the
prior release until the controller has served real enrollment, polling, and command
status traffic under the new one.

Installing an older controller over a successfully upgraded installation is not a
supported rollback procedure. Newer configuration keys or durable formats may be
unknown to the older release. Use the installer's automatic failed-upgrade
rollback, or restore a complete backup with a release documented as compatible
with that backup.

## Current limits

The controller includes a bounded React operator console, deterministic placement,
resource reservations, disruption-budgeted rollouts, and node-local snapshot
forks. Blocked deployments expose stable reason codes and resume after their
condition is repaired. A temporary fork is pinned to its snapshot node and follows
the signed clone, admit, run, stop, destroy, and purge lifecycle automatically.

The controller intentionally has no enterprise single sign-on, business approval
workflow, autoscaling, preemption, multi-controller high availability, external
database adapter, or cross-node state replication. Its job is a small reliable
path from bounded tenant authority to a node that independently verifies it, not
general cluster orchestration.

Default retained-capacity ceilings include 256 tenants, 4,096 nodes, 16,384
credentials, 4,096 enrollment capabilities, 16,384 commands, and 1,024 desired
deployments, with smaller per-tenant and per-node ceilings. Expired enrollment records are reclaimed when a
new enrollment needs space. Commands with known terminal outcomes become eligible
for reclamation after the configured minimum retention period, which defaults to
24 hours. Pending, leased, `failed`, and `outcome_unknown` commands are not
reclaimed automatically.

The durable format separately caps its encoded snapshot and write-ahead log at 64
MiB each. The packaged systemd service caps the process at 256 tasks, 4,096 open
files, and 1 GiB of memory. If measured, legitimate higher record ceilings require
more memory, apply a reviewed systemd drop-in and requalify startup, compaction,
backup, and restore instead of editing the packaged unit.

Tenant, node, and credential records are retained even after revocation and keep
consuming capacity. There is no supported purge or compaction operation for them,
and an unresolved `failed` or `outcome_unknown` command also remains retained.
These are safety bounds, not service-level objectives. Use the operations summary,
attention view, or opt-in metrics to monitor retained usage, but continue to plan
ceilings from expected lifecycle volume, alert on `capacity_exceeded` API
responses, increase limits before known growth crosses them, and test restore
procedures before production use.

See the [Steward Control OpenAPI](https://github.com/hardrails/steward/blob/main/openapi/steward-control.v1.yaml)
for exact schemas, status codes, pagination, and error responses.
