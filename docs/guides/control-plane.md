---
title: Operate the bundled Steward control plane
description: Install Steward Control, create tenants and scoped operators, enroll multi-tenant nodes, deliver signed commands, use MCP, and protect durable state.
section: How-to
---

# Operate the bundled Steward control plane

`steward-control` is Steward's optional self-hosted fleet service. It gives a site
one bounded place to create tenants, issue scoped operator credentials, enroll
nodes, inspect inventory, retain exact signed commands, lease those commands to
Executor, and record terminal delivery status.

The controller does not sign commands or decide what a tenant may run. Tenant and
site private signing keys remain on a trusted signing station or in a separately
operated signing service. The node verifies every signed command against its local
site policy before Executor can change Docker. This separation means compromise of
the controller can delay or replay delivery attempts, but cannot mint tenant
authority or add an undeclared container capability.

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

The guided first install asks for a path for the first site-administrator bearer.
For unattended installation, make that choice explicit:

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/hardrails/steward/releases/latest/download/install-control.sh | \
  sudo /bin/bash -p -s -- --non-interactive \
    --admin-token-out /root/steward-control-admin.token
```

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

The first installation also creates a dedicated Ed25519 evidence-witness identity:

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

Create a tenant:

```console
stewardctl control tenant create \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -tenant-id tenant-a
```

Use the site administrator only for site-wide changes. Issue a tenant-scoped
operator for routine work. `request-id` is a caller-chosen idempotency key: reuse
the same value after an ambiguous timeout instead of requesting another secret.
The output path must not already exist.

```console
stewardctl control operator issue \
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
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
  -control-url "$CONTROL_URL" \
  -token-file "$ADMIN_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -credential-id cred-EXAMPLE
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
command submit/status, and read-only `steward_control_evidence_status`. The
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
   `witness.public.pem` to mode `0644`, and set every other file to mode `0600`
   under the target `steward-control` user and group. Start the service, then run
   the controller doctor to verify configuration and readiness. The doctor
   deliberately reports an inactive service as a failure, even when its
   stopped-state validation succeeds.

Never restore only the write-ahead log, snapshot, manifest, authentication key, or
one witness-key file. Restore the witness pair together or the controller will
fail closed.
The write-ahead log is a hash-chained durable transaction file. Startup repairs
only an incomplete final frame, which is the expected shape of a crash during one
append; a malformed complete frame or broken chain stops startup.

The installer stages a new immutable release, validates configuration and durable
state, and switches the service only after those checks pass. If activation fails,
it restores the prior release. Back up before an upgrade, and do not delete the
prior release until the controller has served real enrollment, polling, and command
status traffic under the new one.

## Current limits

The controller intentionally has no user interface, enterprise single sign-on,
approval workflow, artifact catalog, automatic placement, desired-state
reconciliation, multi-controller high availability, or external database adapter.
Its job is the small reliable path between an already authorized command and a
node that independently verifies it.

Default retained-capacity ceilings include 256 tenants, 4,096 nodes, 16,384
credentials, 4,096 enrollment capabilities, and 16,384 commands, with smaller
per-tenant and per-node ceilings. Expired enrollment records are reclaimed when a
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
These are safety bounds, not service-level objectives. The controller does not yet
expose aggregate retained-record counts as metrics. Plan ceilings from expected
lifecycle volume, alert on `capacity_exceeded` API responses, increase limits
before known growth crosses them, and test restore procedures before production
use.

See the [Steward Control OpenAPI](https://github.com/hardrails/steward/blob/main/openapi/steward-control.v1.yaml)
for exact schemas, status codes, pagination, and error responses.
