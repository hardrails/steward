---
title: Offline and verification tools
description: Inspect images, sign admission artifacts and exact permits, and verify Steward evidence without a hosted service.
section: Reference
---

# Offline and verification tools

`stewardctl` keeps signing and verification usable on disconnected systems. The
commands in this page do not require a private API or vendor account. Commands that
contact a node, Gateway, or Steward Control say so explicitly.

Run `stewardctl help <command>` for the focused command summary and
`stewardctl <command> ... -h` for exact flags.

## Create and verify a site authority package

Generate a valid initial site policy, separated Ed25519 roles, and Control TLS
material without contacting a service:

```console
stewardctl site init steward-site \
  -site-id site-a \
  -tenant-id tenant-a \
  -control-server-names control.customer.example
stewardctl site verify steward-site
```

`site verify` authenticates the signed inventory and policy, checks every recorded
digest and mode, and rejects unrecorded files. Supply
`-site-root-public-key FILE` to verify against a root obtained outside the package.
The generated directory is a custody handoff, not a secret store; separate its
private keys before deployment. See
[Create a site authority]({{ '/getting-started/site-authority/' | relative_url }}).

The nested node workflow composes that verified offline trust with Control's
online, one-time enrollment:

```console
stewardctl site connect steward-site \
  -control-url https://control.customer.example:8443 \
  -token-file /secure/control/site-admin.token
stewardctl site node prepare steward-site node-a
stewardctl site node verify steward-node-node-a
stewardctl site node activate steward-node-node-a
```

`connect` is the only command in this group that requires a site-administrator
Control connection. It creates the tenant, writes a recoverable tenant-scoped
operator bearer, and selects a CLI context without retaining the administrator
bearer. It accepts `-control-url`, `-token-file`, `-ca-file`, `-context`,
`-operator-token-out`, `-request-id`, `-node-id`, and
`-site-root-public-key`. `prepare` uses the resulting tenant operator and accepts
`-control-url`, `-token-file`, `-ca-file`,
`-valid-for`, `-request-id`, `-out`, and `-site-root-public-key`; the connection
flags can come from the current CLI context. `verify` is offline. `activate`
contacts the Control origin recorded in the prepared package, retains a resumable
node-local receipt identity, and accepts `-out` and `-site-root-public-key`.

## Generate and inspect keys

Create an Ed25519 key pair:

```console
stewardctl keygen \
  -private-out tenant.private.pem \
  -public-out tenant.public
```

The private output is created as a new owner-only file. Authenticate public-key
files and their key IDs through an independent process before trusting signatures.

Check that two files form a pair:

```console
stewardctl key match \
  -private-key tenant.private.pem \
  -public-key tenant.public
```

## Sign workload and site policy artifacts

A workload profile, called a capsule in the wire contract, fixes the OCI image
identity and the maximum capabilities the publisher allows. A site policy fixes
what the local operator permits.

```console
stewardctl capsule sign -in capsule.json -out capsule.dsse.json \
  -key publisher.private.pem -key-id publisher-1

stewardctl capsule verify -in capsule.dsse.json \
  -public-key publisher.public -key-id publisher-1

stewardctl policy sign -in policy.json -out policy.dsse.json \
  -key site.private.pem -key-id site-1

stewardctl policy verify -in policy.dsse.json \
  -public-key site.public -key-id site-1
```

These commands authenticate bytes. They do not decide whether a publisher or site
key should be trusted.

## Delegate bounded reconciliation authority

A tenant command key can authorize one short-lived controller key without giving
the tenant private key to Steward Control. This is currently an advanced offline
operation: the operator creates and reviews the instance and admission-template
documents before signing.

Describe the exact instance and lineage identities the controller may place:

```json
{
  "instances": [
    {
      "instance_id": "analyst-1",
      "lineage_id": "analyst-lineage-1",
      "min_instance_generation": 1,
      "max_instance_generation": 4
    }
  ]
}
```

When `admit` is delegated, also provide the exact non-identity admission template:

```json
{
  "capsule_digest": "sha256:<capsule-envelope-digest>",
  "resources": {
    "memory_bytes": 1073741824,
    "cpu_millis": 1000,
    "pids": 128
  },
  "capabilities": {
    "state": false,
    "inference": true,
    "service": true,
    "egress": false,
    "connector": false
  },
  "state_disposition": "none",
  "inference_route_id": "local-model",
  "model_alias": "agent-default",
  "service_id": "hermes-api",
  "placement": {
    "required_isolation": "gvisor",
    "required_labels": [
      {"key": "region", "value": "west"}
    ],
	"preferred_labels": [
	  {"key": "disk", "value": "fast"}
	],
	"spread_by": "zone",
    "tolerations": []
  }
}
```

`placement` is optional. When present, label entries and tolerations must be
sorted and unique. Keys, values, and tolerations may contain letters, digits,
`.`, `_`, `:`, `/`, and `-`, up to 128 bytes each. Every taint published by a
candidate node must have an exact toleration. Required labels and tolerations
are hard constraints. Preferred labels and `spread_by` affect only deterministic
ranking among eligible nodes. The placement contract is tenant-signed with the
rest of the template; Control cannot weaken it.

Issue and verify the delegation on the signing workstation:

```console
stewardctl executor-command delegation issue \
  -delegation-id analyst-deployment \
  -tenant-id tenant-a \
  -controller-public-key controller.public \
  -controller-key-id controller-online \
  -operations admit,renew,start,stop,destroy,read \
  -node-ids executor-1,executor-2 \
  -instances instances.json \
  -admission-template admission-template.json \
  -claim-generation 1 \
  -valid-for 1h \
  -key tenant-command.private.pem \
  -key-id tenant-command \
  -out controller.delegation.dsse.json

stewardctl executor-command delegation verify \
  -in controller.delegation.dsse.json \
  -public-key tenant-command.public \
  -key-id tenant-command
```

The tenant command key must be authorized by site policy for every operation in the
delegation. Lists are sorted into a canonical representation. Instance identities
are exact rather than prefix-based, so independent nodes cannot each create extra
replicas under one delegation.

An advanced command issuer can attach the exact delegation while signing with the
controller key:

```console
stewardctl executor-command issue \
  -command-id start-analyst-1 \
  -tenant-id tenant-a \
  -node-id executor-1 \
  -instance-id analyst-1 \
  -kind start \
  -claim-generation 1 \
  -instance-generation 1 \
  -sequence 2 \
  -payload empty.json \
  -delegation controller.delegation.dsse.json \
  -key controller.private.pem \
  -key-id controller-online \
  -out start.dsse.json
```

Executor independently verifies the tenant signature, controller signature,
delegation digest, exact scope, and normal generation and sequence fences. A
delegation limits authority but does not make a compromised controller available
or honest inside that scope.

## Inspect an offline OCI image

Inspect the exact image archive before transfer:

```console
stewardctl image inspect \
  -archive agent.tar \
  -capsule capsule.dsse.json \
  -publisher-public-key publisher.public \
  -publisher-key-id publisher-1
```

Import is a privileged node operation because it loads the sanitized archive into
Docker:

```console
sudo stewardctl image import \
  -archive agent.tar \
  -capsule capsule.dsse.json \
  -policy policy.dsse.json \
  -publisher-public-key publisher.public \
  -publisher-key-id publisher-1 \
  -site-root-public-key site.public \
  -site-root-key-id site-1
```

The importer verifies referenced OCI blobs, discards tags and unrelated archive
content, and loads only the pinned image. It does not establish build provenance;
authenticate the build and archive source separately.

## Authorize an exact connector action

Authorized Effects binds one permit to a tenant, node, instance generation, grant,
connector operation, task ID, canonical operation-policy digest, content type,
request length, and request digest.

Create the immutable approval context:

```console
stewardctl permit context \
  -admission admission.json \
  -intent intent.json \
  -receipts gateway-receipts.jsonl \
  -receipt-public-key gateway-receipts.public \
  -receipt-node-id gateway-node-a \
  -receipt-epoch 1 \
  -out action.context.json
```

Issue or add an approval with a private key that remains outside the workload:

```console
stewardctl permit issue \
  -admission admission.json \
  -intent intent.json \
  -context action.context.json \
  -trust action-trust.json \
  -request request.json \
  -connector-id tickets \
  -operation-id create \
  -task-id task-001 \
  -key approver-a.private.pem \
  -key-id approver-a \
  -out action.permit.json

stewardctl permit approve \
  -in action.permit.json \
  -admission admission.json \
  -intent intent.json \
  -trust action-trust.json \
  -request request.json \
  -key approver-b.private.pem \
  -key-id approver-b \
  -out action.approved.json
```

Verify before transfer:

```console
stewardctl permit verify \
  -in action.approved.json \
  -authority approver-a=approver-a.public \
  -authority approver-b=approver-b.public \
  -request request.json
```

Exact flag combinations vary by permit schema and approval threshold. Use
`stewardctl help permit` and the
[Authorized Effects guide]({{ '/guides/authorized-effects/' | relative_url }})
for a complete configured example.

## Authorize and recover a service task

A task bundle contains one exact tenant-signed request for a configured lifecycle
service such as the bounded Hermes or OpenClaw adapter.

Issue and verify the owner-only bundle on a signing station:

```console
stewardctl task issue \
  -admission admission.json \
  -intent intent.json \
  -trust service-trust.json \
  -operation-id hermes.run \
  -task-id task-001 \
  -request run.json \
  -key tenant.private.pem \
  -key-id tenant-task-1 \
  -out task.json

stewardctl task verify -in task.json \
  -public-key tenant.public -key-id tenant-task-1 \
  -request run.json
```

Submit it to a local Gateway:

```console
sudo stewardctl task submit \
  -bundle task.json \
  -gateway-url http://127.0.0.1:8091 \
  -token-file /etc/steward/gateway-service-token
```

Recover the same task after a timeout or disconnect:

```console
sudo stewardctl task wait \
  -bundle task.json \
  -gateway-url http://127.0.0.1:8091 \
  -token-file /etc/steward/gateway-service-token \
  -result-out task-result.json
```

Do not mint a replacement task ID after an ambiguous submission. The original
bundle is the recovery handle. Gateway can return the recorded run identity without
dispatching the external operation again.

## Verify Executor evidence

Export a node receipt chain:

```console
stewardctl evidence export \
  -node-url http://127.0.0.1:8090 \
  -token-file /etc/steward/executor-observer-token \
  -out executor-evidence.json
```

Verify it on a disconnected system:

```console
stewardctl evidence verify \
  -in executor-evidence.json \
  -public-key node-receipts.public
```

Use expected sequence and chain-hash checkpoints when you need rollback detection,
not merely signature validation. Preserve the last accepted checkpoint outside the
node.

## Verify Gateway action evidence

Gateway receipt exports bind authorization, permit digest, exact request digest,
spend, dispatch, and observed outcome metadata. They omit raw request and response
bodies.

```console
stewardctl permit audit \
  -in action.approved.json \
  -authority approver-a=approver-a.public \
  -authority approver-b=approver-b.public \
  -receipts gateway-receipts.jsonl \
  -receipt-public-key gateway-receipts.public \
  -receipt-node-id gateway-node-a \
  -receipt-epoch 1 \
  -request request.json
```

For service tasks:

```console
stewardctl task audit \
  -in task.json \
  -public-key tenant.public \
  -key-id tenant-task-1 \
  -receipts gateway-receipts.jsonl \
  -receipt-public-key gateway-receipts.public \
  -receipt-node-id gateway-node-a \
  -receipt-epoch 1 \
  -request run.json
```

An audit proves what Steward signed and correlated. It does not prove that an
untrusted agent's natural-language result is true or that an upstream service
performed the desired business operation.

## Validate secret materialization

Steward's secret handoff is provider-neutral. Prepare protected destinations from a
non-secret manifest, let the operator-selected materializer write values and epoch
markers, then validate readiness:

```console
sudo stewardctl secret materialization prepare \
  -manifest /etc/steward/secrets/materialization.json

sudo stewardctl secret materialization check \
  -manifest /etc/steward/secrets/materialization.json
```

The report includes readiness and rotation epochs, never secret plaintext.

## Save connection context and completion

A CLI context stores paths to token files, not token values:

```console
sudo -H stewardctl context set local-node \
  -node-token-file /etc/steward/executor-observer-token
sudo -H stewardctl node whoami
```

Install completion for the current shell:

```console
stewardctl completion install
```

See [CLI ergonomics]({{ '/guides/cli/' | relative_url }}) for context precedence,
security boundaries, and non-interactive use.
