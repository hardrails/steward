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
  -private-key publisher.private.pem -key-id publisher-1

stewardctl capsule verify -in capsule.dsse.json \
  -public-key publisher.public -key-id publisher-1

stewardctl policy sign -in policy.json -out policy.dsse.json \
  -private-key site.private.pem -key-id site-1

stewardctl policy verify -in policy.dsse.json \
  -public-key site.public -key-id site-1
```

These commands authenticate bytes. They do not decide whether a publisher or site
key should be trusted.

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
  -config /etc/steward/gateway.json \
  -intent intent.json \
  -tenant-id tenant-a \
  -instance-id agent-1 \
  -generation 7 \
  -grant-id grant-DIGEST \
  -connector-id tickets \
  -operation-id create \
  -task-id task-001 \
  -request request.json \
  -out action.context.json
```

Issue or add an approval with a private key that remains outside the workload:

```console
stewardctl permit issue \
  -context action.context.json \
  -private-key approver-a.private.pem \
  -key-id approver-a \
  -out action.permit.json

stewardctl permit approve \
  -in action.permit.json \
  -private-key approver-b.private.pem \
  -key-id approver-b \
  -out action.approved.json
```

Verify before transfer:

```console
stewardctl permit verify \
  -in action.approved.json \
  -context action.context.json \
  -public-key approver-a.public \
  -public-key approver-b.public
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
  -service-id hermes-api \
  -operation-id hermes.run \
  -task-id task-001 \
  -request run.json \
  -private-key tenant.private.pem \
  -key-id tenant-task-1 \
  -out task.json

stewardctl task verify -bundle task.json \
  -public-key tenant.public -key-id tenant-task-1
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
  -permit action.approved.json \
  -receipts gateway-receipts.jsonl \
  -receipt-public-key gateway-receipts.public
```

For service tasks:

```console
stewardctl task audit \
  -bundle task.json \
  -receipts gateway-receipts.jsonl \
  -receipt-public-key gateway-receipts.public
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
