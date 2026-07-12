---
title: Configure signed admission and offline receipts
description: Generate site and publisher keys, sign a Steward profile capsule and site policy, configure Executor, submit an instance intent, and verify receipts offline.
section: How-to guide
---

# Configure signed admission and offline receipts

This guide enables the opt-in signed authority chain. Run the authoring steps on an
operator workstation with `stewardctl`; carry only the required public artifacts
into the site through your approved transfer process. The node creates its own
receipt key locally.

## 1. Create independent keys

```console
mkdir steward-trust && cd steward-trust
stewardctl keygen -key-id site-root-1 \
  -private-out site-root.private.pem -public-out site-root.public
stewardctl keygen -key-id publisher-1 \
  -private-out publisher.private.pem -public-out publisher.public
```

`keygen` refuses to overwrite a file. Keep the site-root and publisher private
keys off the execution node. Do not place a receipt private key in Terraform,
cloud-init, tags, or an enrollment archive; the node configurator generates it.

## 2. Sign the local site policy

Insert the exact base64 publisher public key into `site-policy.json`:

```json
{
  "schema_version": "steward.admission.v1",
  "policy_id": "site-a",
  "policy_epoch": 1,
  "publishers": [{
    "key_id": "publisher-1",
    "public_key": "PASTE publisher.public HERE",
    "revoked": false,
    "allowed_profiles": [{"id":"generic-v1","version":"v1"}],
    "allowed_repositories": ["registry.internal/approved-agent"],
    "allowed_manifest_digests": ["sha256:PASTE_64_LOWERCASE_HEX"],
    "resource_ceiling": {
      "memory_bytes": 536870912,
      "cpu_millis": 1000,
      "pids": 128
    }
  }],
  "tenants": [{
    "tenant_id": "tenant-a",
    "publisher_key_ids": ["publisher-1"],
    "resource_ceiling": {
      "memory_bytes": 536870912,
      "cpu_millis": 1000,
      "pids": 128
    }
  }]
}
```

```console
stewardctl policy sign -in site-policy.json -out site-policy.dsse.json \
  -key site-root.private.pem -key-id site-root-1
stewardctl policy verify -in site-policy.dsse.json \
  -public-key site-root.public -key-id site-root-1
```

Increase `policy_epoch` for every replacement. Executor persists the highest
accepted epoch and rejects an older signed policy after activation.

## 3. Sign a reusable profile capsule

The manifest and config digests have different meanings. Obtain both through your
approved OCI import/inspection workflow; do not substitute a mutable tag.

```json
{
  "schema_version": "steward.admission.v1",
  "capsule_id": "approved-agent-2026-07",
  "publisher_key_id": "publisher-1",
  "profile": {"id":"generic-v1","version":"v1"},
  "image": {
    "repository": "registry.internal/approved-agent",
    "manifest_digest": "sha256:PASTE_MANIFEST_DIGEST",
    "config_digest": "sha256:PASTE_CONFIG_DIGEST",
    "platform": {"os":"linux","architecture":"amd64"}
  },
  "command": ["/usr/local/bin/agent", "--check"],
  "resources": {
    "memory_bytes": 536870912,
    "cpu_millis": 1000,
    "pids": 128
  },
  "capabilities": {"state":false,"inference":false,"service":false,"egress":false},
  "state": {"schema_version":"v1","path":"/state"},
  "service": {}
}
```

```console
CAPSULE_DIGEST=$(stewardctl capsule sign -in capsule.json \
  -out capsule.dsse.json -key publisher.private.pem -key-id publisher-1)
stewardctl capsule verify -in capsule.dsse.json \
  -public-key publisher.public -key-id publisher-1 >/dev/null
printf '%s\n' "$CAPSULE_DIGEST"
```

The digest identifies the exact serialized DSSE envelope, including its signature.

## 4. Configure node trust material atomically

On the Linux node, one command verifies the policy signature and schema, installs
public trust, generates the receipt key locally, initializes the admission fence
exactly once, builds and digest-pins the relay image, runs the real node preflight,
and restarts an already-active Executor only after validation succeeds:

```console
sudo /usr/local/libexec/steward/configure-admission \
  --policy site-policy.dsse.json \
  --site-root-public-key site-root.public \
  --site-root-key-id site-root-1 \
  --node-id node-a
```

The node writes its receipt public key to
`/etc/steward/node-receipts.public`. Retain that public key and the expected chain
head outside the node. The private key is generated on the node and never accepted
as a Terraform/cloud-init input.

Initialization is explicit and exclusive. Normal startup refuses a missing fence
instead of silently forgetting previously consumed generations.

Partial configuration, an invalid signature, a policy rollback, a changed receipt
key, a corrupt receipt chain, or a pending operation journal prevents signed
admission from starting.

## 5. Submit a fenced instance intent

The normal packaged path is the authenticated outbound Executor uplink. Send an
`admit` command whose payload has this shape; its command tenant, node, instance,
and generation must match the intent exactly:

```json
{
  "capsule_dsse_base64": "BASE64_OF_EXACT_capsule.dsse.json",
  "intent": {
    "tenant_id": "tenant-a",
    "node_id": "node-a",
    "instance_id": "agent-001",
    "lineage_id": "lineage-001",
    "generation": 1,
    "capsule_digest": "sha256:DIGEST_PRINTED_BY_STEWARDCTL",
    "resources": {
      "memory_bytes": 536870912,
      "cpu_millis": 1000,
      "pids": 128
    },
    "capabilities": {"state":false,"inference":false,"service":false,"egress":false},
    "state_disposition": "none"
  }
}
```

For a deliberately enabled loopback Executor listener, the operator must also set
`-admission-allow-host-admin-intent` before POSTing the same object to
`/v1/admissions`. This is a privileged break-glass mode: the token authorizes every
tenant on the node. Without that flag, tenant identity must arrive through the
non-forgeable in-process principal established by the authenticated uplink.

Executor verifies both signatures, applies the capsule/policy/intent intersection,
journals the operation, writes a pre-effect receipt, creates and inspects the
gVisor container, writes the commit receipt, then advances the durable fences.
Start, stop, and destroy of a securely admitted workload use the same authenticated
generation, journal, and receipt chain. Destroy persists a tombstone; replaying the
consumed generation cannot recreate the absent container.

## 6. Verify receipts without the node

Copy `/var/lib/steward-executor/evidence.bin` and the previously retained
`node-receipts.public` to an offline audit workstation:

```console
stewardctl evidence verify -in evidence.bin \
  -public-key node-receipts.public -node-id node-a -epoch 1
```

Verification fails on a wrong key, changed frame, partial-frame truncation,
reorder, internal sequence gap, node mismatch, or epoch mismatch. Retain the last
verified sequence independently if you must detect removal of a complete signed
suffix. The receipt proves Steward's recorded
enforcement boundary—not prompt contents, model behavior, or resistance to a
host-root compromise.
