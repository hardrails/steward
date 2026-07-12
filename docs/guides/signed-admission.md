---
title: Configure signed admission and offline receipts
description: Generate site and publisher keys, sign a Steward profile capsule and site policy, configure Executor, submit an instance intent, and verify receipts offline.
section: How-to guide
---

# Configure signed admission and offline receipts

This guide enables the opt-in v1.2 authority chain. Run the authoring steps on an
operator workstation with `stewardctl`; carry only the required public artifacts
and the node receipt key into the site through your approved transfer process.

## 1. Create independent keys

```console
mkdir steward-trust && cd steward-trust
stewardctl keygen -key-id site-root-1 \
  -private-out site-root.private.pem -public-out site-root.public
stewardctl keygen -key-id publisher-1 \
  -private-out publisher.private.pem -public-out publisher.public
stewardctl keygen -key-id node-receipts-1 \
  -private-out node-receipts.private.pem -public-out node-receipts.public
```

`keygen` refuses to overwrite a file. Keep the site-root and publisher private
keys off the execution node. The node receipt private key must reach Executor and
remain mode `0600`; its public half is what auditors need.

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
  "capabilities": {"state":false,"inference":false,"service":false},
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

## 4. Install node trust material

On the Linux node:

```console
sudo install -o root -g steward-executor -m 0640 \
  site-policy.dsse.json /etc/steward/site-policy.dsse.json
sudo install -o root -g root -m 0644 \
  site-root.public /etc/steward/site-root.public
sudo install -o steward-executor -g steward-executor -m 0600 \
  node-receipts.private.pem /etc/steward/node-receipts.private.pem
```

Append these no-whitespace values to `/etc/steward/executor.env`:

```text
EXECUTOR_ADMISSION_POLICY_FILE=/etc/steward/site-policy.dsse.json
EXECUTOR_ADMISSION_SITE_ROOT_PUBLIC_KEY_FILE=/etc/steward/site-root.public
EXECUTOR_ADMISSION_SITE_ROOT_KEY_ID=site-root-1
EXECUTOR_ADMISSION_NODE_ID=node-a
EXECUTOR_ADMISSION_EVIDENCE_KEY_FILE=/etc/steward/node-receipts.private.pem
```

Then validate and restart:

```console
sudo -u steward-executor steward-executor -initialize-admission-fence \
  -admission-fence-file /var/lib/steward-executor/admission-fences.bin
sudo /usr/local/libexec/steward/node-preflight
sudo systemctl restart steward-executor
```

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
    "capabilities": {"state":false,"inference":false,"service":false},
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
