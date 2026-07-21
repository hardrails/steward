---
title: Configure signed admission and offline receipts
description: Generate site and publisher keys, sign a Steward profile capsule and site policy, configure Executor, submit an instance intent, and verify receipts offline.
section: How-to guide
---

# Configure signed admission and offline receipts

This guide configures signed authority. Author artifacts with `stewardctl` on an
operator workstation and transfer only the required trust material through an
approved process. A standalone signed-admission node can generate its receipt key.
A control-plane-enrolled node must import the exact receipt key that proved
possession during enrollment.

## 1. Create independent keys

```console
mkdir steward-trust && cd steward-trust
stewardctl keygen -key-id site-root-1 \
  -private-out site-root.private.pem -public-out site-root.public
stewardctl keygen -key-id publisher-1 \
  -private-out publisher.private.pem -public-out publisher.public
stewardctl keygen -key-id tenant-a-commands \
  -private-out tenant-a-commands.private.pem -public-out tenant-a-commands.public
stewardctl keygen -key-id site-cleanup \
  -private-out site-cleanup.private.pem -public-out site-cleanup.public
```

`keygen` will not overwrite files. Keep site-root and publisher private keys off the
node, tenant command keys on a separate tenant signing station or service outside
Steward Control, and the independent cleanup key in a site incident-response
system. Site policy gives the node only public keys. Never put receipt or command
private keys in Terraform, cloud-init, tags, or cloud-provider metadata. Generate a
control-plane receipt key on the staged node and keep its private half there.

## 2. Sign the local site policy

Insert the exact base64 values from `publisher.public`,
`tenant-a-commands.public`, and `site-cleanup.public` into `site-policy.json`:

```json
{
  "schema_version": "steward.admission.v1",
  "policy_id": "site-a",
  "policy_epoch": 1,
  "site_cleanup_command_keys": [{
    "key_id": "site-cleanup",
    "public_key": "PASTE site-cleanup.public HERE",
    "operations": ["stop", "destroy", "purge", "delete-snapshot"]
  }],
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
    },
    "command_keys": [{
      "key_id": "tenant-a-commands",
      "public_key": "PASTE tenant-a-commands.public HERE",
      "operations": ["admit", "renew", "start", "stop", "destroy", "read", "purge", "snapshot-state", "clone-state", "delete-snapshot", "activation-canary"]
    }]
  }]
}
```

```console
stewardctl policy sign -in site-policy.json -out site-policy.dsse.json \
  -key site-root.private.pem -key-id site-root-1
stewardctl policy verify -in site-policy.dsse.json \
  -public-key site-root.public -key-id site-root-1
```

Increase `policy_epoch` for each replacement. Executor stores the highest accepted
value and rejects older policy.

Node-scoped multi-tenant uplink requires at least one
`site_cleanup_command_keys` entry. These entries may authorize only `stop`,
`destroy`, `purge`, or `delete-snapshot`; their IDs cannot match tenant command keys. This site authority survives
tenant-key compromise or rule removal but cannot admit, start, or read. Each command
binds tenant, node, instance, generations, sequence, validity window, and runtime
reference to Executor's durable record. An emergency cleanup policy may set
`"tenants": []` to block admission while retaining containment and removal.

Each `command_keys` entry belongs to one tenant and authorizes its listed operations.
A tenant needs one for node-scoped remote control, but not for local administration
or a tenant-scoped compatibility credential.

Task keys are separate from lifecycle command keys. When a tenant must authorize an
exact agent-service request, generate another Ed25519 pair, keep its private file on
the signing workstation, list the service in the tenant's `service_ids`, and add
only this public policy entry:

```json
"task_keys": [{
  "key_id": "tenant-a-tasks",
  "public_key": "PASTE tenant-a-tasks.public HERE",
  "service_ids": ["agent-api"]
}]
```

Each tenant may have at most eight task keys. Service IDs within a key must be
sorted, unique, and already allowed for that tenant. Executor returns only public
task authorities that match the admitted service. A task key cannot authorize
admission, lifecycle, another tenant, or an unlisted service. See the
[exact Hermes task workflow]({{ '/guides/hermes-agent/' | relative_url }}#authorize-and-run-one-exact-hermes-task).

Ed25519 task-key material must also be unique across all tenant rules in one site
policy. Steward rejects a policy that assigns the same public key to two tenants,
even under different key IDs. This prevents possession of one tenant's private key
from becoming cryptographic authority for another tenant through a policy mistake.

Action keys are separate again. For a tenant whose connector effects must remain
authorized even when the agent is fully manipulated, add `authorized_effects` to
the tenant rule, pin each public key to connector IDs, and require explicit
`"effect_mode":"authorized"` in the instance intent. Authorized mode prohibits
generic egress and requires a complete exact-request permit. `min_approvals` can
require distinct action keys over the same request. Follow the complete
[Authorized Effects procedure]({{ '/guides/authorized-effects/' | relative_url }}).
Set `"context_binding":"required"` only when each permit must also match the
grant's current signed connector-response history; follow the separate
[context-locking procedure]({{ '/guides/context-locked-effects/' | relative_url }}).

## 3. Sign a reusable profile capsule

The manifest digest identifies an Open Container Initiative (OCI) manifest; the
config digest identifies image configuration. Obtain both by inspection, never from
a mutable tag.

```console
chmod go-w agent-approved.tar
stewardctl image inspect -archive agent-approved.tar
```

Copy `manifest_digest`, `config_digest`, and `platform` exactly into the capsule.
Inspection hashes the bounded archive without contacting Docker or authorizing its
publisher. Select `repository` from the approved build or promotion record; archive
inspection does not establish repository provenance, and an OCI archive may contain
no repository name.

```json
{
  "schema_version": "steward.admission.v1",
  "capsule_id": "approved-agent",
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

If the capsule binds companion content such as a skill manifest or software bill
of materials (SBOM), list each exact artifact by kind and digest:

```json
"artifacts": [{
  "kind": "steward.agent-release.skill-manifest.v1",
  "digest": "sha256:PASTE_64_LOWERCASE_HEX"
}]
```

Copy the same exact `{kind, digest}` pair into `allowed_artifacts` in both the
publisher rule and the intended tenant rule. Publisher authorization is checked
before image import; publisher and tenant authorization are both checked before
admission. An artifact kind alone is not authority, and changing one byte requires
a new digest and policy approval. Each policy rule may contain at most 128 exact
artifact entries.

A publisher rule with `allowed_artifacts` must also list the capsule's exact image
manifest digest in `allowed_manifest_digests`. Admission therefore requires both
an exact approved image manifest and an exact approved artifact declaration; an
unlisted image cannot reuse the declaration. These two allowlists form an
intersection, not a per-image tuple map. If one publisher rule lists several
manifests and several artifacts, any listed manifest may declare any listed
artifact. Use separate publisher rules and keys when that cross-product is too
broad. This check does not scan the image or prove that it contains those bytes.
Verify the exact companion artifact separately through the signed agent release
or another operator-controlled process before adding its digest to policy.

```console
CAPSULE_DIGEST=$(stewardctl capsule sign -in capsule.json \
  -out capsule.dsse.json -key publisher.private.pem -key-id publisher-1)
stewardctl capsule verify -in capsule.dsse.json \
  -public-key publisher.public -key-id publisher-1 >/dev/null
printf '%s\n' "$CAPSULE_DIGEST"
```

The digest identifies the exact serialized DSSE (Dead Simple Signing Envelope),
including its signatures. DSSE binds a typed payload to those signatures.

## 4. Import the image under signed authority

Transfer the archive, capsule, policy, and site-root public key through approved
media. Authenticate them on the node before Docker receives image content:

```console
sudo stewardctl image import \
  -archive agent-approved.tar \
  -capsule capsule.dsse.json \
  -policy site-policy.dsse.json \
  -site-root-public-key site-root.public \
  -site-root-key-id site-root-1
```

Before calling Docker, import verifies signatures, publisher revocation,
repository, manifest, and exact companion-artifact allowlists, the built-in
profile, every blob, and the signed manifest/config/platform tuple. Docker receives
a sanitized archive with only the selected manifest, config, and layers. Steward then
inspects the local config and rejects declared volumes or platform drift. Import
does not authorize an instance; Executor later requires capsule, policy, and tenant
intent to agree.

## 5. Configure node trust material atomically

For initial multi-tenant enrollment, pass these trust files with both uplink
credentials to `configure-node`; see
[Enroll and activate a Steward node]({{ '/getting-started/enroll/' | relative_url }}).
Do not activate a node-scoped credential separately.

Use `configure-admission` only after `configure-node` or the full installer has
created the node's base local or remote enrollment. A package staged with
`--stage-only` does not yet have the token and base configuration that preflight
requires. On a configured node, `configure-admission` adds signed trust without
changing its control-plane credential, or replaces policy on an enrolled node.
The command verifies policy, installs public trust, imports a supplied receipt key
pair or generates one when no enrollment identity exists, initializes missing
fence, journal, and evidence stores with their service ownership,
ensures that the active release has a verified relay-image binding, runs preflight,
and restarts an active Executor. A failed transaction removes only stores and keys
that it created. Authenticate the two files, then copy them into a protected
root-owned directory before configuration. Changes activate only after all checks
pass:

```console
sudo install -d -o root -g root -m 0700 /root/steward-admission
sudo install -o root -g root -m 0644 site-policy.dsse.json \
  /root/steward-admission/site-policy.dsse.json
sudo install -o root -g root -m 0644 site-root.public \
  /root/steward-admission/site-root.public
sudo /usr/local/libexec/steward/configure-admission \
  --policy /root/steward-admission/site-policy.dsse.json \
  --site-root-public-key /root/steward-admission/site-root.public \
  --site-root-key-id site-root-1 \
  --node-id node-a
```

For a control-plane-enrolled node, also pass `--receipt-private-key` and
`--receipt-public-key` using the pair created before enrollment exchange. The
helper validates the pair and refuses to replace an installed evidence identity.

An omitted compatibility flag preserves its current installed value during
reconfiguration. Disabling an existing exception is explicit:

```console
sudo /usr/local/libexec/steward/configure-admission \
  --policy /root/steward-admission/site-policy.dsse.json \
  --site-root-public-key /root/steward-admission/site-root.public \
  --site-root-key-id site-root-1 \
  --disallow-host-admin-intent \
  --disallow-unquotaed-state-on-dedicated-host
```

Before signing a hand-authored capsule, run
`stewardctl capsule check-profile -in capsule.json`. Signing and verification
repeat the same check. See the [runtime profile contracts]({{
'/reference/runtime-profiles/' | relative_url }}) for the exact command, state,
and service values.

Rollback here covers handled process errors only. After `SIGKILL` or power loss,
keep the node services stopped and follow an approved whole-configuration recovery;
rerunning does not automatically restore the pre-change files. Preserve every
fence, journal, and evidence file during recovery.

Retain `/etc/steward/node-receipts.public` and the expected chain head outside the
node. The head is the last sequence and hash needed to detect suffix removal. The
node-generated private key is never accepted through Terraform or cloud-init.

Startup rejects a missing fence instead of forgetting consumed generations.

Partial configuration, invalid signatures, policy rollback, receipt-key change, or
corrupt evidence stops startup. A valid pending journal allows degraded startup but
blocks admission and other normal mutations until an operator resolves it.

Signed control stores have finite lifetime limits: 64 MiB for evidence, 16 MiB for
the operation journal, 4 MiB and 65,535 records for admission fences, and 1 MiB for
encoded Executor uplink state. There is no supported rollover or compaction command.
Monitor these files and plan node retirement before a limit blocks further signed
mutations. See [durable control-store limits]({{ '/limitations/' | relative_url }}#durable-control-stores-have-fixed-lifetime-limits).

## 6. Submit a fenced instance intent

Normally, send `admit` through Executor's authenticated outbound uplink. Command and
intent must name the same tenant, node, instance, and generation:

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

For a deliberately enabled loopback listener, set
`-admission-allow-host-admin-intent` before posting to `/v1/admissions`. This
recovery option lets the token authorize every tenant. Otherwise tenant identity
must come from the authenticated uplink.

Executor verifies signatures and requires capsule, policy, and intent to agree. A
capsule companion artifact must match an exact allowlist entry under both publisher
and tenant authority. Executor journals the operation, writes a pre-effect receipt,
creates and inspects the gVisor container, writes a commit receipt, then advances
fences. Lifecycle operations use the same identity, journal, and chain. A destroy
tombstone prevents generation replay.

## 7. Verify and export receipts without the node

Copy `/var/lib/steward-executor/evidence.bin` and the previously retained
`node-receipts.public` to an offline audit workstation:

```console
stewardctl evidence verify -in evidence.bin \
  -public-key node-receipts.public -node-id node-a -epoch 1
```

Wrong keys, changed frames, a partial trailing frame, reordering, sequence gaps, and
node or epoch mismatches fail verification. Removing one or more complete records
from the end can form a valid shorter chain; detecting that requires the exact
off-node head described below. For automation, emit JSON:

```console
stewardctl evidence verify -in evidence.bin \
  -public-key node-receipts.public -node-id node-a -epoch 1 \
  -json > verified-head.json
```

Retain `head.sequence` and `head.chain_hash` off-node. Supply both when verifying the
same checkpoint to detect removal or replacement of a signed suffix:

```console
EXPECTED_SEQUENCE="<retained-sequence>"
EXPECTED_CHAIN_HASH="sha256:<retained-chain-hash>"
stewardctl evidence verify -in evidence.bin \
  -public-key node-receipts.public -node-id node-a -epoch 1 \
  -expected-sequence "$EXPECTED_SEQUENCE" \
  -expected-chain-hash "$EXPECTED_CHAIN_HASH"
```

Export verified newline-delimited JSON with the same rollback expectations:

```console
stewardctl evidence export -in evidence.bin \
  -public-key node-receipts.public -node-id node-a -epoch 1 \
  -expected-sequence "$EXPECTED_SEQUENCE" \
  -expected-chain-hash "$EXPECTED_CHAIN_HASH" > receipts.ndjson
```

Each record line has `"kind":"receipt"`; the final line has `"kind":"head"`.
The export is independently verifiable with the trusted node public key, node ID,
and key epoch. Each receipt contains its original signed frame, which is the source
of truth. The readable fields are a human-readable copy that verification checks
against the signed frame. Export emits output only after verifying that the
evidence file remained unchanged during the operation. Expected values assert the
exact head, not a minimum; after legitimate records are appended, retain and use
the new head. Receipts prove Steward's recorded enforcement, not prompt contents,
model behavior, or resistance to host-root compromise.
