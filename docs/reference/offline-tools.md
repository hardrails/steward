---
title: Local operator tools
description: Inspect OCI archives, verify evidence, and check release drain and durable-state compatibility with stewardctl.
section: Reference
---

# Local operator tools

`stewardctl image` inspects and imports image media, and `stewardctl evidence`
verifies receipts without a registry, transparency service, or vendor control plane.
Within those two command groups, only `image import` contacts Docker; the other
operations use local files. Commands under `stewardctl node` contact the local
Executor API.

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
flags can select the fence, journal, evidence, uplink, supervisor, and Gateway files.

The bounded JSON result reports active fences, pending journal operations, retained
Gateway grants, seven observed format versions, target compatibility, and
`drained`. The inventory includes the Gateway connector receipt log. A `null`
format means the file is absent or, for the Executor evidence log, has no record
header yet. Tombstone fences preserve replay history but do not count as active.
The command exits nonzero when workload or grant state remains, a file is malformed
or missing when required, or the target reader/writer range is unsafe.

`upgrade inspect-formats` returns the same seven format observations without requiring
a drained node. Activation uses it after a failed target start to decide whether the
prior release can safely read the state before restoring the old active-release
symlink and relay binding.

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
