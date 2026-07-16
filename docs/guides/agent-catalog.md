---
title: Curate agent releases for offline use
description: Build, transfer, verify, search, and compare a curator-signed catalog of exact agent releases without granting deployment authority.
section: Agent compatibility
---

# Curate agent releases for offline use

An agent catalog gives operators one signed, portable inventory of releases they
have chosen to review. It supports an outcome-first decision:

**What work does this release claim to do, what exact capabilities does it
request, and what evidence and limits accompany it?**

The catalog works without a hosted registry. It embeds each publisher-signed
agent release and the exact Ed25519 publisher public key needed to verify it.
Each entry also binds the archive, skill manifest, and qualification-evidence
files that the curator checked.

The catalog has **descriptive-only authority**. It cannot authorize a tenant,
node, image import, workload, capability, task, connector call, or rollout.
Catalog status values are signed curator labels, not admission decisions.

## Trust and verification model

Three different decisions remain separate:

1. **Publisher claim:** the publisher signs the release and embedded workload
   capsule.
2. **Curator selection:** the curator signs a catalog revision that pins the
   publisher identity, exact release, external file bindings, and entry status.
3. **Operator authorization:** the site policy, instance intent, current
   admission checks, and tenant task permits decide whether anything may run.

Obtain the curator public key and expected key ID through an authenticated
channel independent of the catalog file. The catalog embeds publisher public
keys so it can be verified offline, but the curator signature is what
authenticates those pinned publisher identities as part of that catalog.

`stewardctl agent-catalog verify` authenticates the curator signature, checks the
bounded catalog schema, and reverifies every embedded release and capsule with
its pinned publisher key. It evaluates each capsule at the signed catalog issue
time. This preserves historical verification after a capsule expires.

That historical check does **not** establish that a release is deployable now.
Before import or activation, run current-time release verification against the
publisher key and exact archive, then apply current site policy and admission
checks.

## Prepare the catalog inputs

For every entry, place these exact files on a trusted curation workstation:

- the publisher-signed agent release;
- the publisher's base64 Ed25519 public key and expected key ID;
- the offline Open Container Initiative (OCI) archive named by the release;
- the exact skill manifest named by the release; and
- the exact qualification-evidence file named by the release.

The curation workstation also needs an owner-only curator Ed25519 private key.
Generate one with `stewardctl keygen` if your key-management process does not
already provide it:

```console
stewardctl keygen \
  -private-out curator.private.pem \
  -public-out curator.public \
  -key-id site-agent-curator
```

Keep the curator private key outside workload nodes. A catalog needs no online
service, database, package manager, or dynamic code loader.

## Write a strict source manifest

The source manifest is unsigned operator input used only to create a signed
catalog. Every referenced input path must be relative to the manifest's
directory and contain no `..` component. Steward opens that directory once as a
descriptor-pinned root: later renames, symlink replacements, or other changes
to its pathname cannot redirect referenced-file opens into another directory.
Absolute paths and symlinks that escape the pinned root are rejected. Small
files also pass stable-file checks, and archives are copied to private
snapshots, before Steward trusts their bytes.

```json
{
  "schema_version": "steward.agent-catalog-source.v1",
  "catalog_id": "approved-site-agents",
  "revision": 12,
  "entries": [
    {
      "entry_id": "hermes-workspace-audit",
      "status": "approved",
      "release": "inputs/hermes-workspace-audit.release.dsse.json",
      "publisher_key_id": "publisher-key-id",
      "publisher_public_key": "inputs/publisher.public",
      "archive": "inputs/hermes-agent-adapter.tar",
      "skill_manifest": "inputs/steward.workspace-audit.manifest.json",
      "qualification_evidence": "inputs/hermes-qualification.json"
    }
  ]
}
```

`catalog_id`, `entry_id`, curator key IDs, and publisher key IDs must start with
an ASCII letter or digit. Remaining characters may be ASCII letters, digits,
`.`, `_`, or `-`. `entry_id` values must be unique. A catalog contains 1 to 64
entries. Each status must be one of:

- `candidate`: retained for evaluation;
- `approved`: selected under the curator's documented review process; or
- `retired`: no longer preferred by the curator.

Steward signs the status text but does not assign promotion semantics to it.
In particular, `retired` does not revoke a publisher or block an already
authorized workload.

## Issue and self-verify a catalog revision

```console
stewardctl agent-catalog issue \
  -manifest catalog-source.json \
  -key curator.private.pem \
  -key-id site-agent-curator \
  -out approved-site-agents.revision-12.dsse.json
```

Before signing, Steward:

- strictly decodes the bounded source manifest;
- verifies every release and embedded capsule with the supplied publisher key;
- reads every bounded publisher key, skill manifest, and
  qualification-evidence file, then checks its exact signed binding before
  opening any archive;
- rejects duplicate publisher/release identities, duplicate release envelopes,
  and one publisher key ID resolving to different public keys;
- rejects a catalog whose signed archive sizes total more than 64 GiB before
  opening any archive;
- confines every referenced-file open beneath the descriptor-pinned manifest
  directory;
- inspects each untrusted archive through a stable private snapshot while
  enforcing the remaining cumulative expansion budget;
- checks the archive digest, byte length, image manifest, configuration, and
  platform against the release;
- sorts entries by `entry_id`; and
- self-verifies the completed catalog.

The 64 GiB aggregate limit applies to signed source archive bytes and counts an
archive each time an entry asks Steward to inspect it. It allows all 64 entries
when each archive is at most 1 GiB, or three maximum-size 20 GiB archives with
4 GiB of headroom. This bounds source snapshot and hashing work for one
untrusted manifest. Steward also uses each signed byte length as that entry's
inspection ceiling, so an understated archive is rejected before Steward copies
the larger source.

A separate 128 GiB cumulative limit bounds first-pass uncompressed tar payload
bytes across the whole issuance. Each archive receives the smaller of its
existing 40 GiB uncompressed limit and the budget still available. After a
valid archive is parsed, Steward subtracts its exact measured payload bytes
before inspecting the next archive. The limit permits three archives to reach
the individual 40 GiB maximum with 8 GiB of headroom; across 64 entries, it
allows an average of 2 GiB of uncompressed payload per archive. These limits
bound different work: 64 GiB bounds source snapshot and hashing input. The
128 GiB ceiling bounds accepted first-pass tar payload; because inspection uses
a fixed number of archive passes, it bounds total parser and decompression work
by a constant multiple. It does not promise that total bytes processed across
all passes stay below 128 GiB.

The command writes a new mode-`0600` file and refuses to overwrite an existing
path. It does not execute, import, or dynamically load any supplied content.

The signed catalog records `authority` as `descriptive-only`. Its output also
reports the catalog envelope digest. Retain that digest with the catalog ID and
revision in an operator-controlled change record.

## Transfer into an air-gapped environment

Transfer the signed catalog through approved media. Transfer the curator public
key through a separate authenticated path when practical.

If operators may later deploy an entry, also transfer the original signed
release, publisher public key, archive, skill manifest, and qualification
evidence. The catalog embeds the release and publisher identity for offline
discovery and verification, but it does not embed the archive, skill manifest,
or qualification-evidence bytes.

On the destination workstation, verify the catalog before using its metadata:

```console
stewardctl agent-catalog verify \
  -in approved-site-agents.revision-12.dsse.json \
  -public-key curator.public \
  -key-id site-agent-curator
```

The JSON result identifies the catalog, revision, issue time, fixed authority,
curator key, exact envelope and payload digests, and verified entry count.

## List and search releases

List every verified entry:

```console
stewardctl agent-catalog list \
  -in approved-site-agents.revision-12.dsse.json \
  -public-key curator.public \
  -key-id site-agent-curator
```

Filter by exact curator status:

```console
stewardctl agent-catalog list \
  -in approved-site-agents.revision-12.dsse.json \
  -public-key curator.public \
  -key-id site-agent-curator \
  -status approved
```

Search accepts one bounded, case-insensitive query. The exact reserved queries
`capability:state`, `capability:inference`, `capability:service`,
`capability:egress`, and `capability:connector` evaluate the verified capsule
booleans directly. Publisher-written outcome or limitation text cannot spoof
those filters. Every other query is a substring search across outcome text,
release, capsule, and publisher identities, exact command arguments, image and
platform, capsule validity, profile, resource ceilings, state and service
shapes, artifacts, qualification runtime, and limitations.

```console
stewardctl agent-catalog search \
  -in approved-site-agents.revision-12.dsse.json \
  -public-key curator.public \
  -key-id site-agent-curator \
  -query "capability:inference" \
  -status approved
```

Search is a local metadata filter. It does not rank releases, interpret natural
language, scan content for malware, or select a deployment.

## Inspect and compare exact metadata

Show one entry by exact ID:

```console
stewardctl agent-catalog show \
  -in approved-site-agents.revision-12.dsse.json \
  -public-key curator.public \
  -key-id site-agent-curator \
  -entry-id hermes-workspace-audit
```

The result includes:

- signed outcome title, summary, and observable outcome;
- exact release ID, capsule ID, and capsule command argument array;
- release, release-payload, capsule-envelope, and capsule-payload digests;
- capsule issue and expiry times;
- exact profile, image, platform, resource ceilings, capabilities, state and
  service shapes, and artifact digests;
- archive, skill-manifest, and qualification-evidence digest and size bindings;
- fixed canary metadata; and
- qualification completion time, runtime, evidence digest, and limitations.

Compare two entries:

```console
stewardctl agent-catalog compare \
  -in approved-site-agents.revision-12.dsse.json \
  -public-key curator.public \
  -key-id site-agent-curator \
  -left-entry-id hermes-workspace-audit \
  -right-entry-id hermes-workspace-audit-candidate
```

The result contains both verified entries and a deterministic field-by-field
difference list. Capsule commands are represented as JSON arrays in differences,
so embedded whitespace or control characters cannot blur argument boundaries.
Differences remain facts from signed metadata. Steward does not declare a
winner.

## Carry artifact approval into site policy

Catalog curation does not update admission policy. Before approving a release,
copy every exact capsule artifact `{kind, digest}` pair shown by
`agent-catalog show` into `allowed_artifacts` in both:

- the matching publisher rule; and
- every tenant rule that may admit the capsule.

The publisher rule must also include that entry's exact image manifest digest in
`allowed_manifest_digests`.

For example:

```json
"allowed_artifacts": [
  {
    "kind": "skill-manifest",
    "digest": "sha256:PASTE_64_LOWERCASE_HEX"
  }
]
```

Publisher artifact authority is checked before image import. Publisher and
tenant artifact authority are both checked before workload admission. A matching
kind with a different digest or an unlisted image is not authorized. Publisher
manifest and artifact allowlists form an intersection rather than per-image
tuples. If one publisher rule lists several of each, any listed image may declare
any listed artifact; use separate publisher keys and rules when that cross-product
is too broad. Steward does not scan the image or prove that the companion bytes
are embedded in it. Verify the separately transferred artifact through the signed
release before policy approval. Changing one byte in the skill manifest therefore
requires a new digest, signed release, catalog revision, and policy approval.

See [signed admission]({{ '/guides/signed-admission/' | relative_url }}) for the
complete policy procedure.

## Verify present deployability

When an operator selects an entry, verify the separately transferred release and
archive at the current time:

```console
stewardctl agent-release verify \
  -in inputs/hermes-workspace-audit.release.dsse.json \
  -public-key inputs/publisher.public \
  -key-id publisher-key-id \
  -archive inputs/hermes-agent-adapter.tar
```

Then apply the current signed site policy, instance intent, node checks, and
tenant task authority. An `approved` catalog entry can still be unusable because
its capsule expired, its publisher was revoked, site policy changed, required
artifacts are not allowed, the target platform differs, or qualification does
not cover the intended environment.

For the built-in Hermes canary workflow, continue with
[agent activation]({{ '/guides/agent-activation/' | relative_url }}).

## Manage revisions and rollback

Catalog revisions are immutable signed snapshots. Create a new output file for
each change, including status changes and publisher-key rotation.

Steward verifies one detached catalog at a time. It does not know the highest
revision an operator previously accepted and cannot detect catalog rollback by
itself. Retain the last accepted `catalog_id`, `revision`, and
`envelope_digest` outside the transfer media, then enforce these rules in the
promotion procedure:

- reject a revision lower than the retained value;
- investigate the same revision with a different envelope digest; and
- update the retained checkpoint only after review and acceptance.

Retain older catalogs when audit policy requires historical reconstruction.
Use signed site policy and publisher revocation, not a `retired` catalog label,
to remove deployment authority.

## Limits of the catalog

The catalog does not:

- download or install packages;
- authorize or import an image;
- grant capabilities or task authority;
- prove that qualification claims are truthful or complete;
- prove that signed skill content is benign;
- detect dormant or context-dependent malicious behavior;
- establish current deployability; or
- enforce revision monotonicity across detached files.

It provides a smaller guarantee: an independently verifiable curator selected
these exact publisher identities, releases, external file bindings, statuses,
and signed capsule facts at this catalog revision.
