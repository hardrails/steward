---
title: Release artifacts and verification
description: Steward release filenames, target matrix, package contents, version identity, checksum verification, and first-install selection rules.
section: Reference
---

# Release artifacts and verification

Each GitHub release contains static archives, native Linux node packages, the guided
installer, and a SHA-256 manifest.

## File matrix

| Filename pattern | Contents |
| --- | --- |
| `steward_<version>_linux_amd64.tar.gz` | Seven binaries plus universal node appliance |
| `steward_<version>_linux_arm64.tar.gz` | Seven binaries plus universal node appliance |
| `steward-control_<version>_linux_amd64.tar.gz` | Controller binary, hardened systemd unit, configuration template, doctor, and license |
| `steward-control_<version>_linux_arm64.tar.gz` | Controller binary, hardened systemd unit, configuration template, doctor, and license |
| `steward-node_<version>_amd64.deb` | Debian-family node package |
| `steward-node_<version>_arm64.deb` | Debian-family node package |
| `steward-node_<version>_amd64.rpm` | RPM-family node package (`x86_64` metadata) |
| `steward-node_<version>_arm64.rpm` | RPM-family node package (`aarch64` metadata) |
| `steward_<version>_darwin_amd64.tar.gz` | macOS development supervisor, controller, CLI, and MCP adapter |
| `steward_<version>_darwin_arm64.tar.gz` | macOS development supervisor, controller, CLI, and MCP adapter |
| `steward-buzz_<version>_<os>_<arch>.tar.gz` | Optional Buzz integration recipe, target-native bridge and CLI, exact source lock, reviewed patch, and service/configuration examples |
| `install-steward.sh` | Interactive and unattended top-level installer |
| `install-control.sh` | Interactive and unattended controller installer for systemd Linux |
| `install-macos.sh` | Native macOS operator and development installer |
| `steward-support_<version>.json` | Supported platforms, runtime, isolation requirements, compatibility boundary, and known limits emitted by the stamped binary |
| `checksums.txt` | SHA-256 values for every other release asset |

Linux archives and packages include hardened systemd units, configuration templates,
enrollment, preflight, and node-doctor helpers, and whole-release activation and
removal tools.
The node archives and packages contain the `steward-control` binary for tooling and
version parity, but they do not contain or install its service unit, configuration,
doctor, or installer. Those deployment assets exist only in the dedicated
controller archive and `install-control.sh` path.
They also include the exact-pinned Hermes Agent adapter definition, builder, signed
workspace-audit and connector-work skills, and qualification test harness. They do
not include a built Hermes image.
macOS archives contain `steward`, `steward-control`, `stewardctl`, `steward-mcp`,
the license, and README. `steward-control` is a development binary there; the
service installer supports systemd Linux only.

## Hermes adapter build outputs

Steward does not publish a prebuilt Hermes OCI archive. Dependency and base-image
notices are incomplete, so redistribution remains blocked even though the pinned
adapter has passed its runtime qualification.

On an installed Linux node, the packaged interactive builder is:

```console
/usr/local/libexec/steward/build-hermes-adapter \
  --output hermes-agent-adapter.tar
```

For unattended operation, add `--non-interactive`. Without `--source-dir`, the
builder downloads only Hermes commit
`3ef6bbd201263d354fd83ec55b3c306ded2eb72a` into a temporary directory. An operator
can instead transfer an exact clean checkout and pass
`--source-dir /path/to/hermes-agent`; that prevents the source download. The
digest-pinned base image and locked build dependencies must still be present locally
or reachable during the build.

The builder publishes the requested image archive and a sibling file named
`<archive>.attestation.json`. The canonical metadata records the pinned source,
adapter and builder identities, digest-pinned base image, output manifest and config
digests, platform, archive digest, and size. It contains no agent content or secrets.
It is metadata, not a signature or independent proof of provenance. Authenticate the
Steward release and source transfer, then inspect and sign the exact archive through
the documented admission workflow.

The Linux payload also exposes the packaged end-to-end harness at
`/usr/local/libexec/steward/hermes-steward-acceptance`. It requires Docker, the
`runsc` gVisor runtime, Python 3, `curl`, `base64`, and standard GNU userland tools.

Run it only on a disposable `linux/amd64` host with no production Steward services:
it uses fixed ports and creates and removes Docker resources.

```console
sudo env \
  STEWARD_ACCEPT_DISPOSABLE_HOST_RISK=YES \
  HERMES_ARCHIVE="$PWD/hermes-agent-adapter.tar" \
  /usr/local/libexec/steward/hermes-steward-acceptance
```

Set `HERMES_INTEGRATION_EVIDENCE_OUT` to a new path when an owner-only,
metadata-only qualification record is required. The detailed
[Hermes guide]({{ '/guides/hermes-agent/' | relative_url }}) explains the
qualification evidence and its limits.

## Buzz bridge build output

Steward does not redistribute a mutable or independently versioned Buzz binary.
Each Linux and macOS release includes a small target-native Buzz kit. Its
`./build-buzz --output <new-directory>` command builds one local bundle containing
the exact pinned and locally verified Buzz CLI,
`steward-buzz-bridge`, `stewardctl`, both licenses, the immutable source lock, and
the service/configuration examples. The build fails if the Buzz tag, commit, tree,
source inputs, Rust toolchain, Steward patch, or bridge inputs differ from the
reviewed lock.

The scheduled `buzz-pin.yml` workflow proposes stable upstream source updates as
pull requests. It waits through an observation window and never auto-merges. CI
then rebuilds the complete patched CLI from that exact source. See the [Buzz
integration guide]({{ '/guides/buzz/' | relative_url }}) for online and air-gapped
builds. The kit includes target-native Steward binaries, so building Buzz does not
require Go. It does require the source-locked Rust toolchain and either network
access to the exact source and locked Cargo dependencies or an operator mirror.

## Verify a downloaded release

```console
RELEASE_TAG="<release-tag>"
gh release download "$RELEASE_TAG" --repo hardrails/steward --dir "steward-$RELEASE_TAG"
cd "steward-$RELEASE_TAG"
sha256sum -c checksums.txt
```

On stock macOS, use `shasum -a 256 -c checksums.txt` instead of `sha256sum`.

After checksum verification, compare the published support contract with the
installed CLI:

```console
stewardctl support matrix -output json > installed-support.json
cmp installed-support.json steward-support_<version>.json
```

The release workflow performs the same byte comparison before publication. See
the [installed support contract]({{ '/reference/support-contract/' | relative_url }}).

A checksum proves only that files match the downloaded manifest. For high-assurance
imports, authenticate the manifest with a trusted signature or verify it as part of
an independently authenticated release bundle.

## Version identity

Published binaries are linker-stamped. For each Linux target, the release build
executes every host-native binary and requires each to report the exact tag.
Verify after installation:

```console
steward -version
steward-control -version
steward-executor -version
stewardctl -version
steward-gateway -version
steward-relay -version
steward-storage-zfs -version
steward-mcp -version
```

Every node-payload binary must match the active
`/opt/steward/releases/<version>` directory. A controller installed through the
dedicated path must match `/opt/steward-control/releases/<version>`. Release tags
use `vX.Y.Z` semantic versioning, with optional prerelease suffixes and no build
metadata.

Linux releases also contain `release.json`. Its canonical file map binds every
binary and host-integration asset by SHA-256. Its `state_formats` map declares the
minimum and maximum durable format each release reads and the format it writes for
Gateway state, Gateway connector receipts, admission fences, the operation journal,
Executor evidence, the Executor lifecycle uplink fence, the separate durable
delivery ledger, and supervisor state. Activation uses these ranges to reject an
unsafe upgrade or rollback before changing the active-release symlink or relay
binding.

Current manifests declare `admission_fence` readers 1 through 4 and writer 4.
Format 1 stores policy and instance-generation high-water records. Format 2 adds
the committed route-policy digest. Format 3 adds the durable node maintenance
cordon. Entering or exiting maintenance rewrites the atomic snapshot as format 3;
a release limited to format 1 or 2 is then ineligible even after the cordon exits.

Current manifests declare `connector_receipt_log` with `read_min: 1`, `read_max: 7`,
and `write: 7`. Ordinary connector records retain schema 1. Action-permit records use
schema 2 and add the action-authority key ID, exact permit digest, and exact request
digest. Schema 3 is the historical two-record service-task format. Current lifecycle
tasks use schema 4, which adds task-local sequence and hash links across
authorization, dispatch, and terminal records. Authorized connector events use
schema 5, which adds explicit effect mode and exact operation-policy digest. A
stable pre-effect denial marker binds the first observed attacker-selectable request
digest but claims no verified permit or authority key and does not enumerate later
denials. Schema 6 records a multi-party authorized call's canonical signer set and
signed approval threshold. Schema 7 binds a context-locked call's response-history
head and terminal response digest. All seven schemas may appear in one signed chain. Format inspection
requires reader 2 whenever action authorities are configured, reader 4 whenever
service-task operations are configured, reader 5 after the first authorized
denial, authorization, or terminal record. Before that event, action-authority
configuration makes the prospective connector-receipt requirement format 2. A
multi-party authorization or terminal record requires reader 6. A context-required
grant requires reader 7.

Current manifests also declare `gateway_state` readers 1 through 8 and writer 8.
Gateway state format 4 retains service identity and tenant task authorities for
task-authorized grants. Format 5 additionally retains authorized mode and the
signed-policy-derived connector/action-key scopes, so a retained authorized grant
requires Gateway state format 5 before its first connector event. Format 6 binds a
multi-party approval threshold into the retained grant. Format 7 retains the
context-lock requirement. A release whose
reader or writer stops at an observed or configuration-required format is not a
safe rollback target.

Current manifests declare `evidence_log` readers 1 through 2 and writer 2. Evidence
format 1 contains the original closed Executor event vocabulary. Format 2 adds
`activation_begin` and `activation_checkpoint`. Both formats can coexist in one
signed chain, and inspection reports the highest version present. Executor fsyncs
the format 2 begin marker after read-only admission preflights and before the
admission-allow receipt, mutation journal, or host mutation. An older reader is
therefore rejected before rollback even if the workload was later destroyed.

Current manifests declare `uplink_delivery_state` readers 2 through 4 and writer 4.
Format 3 adds the wire protocol, claim generation, and protocol 4 projections.
Format 4 also retains the verified command kind. That binding lets Executor
compact acknowledged `activation_canary_failed` and
`activation_canary_cancelled` outcomes without treating another command's failure
as a canary result. A migrated format-3 failure has no retained command kind and
therefore remains noncompactable. Upgrade inspection reads formats 2 and 3 without
changing them. Normal Executor startup atomically rewrites either format as format
4 before polling. A release whose reader stops at format 2 or 3 is not a safe
rollback target after that startup, even when the ledger is empty. There is no
supported downgrade or single-file restore procedure.

See [platform support]({{ '/reference/platform-support/' | relative_url }}) and
[air-gapped installation]({{ '/guides/air-gapped/' | relative_url }}).
