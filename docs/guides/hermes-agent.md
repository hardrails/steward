---
title: Build and run the qualified Hermes Agent adapter
description: Build Steward's exact pinned Hermes Agent adapter, understand its proven gVisor runtime and signed workspace and connector skills, and rerun the qualification proof.
section: Agent compatibility
---

# Build and run the qualified Hermes Agent adapter

Steward includes a qualified adapter definition for Hermes Agent commit
[`095b9eed3801c251796df93f48a8f2a527ff6e70`](https://github.com/NousResearch/hermes-agent/commit/095b9eed3801c251796df93f48a8f2a527ff6e70).
The adapter builds Hermes from that exact source revision into a hardened image that
runs every process as UID/GID `65532:65532`. It does not use or modify the official
upstream image.

Qualification means this pinned source and Steward adapter passed the documented
runtime proof under gVisor on `linux/amd64`, including a signed workspace audit and
an authenticated connector effect through a signed custom skill. The state proof
also runs useful work before and after a container restart. Other platforms require
their own qualification run. The retained proof does not approve another Hermes
commit, a changed adapter, or arbitrary Hermes plugins, channels, skills, or Model
Context Protocol (MCP) servers.

Steward distributes the adapter definition and builder, not a prebuilt Hermes image.
The dependency and base-image notice inventory is incomplete, so Steward does not
redistribute an adapter OCI archive. Operators build and approve the exact image in
their own environment.

## Why the official image remains inadmissible

At the pinned revision, the official image starts as root through `/init`, uses
`s6-overlay` to change ownership and initialize configuration, declares
`VOLUME /opt/data`, and later drops to UID/GID `10000:10000`. Those choices
conflict with Steward's fixed non-root identity, read-only root filesystem,
`no-new-privileges`, and rejection of image-declared volumes.

The qualified adapter instead builds from reviewed source. Its small entrypoint
performs only fixed-path initialization as UID/GID `65532:65532`, verifies the
built-in signed skills, starts the upstream Hermes gateway, and exposes one bounded
service bridge. It does not add a root initialization phase or change Hermes core
source.

## Proven runtime contract

The `hermes-v1@v1` Steward profile fixes these values:

| Property | Enforced value |
| --- | --- |
| persistent state | `/opt/data` |
| `HOME` | `/opt/data/home` |
| working directory | `/opt/data` |
| process identity | UID/GID `65532:65532` |
| command | `serve` |
| service port | `8766` |
| writable filesystem | lineage volume plus a 64 MiB memory-backed `/tmp` (`tmpfs`) |

A lineage volume preserves one workload's state across approved replacements.
Docker's portable local volume driver has no hard byte or inode quota. Persistent
state therefore requires
`-allow-unquotaed-state-on-dedicated-host`, complete signed admission, and a policy
containing exactly one tenant. This is a dedicated-host compatibility mode, not a
shared-host storage-isolation claim.

On `linux/amd64`, the qualification suite ran the adapter with Docker's gVisor
`runsc` runtime, a read-only root filesystem, all Linux capabilities dropped,
`no-new-privileges`, fixed temporary storage, and no public network route. It
verified the complete process tree remained at UID/GID `65532:65532`, state writes
stayed under `/opt/data`, the immutable root rejected writes, and restart preserved
the generated configuration while the verified skill remained on the read-only
image filesystem.

## Useful work: signed workspace audit

The adapter includes the signed `steward.workspace-audit` skill. At startup, the
adapter verifies the skill manifest and file digests in the image's read-only
`/opt/steward/skills` directory. Hermes loads that directory through its
`skills.external_dirs` setting, and the model invokes the same immutable script
path. The agent's writable UID cannot unlink or replace the skill. The skill reads
only `/opt/data/workspace` and returns a canonical inventory containing each regular
file's path, size, and SHA-256 digest. This gives an operator a stable record for
reviewing workspace contents or detecting changes without sending the files
elsewhere.

The scan accepts at most 128 files, 128 directories, 16 directory levels, 256 KiB
per file, and 1 MiB in total. It rejects symbolic links, hard-linked files, special
files, paths longer than 512 bytes, and files that change during the scan. It never
uses the network.

Qualification submitted the audit through Hermes's native run API, verified the
returned workspace manifest digest, restarted the gVisor container with the same
state, and successfully ran the audit again. This proves that useful, bounded work
survives the tested restart path while the signed skill stays bound to the immutable
image. The deterministic qualification model exercises Hermes's native skill index
and tool loop; it does not predict how an arbitrary production model will choose
among skills or prove the safety of arbitrary workspace content.

## Useful work: signed connector operation

The adapter also includes the signed `steward.connector-work` skill. Hermes first
discovers it in the native external-skill index, calls
`skill_view`, receives the exact signed `SKILL.md`, and then follows its prescribed
terminal command. Qualification fails if the index entry is absent, the skill body
differs by one byte, the load is skipped, or an older turn's tool result is reused.
The bridge advertises this fixture separately in
`GET /steward/v1/negotiation`.

The skill sends one fixed JSON job to the logical
`http://steward-relay:8081/v1/connectors/local-work/operations/perform` path. It
is not configured with the upstream origin or its bearer credential. Gateway
checks the tenant-bound grant, exact operation, destination and DNS policy, task
replay fence, call budget, and tenant evidence quota; durably signs authorization
before the effect; injects the credential only on the upstream request; and signs
the terminal outcome. The fixture upstream returns a deterministic SHA-256 result,
so the proof verifies actual authenticated work rather than container readiness.

The same run proves that the spent task ID is denied on replay and that an
undeclared operation is denied. It then scans container metadata, the read-only
image layer, the state volume, `/tmp`, `/workspace` when present, and `/dev/shm`
for the qualification credential, configured origin authority, port, and credential
path. This is a regression test for the fixed fixture material, not a claim that
arbitrary upstream responses cannot disclose secrets. Gateway relays bounded
response bodies and non-Steward headers, so the configured upstream remains trusted
not to reflect authentication material or private origin details.

A separate Steward integration gate inspected and imported the archive through a
publisher-signed capsule and site policy, started Hermes through Executor, and sent
the audit and connector requests through Gateway's authenticated service path. It
verified one upstream effect, replay and forbidden-operation denial, and the signed
connector receipt chain. It changed the workspace after the first audit, destroyed
the container, admitted the next generation with resumed state, required a different
manifest from a fresh Hermes session, purged the lineage volume, and verified
Executor's signed receipt chain. This also exercises Docker 29's containerd image
store, where Docker addresses the image by its manifest digest while Steward still
verifies the signed config digest.

The repository publishes the metadata-only
[closed-runtime evidence]({{ '/reference/evidence/hermes-feasibility.json' | relative_url }})
and [signed-integration evidence]({{ '/reference/evidence/hermes-integration.json' | relative_url }})
for the qualified inputs. CI recomputes the adapter file-set, builder, Dockerfile,
source-input, and acceptance-harness digests and fails if they no longer match the
evidence. The files contain no prompt, response, workspace content, credential, or
log. They are release-bound records, not independently signed attestations.

## Build the adapter

Use a `linux/amd64` build host. Docker with the `runsc` runtime, Git, Python 3, and
the command-line tools checked by the builder must be available. Upstream build
hooks execute in a bounded gVisor container with read-only inputs, no Docker socket,
and `--network=none`. First, a networkless gVisor planner reads the verified
`uv.lock`. A non-executing host fetcher then downloads only the planned CPython 3.13
`linux/amd64` wheels from `files.pythonhosted.org`. It refuses redirects and proxies
and verifies each wheel's locked SHA-256 digest and byte size. The final image is also assembled with build
networking disabled. Source checkout and a missing digest-pinned base image can still
require host-side network access. Do not place secrets or production data on the
build host; use a disposable build machine because gVisor reduces build risk but does
not make untrusted code harmless. From a Steward source checkout, run the interactive
builder:

```console
scripts/build-hermes-adapter.sh --output hermes-agent-adapter.tar
```

For automation, disable prompts and provide the output path:

```console
scripts/build-hermes-adapter.sh \
  --non-interactive \
  --output hermes-agent-adapter.tar
```

An installed Linux release provides the same builder through a stable helper path:

```console
/usr/local/libexec/steward/build-hermes-adapter \
  --non-interactive \
  --output hermes-agent-adapter.tar
```

Without `--source-dir`, the builder fetches only the pinned Hermes commit into a
temporary directory. To use an exact checkout already transferred to the build host,
pass it explicitly:

```console
scripts/build-hermes-adapter.sh \
  --non-interactive \
  --source-dir /srv/sources/hermes-agent \
  --output hermes-agent-adapter.tar
```

`--source-dir` prevents a source download. The builder exports the pinned commit; it
does not copy mutable working-tree files or invoke repository-local Git hooks or
file-monitor commands. The digest-pinned base image and locked build dependencies
must still be present locally or reachable during the build. The resulting image
does not download code, skills, models, or configuration when it starts or handles
a task.

The builder reads committed Git objects rather than mutable working-tree files. It
refuses a source revision other than the exact pin, a missing committed adapter,
an unregistered `runsc`, insufficient free space, an unsafe gVisor build artifact,
or an oversized archive. It never overwrites output. If both output files already
form an exact pair bound to the current builder and current Steward commit or release,
it reports the completed publication; otherwise it refuses them. From an installed
release, it also verifies every adapter file against `release.json`. It creates two
new files:

- `hermes-agent-adapter.tar`, a Docker/OCI image archive; and
- `hermes-agent-adapter.tar.attestation.json`, canonical metadata that binds the
  source revision and tree, Steward adapter recipe, digest-pinned base image, output
  image identity, platform, archive digest, and archive size.

The metadata attestation contains no agent content or secrets. It is not a signature
and does not independently prove source provenance; authenticate the Steward release
or checkout and the source transfer through your own trust process.

## Rerun the end-to-end proof

Run qualification only on a disposable `linux/amd64` host with Docker, the `runsc`
gVisor runtime, Python 3, `curl`, `base64`, and standard GNU userland tools. The
harness uses fixed loopback ports, creates and removes Docker images, networks,
containers, and volumes, and starts temporary Steward services. Do not run it on a
production node or alongside another Steward deployment.

An installed Linux release includes the exact harness and automatically selects its
packaged binaries:

```console
sudo env \
  STEWARD_ACCEPT_DISPOSABLE_HOST_RISK=YES \
  HERMES_ARCHIVE="$PWD/hermes-agent-adapter.tar" \
  HERMES_INTEGRATION_EVIDENCE_OUT="$PWD/hermes-integration.json" \
  /usr/local/libexec/steward/hermes-steward-acceptance
```

From a source checkout, use `scripts/hermes-steward-acceptance.sh`; it builds the
four required Steward binaries when explicit `EXECUTOR_BIN`, `GATEWAY_BIN`,
`RELAY_BIN`, and `STEWARDCTL_BIN` paths are not supplied. The evidence destination
must not already exist. A successful run writes owner-only, metadata-only evidence
that binds the archive, build attestation, harness, binaries, accepted image,
completed hostile-path checks, and verified receipt-chain heads. It does not retain
prompts, model output, workspace contents, credentials, origins, or logs.

## Inspect and import the exact output

Inspect the archive without changing Docker:

```console
chmod go-w hermes-agent-adapter.tar
stewardctl image inspect -archive hermes-agent-adapter.tar
```

Compare the reported manifest digest, config digest, and platform with the generated
attestation and your build record. Select the approved repository provenance through
your trusted build or promotion process; an OCI archive may not contain a repository
name. Sign those exact values and the `hermes-v1@v1` profile into a capsule using
your established Steward key workflow. After site policy authorizes its publisher
and repository, import the same archive:

```console
sudo stewardctl image import \
  -archive hermes-agent-adapter.tar \
  -capsule hermes-capsule.dsse.json \
  -policy site-policy.dsse.json \
  -site-root-public-key site-root.public \
  -site-root-key-id site-root-1
```

Import success proves the archive's identity and static image contract. It does not
repeat the runtime qualification or approve a different command, model alias,
service grant, or egress route. See
[image and evidence tools]({{ '/reference/offline-tools/' | relative_url }}) and
[signed admission]({{ '/guides/signed-admission/' | relative_url }}).

## Inference and service behavior

The adapter accepts only this inference base URL:
`http://steward-relay:8080/v1`. Gateway does not configure, mount, or inject the
real upstream credential into the workload and enforces the model alias granted by
signed policy. The configured inference provider remains trusted not to reflect
that credential in a response. The adapter uses the fixed non-secret
`steward-local` placeholder as its local API key. It cannot select an arbitrary
inference endpoint.

Port `8766` is intended only for a Steward authenticated service grant. The bridge
exposes this fixed allowlist:

- `GET /steward/v1/negotiation`
- `GET /health`
- `POST /v1/runs`
- `GET /v1/runs/{run_id}`, where the ID is `run_` plus 32 lowercase hexadecimal
  characters

Run event streams are not exposed. The bridge requires `Content-Length` for a run
submission, limits request bodies to 64 KiB and responses to 1 MiB, applies a
30-second I/O timeout, and uses one worker with a connection queue of eight. It
replaces the caller's authorization with a fixed container-internal token and does
not forward cookies. Do not expose port `8766` directly to a public or tenant-facing
network; Steward's service grant supplies host authentication but not application
authorization for end users.

The adapter receives no raw Internet route, Docker socket, host mount, privileged
mode, caller-selected credential, or undeclared port. Additional Hermes channels,
plugins, skills, MCP servers, or egress destinations require their own bounded design
and qualification; the current proof does not authorize them.
