---
title: Hermes Agent adapter contract
description: Understand the built-in Hermes layout, why the upstream image is not directly admissible, and how to qualify a hardened adapter without bypassing upstream initialization.
section: Agent compatibility
---

# Hermes Agent adapter contract

The compiled-in `hermes-v1@v1` **layout contract** fixes paths and identity settings
that an untrusted capsule cannot change. Steward does not include Hermes Agent,
build its image, or certify the upstream image.

| Property | Enforced value |
| --- | --- |
| persistent state | `/opt/data` |
| `HOME` | `/opt/data/home` |
| working directory | `/opt/data` |
| process identity | UID/GID `65532:65532` |
| writable filesystem | lineage volume plus a 64 MiB memory-backed `/tmp` (`tmpfs`) |

A lineage volume preserves one workload's state across approved replacements.
Steward's portable Docker volume has no hard byte or inode quota, so this layout is
usable only with the explicit dedicated-host state mode. It is not a shared-host
state guarantee.

Hermes Agent is a separate project. The status below was reviewed on 2026-07-11 at
upstream commit
[`095b9eed3801c251796df93f48a8f2a527ff6e70`](https://github.com/NousResearch/hermes-agent/commit/095b9eed3801c251796df93f48a8f2a527ff6e70),
using its pinned
[Docker guide](https://github.com/NousResearch/hermes-agent/blob/095b9eed3801c251796df93f48a8f2a527ff6e70/website/docs/user-guide/docker.md),
[Dockerfile](https://github.com/NousResearch/hermes-agent/blob/095b9eed3801c251796df93f48a8f2a527ff6e70/Dockerfile),
and [Compose contract](https://github.com/NousResearch/hermes-agent/blob/095b9eed3801c251796df93f48a8f2a527ff6e70/docker-compose.yml).
Review the exact source revision you plan to package; a later upstream change can
invalidate this assessment.

## Current validation status

The official Hermes image is **not directly admissible**. Steward does not ship or
claim a validated Hermes adapter.

The upstream container starts as root through `/init`. `s6-overlay`, its container
init and service supervisor, then fixes ownership and configuration before services
drop to the `hermes` user at default UID/GID `10000:10000`. The image declares
`VOLUME /opt/data`. Upstream warns that bypassing `/init` skips required setup and
breaks the gateway.

Those requirements conflict with Steward's closed runtime:

- Executor starts workloads as `65532:65532`, with a read-only root, no capabilities,
  and `no-new-privileges`;
- policy-bound import rejects any image config that declares a writable volume,
  because Docker could create storage outside the lineage contract; and
- a child Dockerfile has no instruction that clears an inherited `VOLUME`
  declaration from the final image config.

Changing only `USER` and replacing `/init` bypasses upstream initialization while
retaining the disallowed volume. Do not use such a derivative.

## Adapter acceptance contract

A Hermes adapter is suitable for a signed capsule only after a trusted image
pipeline and the target Steward node pass every requirement below:

1. Pin the source revision and every base image by digest. Record source, inputs,
   output manifest and config digests, and platform.
2. Build from reviewed source into a final Open Container Initiative (OCI) config
   with no declared volumes. Do not expect `FROM` the official image to remove its
   inherited volume.
3. Preserve `/init` and `s6-overlay` responsibilities: ownership checks, configuration
   seeding, profile reconciliation, supervision, signal handling, and privilege
   drop. Review and test any replacement as an upstream fork; a direct executable
   entrypoint is not equivalent.
4. Prove the complete process tree starts and remains at UID/GID `65532:65532`
   without a root initialization phase, `setuid`, `chown`, capabilities, or a
   writable image root.
5. Prove every write lands under `/opt/data` or `/tmp`. Package executables,
   Python/Node dependencies, skills, and certificates in the immutable image;
   startup cannot download or install code.
6. Configure the main and auxiliary model paths to use the injected
   `OPENAI_BASE_URL`, `OPENAI_API_KEY`, and `OPENAI_MODEL` values.
   `OPENAI_API_KEY` is the fixed, non-secret placeholder `steward-local`; Gateway
   removes the agent's `Authorization` header and injects the operator-owned
   upstream credential, if configured. Verify that Hermes cannot select a model
   other than the signed alias.
7. Keep bot tokens, API keys, and other credentials out of the Dockerfile, archive,
   capsule, command arguments, and logs. Steward has no generic secret-injection
   channel. A mode needing another credential requires an operator-approved design.
8. Sign the exact, tested argument vector. Exercise retain/resume state,
   restart, stop, destroy, reconciliation after Executor restart, and the
   negative cases for unapproved egress, mounts, users, and image drift.

This checklist is a release gate. It is not evidence that a compliant adapter
already exists.

## Inspect and import an adapter immutably

After the trusted pipeline builds the adapter archive, inspect it without changing
Docker:

```console
chmod go-w hermes-adapter.tar
stewardctl image inspect -archive hermes-adapter.tar
```

Take the manifest digest, config digest, and platform from `image inspect`. Select
the approved repository provenance separately from the trusted build or promotion
pipeline; an OCI archive may not contain a repository name. Sign those values and
the `hermes-v1@v1` profile into a capsule. After site policy authorizes its
publisher and repository, import the same archive:

```console
sudo stewardctl image import \
  -archive hermes-adapter.tar \
  -capsule hermes-capsule.dsse.json \
  -policy site-policy.dsse.json \
  -site-root-public-key site-root.public \
  -site-root-key-id site-root-1
```

The official Hermes archive at the reviewed revision should fail because it declares
a volume.
Import success proves only the archive's identity and static image contract. It
does not replace the runtime acceptance tests above. See
[image and evidence tools]({{ '/reference/offline-tools/' | relative_url }}) and
[signed admission]({{ '/guides/signed-admission/' | relative_url }}).

## Deliberate capability limits

An accepted Hermes skill can reach only explicitly signed HTTP(S) destinations,
and only when its libraries honor standard proxy variables. Raw TCP/UDP, browser
sandboxes, host projects, Docker, undeclared messaging transports, extra mounts,
and arbitrary credentials remain unavailable. Do not enable unrestricted container
networking or bypass the upstream init contract to make an integration appear to
work.
