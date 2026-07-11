---
title: Hermes Agent on Steward
description: Safely evaluate a digest-pinned NousResearch Hermes Agent image under Steward Executor v0.1 and understand what is required for full connected operation.
section: Agent compatibility
---

# Hermes Agent on Steward

<div class="callout warning">
  <strong>Compatibility status: lifecycle validation only</strong>
  Steward v0.1 can admit and start a Hermes Agent image under its hardened sandbox.
  It cannot yet provide the network, secrets, persistent <code>/opt/data</code>, or
  gateway ports required for a useful connected Hermes deployment.
</div>

[Hermes Agent](https://github.com/NousResearch/hermes-agent) is an independent agent
runtime. Its official Docker workflow stores configuration, credentials, memories,
skills, and sessions under `/opt/data`, and connected use requires model and tool
network access. Steward v0.1 deliberately supplies neither persistent host storage
nor network access.

## Validate the image boundary

Run this on a Steward Linux node with Docker and `runsc`. Select and record an
explicit upstream version; do not automate against a floating tag in production.

```console
HERMES_TAG=<approved-version>
docker pull "nousresearch/hermes-agent:$HERMES_TAG"
HERMES_IMAGE=$(docker image inspect --format '{% raw %}{{index .RepoDigests 0}}{% endraw %}' \
  "nousresearch/hermes-agent:$HERMES_TAG")
printf '%s\n' "$HERMES_IMAGE"
```

First test the image directly under the same non-negotiable container controls used
by Executor. Adapt the final command if the pinned upstream release changes its CLI:

```console
docker run --rm \
  --runtime runsc \
  --network none \
  --read-only \
  --user 65532:65532 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /workspace:rw,nosuid,nodev,size=67108864 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=67108864 \
  --workdir /workspace \
  "$HERMES_IMAGE" hermes --help
```

Then follow [Operate an Executor workload]({{ '/guides/workload-lifecycle/' | relative_url }})
with:

- `profile_id`: `hermes-compat-v1`
- `image`: the value of `$HERMES_IMAGE`
- `command`: `['hermes', '--help']`, adjusted only to the pinned image's documented CLI

A successful test proves the image can enter the v0.1 sandbox and execute the chosen
offline command. It does **not** prove a gateway, messaging integration, browser
tool, model call, or persistent memory works.

## Why the normal Hermes setup does not fit v0.1

The upstream setup command mounts a durable host directory at `/opt/data` and writes
secrets and configuration there. The gateway also needs outbound connections and
normally exposes a service port. Executor's public v0.1 contract has no field for
any of those capabilities, so a control plane cannot smuggle them through.

Full Hermes operation belongs behind future, auditable grants:

1. tenant-scoped durable volume claims;
2. opaque secret references resolved only on the node;
3. destination-constrained egress through a tenant-aware proxy; and
4. explicit service/port publication with authenticated ingress.

Until those contracts exist, use Hermes' [official Docker guide](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/docker.md)
outside Steward for functional evaluation. Treat that as a different security
boundary; do not weaken Executor or expose the Docker socket to bridge the gap.
