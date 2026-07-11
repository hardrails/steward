---
title: OpenClaw on Steward
description: Safely evaluate a digest-pinned OpenClaw image under Steward Executor v0.1 and understand the storage, secret, network, and port grants full operation needs.
section: Agent compatibility
---

# OpenClaw on Steward

<div class="callout warning">
  <strong>Compatibility status: lifecycle validation only</strong>
  Steward v0.1 can admit and start an OpenClaw image under its hardened sandbox.
  It cannot yet provide OpenClaw's persistent configuration/workspace, credentials,
  outbound connections, or gateway ports.
</div>

[OpenClaw](https://github.com/openclaw/openclaw) is an independent personal agent
runtime. Its official Docker deployment persists configuration and workspace data,
injects authentication material, connects to model and messaging services, and
publishes gateway ports. Steward v0.1 denies each of those capabilities by default.

## Validate the image boundary

Choose an approved immutable upstream release rather than a floating `latest` tag:

```console
OPENCLAW_TAG=<approved-version>
docker pull "ghcr.io/openclaw/openclaw:$OPENCLAW_TAG"
OPENCLAW_IMAGE=$(docker image inspect --format '{% raw %}{{index .RepoDigests 0}}{% endraw %}' \
  "ghcr.io/openclaw/openclaw:$OPENCLAW_TAG")
printf '%s\n' "$OPENCLAW_IMAGE"
```

Test an offline CLI operation under the same hardening Executor applies. OpenClaw's
entrypoint has changed across releases, so verify the command in the documentation
for the exact image you pinned:

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
  "$OPENCLAW_IMAGE" node dist/index.js --help
```

Then follow [Operate an Executor workload]({{ '/guides/workload-lifecycle/' | relative_url }})
with:

- `profile_id`: `openclaw-compat-v1`
- `image`: the value of `$OPENCLAW_IMAGE`
- `command`: `['node', 'dist/index.js', '--help']`, adjusted to the pinned image

This proves only that the selected command executes inside the v0.1 sandbox. It does
not establish functional model access, channel connectivity, browser control,
workspace persistence, or gateway reachability.

## What full operation requires

OpenClaw's normal container setup needs capabilities intentionally missing from the
v0.1 workload schema:

1. tenant-scoped persistent configuration and workspace claims;
2. node-resolved secrets that never appear in a fleet command payload;
3. constrained egress to approved model and channel endpoints; and
4. explicit, authenticated gateway publication when remote clients are required.

Until Steward implements those narrow grants, use OpenClaw's
[official Docker guide](https://github.com/openclaw/openclaw/blob/main/docs/install/docker.md)
outside Steward for functional evaluation. Do not mount the Docker socket, add broad
host volumes, disable gVisor, or enable unrestricted container networking as a
workaround.
