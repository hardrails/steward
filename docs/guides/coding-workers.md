---
title: Let Hermes use Codex or Claude Code
description: Delegate a bounded repository task from Hermes to an isolated official coding CLI without mounting its credentials into Hermes.
section: How-to guide
---

# Let Hermes use Codex or Claude Code

Hermes can ask Codex or Claude Code to inspect or change a repository through
Steward's developer profile. The coding CLI runs in a separate container with a
dedicated Git worktree and authentication store. It does not run in the Hermes
process or share Hermes state.

That boundary is deliberate. Coding agents need broader filesystem and provider
access than a general assistant. A separate worker makes that authority visible,
replaceable, and independently isolatable.

## API keys and subscriptions are different

Hermes's own model calls use an API key behind Steward Gateway. A ChatGPT or
Claude consumer subscription is not a general API key and cannot be used as the
Hermes inference route.

The official Codex and Claude Code CLIs can support their own first-party login
flows. Steward does not collect, proxy, or automate that login. Run it yourself
inside the coding worker's dedicated credential volume. Subscription mode is
opt-in and lower assurance because a reusable account credential must exist in
the worker. Never mount that credential store into Hermes.

For unattended production work, a scoped API key behind a dedicated egress proxy
is easier to rotate, audit, and restrict. For personal first-party CLI use, follow
the provider's current terms and authentication documentation. Steward does not
offer another user's Claude subscription as a managed service.

## 1. Build one worker image

The worker image pins the official packages in `package-lock.json`. A running
container selects exactly one engine.

```console
docker build --pull=false -t steward-coding-worker workers/coding
```

Create a disposable worktree instead of mounting your only checkout:

```console
git -C /srv/projects/application worktree add /srv/steward-worktrees/application HEAD
```

The worker requires a clean Git worktree by default. It never commits or pushes.
Read mode maps to Codex's read-only sandbox or Claude Code's plan mode. Write mode
maps to workspace-write or accept-edits and returns changed paths; review the real
diff before accepting it.

## 2. Authenticate the selected CLI

Use a dedicated bind directory owned by the worker identity:

```console
sudo install -d -o 65532 -g 65532 -m 0700 /var/lib/steward-coding/codex-auth
sudo install -d -o 65532 -g 65532 -m 0700 /var/lib/steward-coding/claude-auth
```

For Codex subscription login, run the official device flow in a one-off container:

```console
sudo docker run --rm -it --user 65532:65532 \
  --mount type=bind,src=/var/lib/steward-coding/codex-auth,dst=/home/worker/.codex \
  --entrypoint /opt/worker/node_modules/.bin/codex \
  steward-coding-worker login --device-auth
```

For Claude Code, use its official login or `setup-token` flow in the same pattern,
mounting `/var/lib/steward-coding/claude-auth` at `/home/worker/.claude` and using
`/usr/local/bin/claude` as the entrypoint. Authentication behavior can change in
the upstream CLI; verify the pinned package's provider documentation before use.

With API-key mode, inject `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` into the coding
worker through your secret manager. Do not put it in the agent definition, Gateway
configuration, shell history, or Hermes state.

## 3. Run the isolated worker

Create a random token shared only by this worker and Gateway, using separate
owner-correct files as in the [research guide]({{ '/guides/research-agents/' |
relative_url }}). Then run one engine. This example uses Codex:

```console
sudo docker run -d --name steward-codex-worker --restart unless-stopped \
  --read-only --runtime runsc --user 65532:65532 --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 256 --memory 2g --cpus 2 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m \
  -p 127.0.0.1:9081:8080 \
  -e STEWARD_CODING_ENGINE=codex \
  -e STEWARD_WORKER_TOKEN_FILE=/run/secrets/worker-token \
  --mount type=bind,src=/srv/steward-worktrees/application,dst=/workspace \
  --mount type=bind,src=/var/lib/steward-coding/codex-auth,dst=/home/worker/.codex \
  --mount type=bind,src=/etc/steward/coding-worker/token,dst=/run/secrets/worker-token,readonly \
  steward-coding-worker
```

Restrict this container's network to the selected provider and required source
systems. The worker scans results for exact credential material and common
encodings, but output filtering cannot replace network isolation.

## 4. Connect Gateway and deploy the developer profile

```console
sudo stewardctl gateway connector set \
  -preset codex-worker \
  -base-url http://127.0.0.1:9081 \
  -credential-file /etc/steward/credentials/codex-worker \
  -allow-insecure-http \
  -allow-cidr 127.0.0.0/8 \
  -tenant-budget development=8388608
sudo systemctl restart steward-gateway
```

Use `-preset claude-code-worker`, connector ID `steward-claude-code`, and a
separately running worker for Claude Code. Start from
[`examples/agents/developer/agent.json`](https://github.com/hardrails/steward/blob/main/examples/agents/developer/agent.json),
then follow [Build and run an agent]({{ '/guides/build-agents/' | relative_url }}).
The developer profile requires the signed coding-worker skill and at least one of
the two connector IDs.

Ask Hermes for read-only work first:

```console
stewardctl task run developer \
  "Ask Codex to inspect the repository, explain the failing test, and propose a fix. Do not edit files."
```

Write mode is appropriate only when the user requested changes and the worker's
worktree is disposable. Steward returns the worker's summary and changed paths;
it does not declare the patch correct, merge it, or bypass repository review.

