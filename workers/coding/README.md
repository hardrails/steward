# Coding worker

This optional container lets Hermes request bounded work from the official Codex
or Claude Code CLI. It is a separate trust boundary with its own repository
worktree and authentication state. Neither is mounted into Hermes.

The image pins both CLI packages in `package-lock.json`. Choose one engine per
running container with `STEWARD_CODING_ENGINE=codex` or
`STEWARD_CODING_ENGINE=claude-code`. The worker accepts one exact `/v1/run`
operation, never invokes a shell to construct the CLI command, requires a clean
Git worktree by default, and never commits or pushes changes.

## Authentication choices

API keys are the higher-assurance option because an operator can place the key
behind a dedicated inference proxy and tightly restrict worker egress. A user may
instead sign in through the official CLI and mount its dedicated credential
volume. Steward does not implement, proxy, or collect that login.

For Codex, create a dedicated bind directory owned by the worker, then use the
official device login from an interactive one-off container. A new Docker named
volume is root-owned by default and is not writable by UID `65532`.

```console
sudo install -d -o 65532 -g 65532 -m 0700 /var/lib/steward-coding/codex-auth
docker run --rm -it --user 65532:65532 \
  --mount type=bind,src=/var/lib/steward-coding/codex-auth,dst=/home/worker/.codex \
  --entrypoint /opt/worker/node_modules/.bin/codex steward-coding-worker login --device-auth
```

For Claude Code, run its official `setup-token` or login workflow in a one-off
container with a dedicated `/home/worker/.claude` volume. This is for the
operator's own first-party CLI use. Steward must not offer Claude subscription
login as a managed service or route another user's subscription credential.

Subscription credentials necessarily exist inside the coding-worker trust
boundary because the official CLI needs them. They still do not enter Hermes.
Use a dedicated account where appropriate, restrict the container's network to
the provider and required source systems, and treat subscription mode as opt-in.
The worker blocks exact credential material and common encodings from its result,
but output scanning is not a substitute for network isolation.

## Build and run

```console
docker build --pull=false -t steward-coding-worker .
docker run --rm --read-only --runtime runsc --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 256 --memory 2g --cpus 2 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m \
  -p 127.0.0.1:9081:8080 \
  -e STEWARD_CODING_ENGINE=codex \
  -e STEWARD_WORKER_TOKEN_FILE=/run/secrets/worker-token \
  --mount type=bind,src="$PWD/repository",dst=/workspace \
  --mount type=bind,src=/var/lib/steward-coding/codex-auth,dst=/home/worker/.codex \
  --mount type=bind,src="$PWD/worker-token",dst=/run/secrets/worker-token,readonly \
  steward-coding-worker
```

Use a disposable Git worktree rather than a developer's only checkout. `read`
mode selects Codex's read-only sandbox or Claude Code's plan mode. `write` mode
selects workspace-write or accept-edits mode and returns the resulting changed
paths. Review the actual diff before accepting it.
