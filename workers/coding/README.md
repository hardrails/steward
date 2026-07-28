# Coding worker

This optional container lets Hermes request bounded work from the official Codex
or Claude Code CLI. It is a separate trust boundary with its own repository
clone and authentication state. Neither is mounted into Hermes. The supported
service runtime is Linux because immutable handoffs require Linux child-process
containment before capture.

The image pins both CLI packages in `package-lock.json`. Choose one engine per
running container with `STEWARD_CODING_ENGINE=codex` or
`STEWARD_CODING_ENGINE=claude-code`. The worker accepts one exact `/v1/run`
operation, never invokes a shell to construct the CLI command, requires a clean
Git checkout by default, and does not itself invoke commit or push operations.
Operators must still make Git metadata read-only, remove repository remotes and
credentials, and restrict egress; the final `HEAD` check cannot prove an engine
never committed and reset or attempted a push.

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

Prepare a standalone clone with a contained `.git` directory. Do not use
`git worktree add`: its `.git` file points to metadata outside the mounted path.
Use `git clone --no-local` for a local source, detach the exact approved commit,
remove `origin`, make the clone owned by UID/GID `65532:65532`, and confirm it is
clean.

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
  --mount type=bind,src="$PWD/repository/.git",dst=/workspace/.git,readonly \
  --mount type=bind,src=/var/lib/steward-coding/codex-auth,dst=/home/worker/.codex \
  --mount type=bind,src="$PWD/worker-token",dst=/run/secrets/worker-token,readonly \
  steward-coding-worker
```

The parent workspace mount remains writable while the nested Git metadata mount
is read-only. Restrict network access to the selected provider and deny Git
hosting and private infrastructure destinations.

## Request contracts

`steward.coding-task.v1` preserves the original summary-and-path response.
`STEWARD_ALLOW_DIRTY_WORKSPACE=YES` is its development-only clean-check escape
hatch.

`steward.coding-task.v2` additionally requires `expected_base_commit`, always
requires a clean checkout, ignores that escape hatch, and returns a
`steward.git-handoff.v1`. Call it through the signed developer helper with a fresh
one-use `--task-id`; adding `--expected-base-commit` selects version 2, while
omitting it selects version 1. The handoff contains the object format, base commit
and tree, one binary full-index patch, the patch's SHA-256 digest and length, a
sorted changed-path inventory, and the result tree reproduced through a second
temporary Git index and object directory. The source index, refs, and object
database are not used for handoff writes.

Version 2 is bounded to 512 paths, 48 KiB of path bytes, a 256 KiB patch, and a
448 KiB canonical result. One 45-second aggregate deadline covers both captures
and verification after an engine task of at most 900 seconds. The shipped Steward
Gateway coding presets fix the connector ceiling at 990 seconds.

Ignored output, submodules, special files, unsafe or portable-colliding paths,
partial or sparse repositories, alternate object stores, executable Git filters,
unstable captures, and non-reproducible patches fail closed. Changed content,
relevant base/result blobs, streams, and raw patch bytes are scanned for protected
credential material.

The handoff is untrusted application output. Reproducing its result tree does not
prove the patch correct, identify the provider or model, or make it a signed
artifact. Apply it to an independently obtained base, inspect the staged diff, and
run repository tests before committing or publishing anything.
