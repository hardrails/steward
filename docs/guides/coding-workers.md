---
title: Let Hermes use Codex or Claude Code
description: Delegate a bounded repository task from Hermes to an isolated official coding CLI without mounting its credentials into Hermes.
section: How-to guide
---

# Let Hermes use Codex or Claude Code

Hermes can ask Codex or Claude Code to inspect or change a repository through
Steward's developer profile. The coding CLI runs in a separate container with a
disposable standalone Git clone and authentication store. It does not run in the
Hermes process or share Hermes state. The supported worker service runs on Linux;
version 2 handoffs depend on Linux child-process containment.

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

Create a disposable standalone clone instead of mounting your only checkout or a
linked Git worktree. `--no-local` copies the object store rather than borrowing
objects from the source checkout. Removing `origin` removes the inherited default
push destination; the read-only metadata and denied Git-host egress remain the
actual controls:

```console
base_commit=$(git -C /srv/projects/application rev-parse --verify HEAD^{commit})
sudo install -d -o 65532 -g 65532 -m 0700 /srv/steward-coding
sudo -u '#65532' -g '#65532' \
  git clone --no-local /srv/projects/application /srv/steward-coding/application
sudo -u '#65532' -g '#65532' \
  git -C /srv/steward-coding/application checkout --detach "$base_commit"
sudo -u '#65532' -g '#65532' \
  git -C /srv/steward-coding/application remote remove origin
```

Version 2 requires this checkout to be clean and at the expected base commit. The
version 1 development escape hatch does not relax that rule. Read mode maps to
Codex's read-only sandbox or Claude Code's plan mode. Write mode maps to
workspace-write or accept-edits.

The supervisor does not invoke `git commit` or `git push`, and version 2 rejects a
changed final `HEAD`. Those checks cannot prove that an engine never committed and
reset or attempted a push. The read-only Git metadata mount and network policy
below make those effects unavailable.

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
  --mount type=bind,src=/srv/steward-coding/application,dst=/workspace \
  --mount type=bind,src=/srv/steward-coding/application/.git,dst=/workspace/.git,readonly \
  --mount type=bind,src=/var/lib/steward-coding/codex-auth,dst=/home/worker/.codex \
  --mount type=bind,src=/etc/steward/coding-worker/token,dst=/run/secrets/worker-token,readonly \
  steward-coding-worker
```

The nested mount is intentional: `/workspace` remains writable while its contained
`.git` directory is read-only. The worker verifies one exact private `.git` mount,
rejects descendant mounts, and refuses readiness unless the kernel enforces it as
read-only. A linked worktree's `.git` file points outside the mount and is
therefore not a supported version 2 input.

Restrict this container's network to the selected provider and deny Git hosting,
private, node, management, and metadata destinations. Do not mount Git credentials
or credential-helper configuration. The worker scans engine streams, changed
content, relevant Git blobs, and the raw patch for exact credential material and
common encodings, but filtering cannot replace network isolation.

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

Write mode is appropriate only when the user requested changes and the clone is
disposable. For a portable handoff, have the developer profile call its signed
helper with:

- a fresh, unpredictable `--task-id` used for exactly one intended connector
  call;
- `--mode write`; and
- `--expected-base-commit` set to the exact lowercase SHA-1 or SHA-256 commit
  from the standalone clone.

The expected base selects `steward.coding-task.v2`; omitting it preserves the
version 1 request and result. The signed helper validates the complete version 2
response before printing canonical JSON. A failed engine still returns its
validated result but the helper exits nonzero.

If a call ends ambiguously, preserve its task ID and investigate Gateway evidence.
Do not automatically mint a new ID and repeat a potentially completed write.

Version 2 permits at most 512 changed paths, 48 KiB of path bytes, a 256 KiB
binary patch, and a 448 KiB canonical result. It rejects a dirty start, ignored
output, submodules, special files, unsafe or colliding portable paths, executable
Git filters, sparse or partial repositories, alternate object stores, an unstable
capture, and a patch that cannot independently recreate its result tree. The
engine timeout remains at most 900 seconds. The worker reserves another 120
seconds across preflight, cleanup, handoff capture, and response delivery. The
signed helper and coding connector preset allow 1,050 seconds, including a
30-second relay and transport margin, and the preset serializes calls with
`max-concurrent=1`.

## Review a version 2 handoff offline

Save the helper's exact JSON object as `coding-result.json`. Keep the independently
approved base commit outside that response, then decode and verify the patch:

```console
approved_base_commit=REPLACE_WITH_PRE_DISPATCH_COMMIT
jq -er '.schema_version == "steward.coding-result.v2"' coding-result.json >/dev/null
test "$(jq -er '.handoff.base_commit' coding-result.json)" = "$approved_base_commit"
patch_base64=$(jq -er '.handoff.patch_base64' coding-result.json)
printf '%s' "$patch_base64" | base64 --decode >coding.patch
test "$(base64 -w 0 coding.patch)" = "$patch_base64"
test "$(wc -c <coding.patch | tr -d ' ')" = \
  "$(jq -er '.handoff.patch_bytes' coding-result.json)"
patch_sha256=$(jq -er \
  '.handoff.patch_sha256 | select(test("^sha256:[0-9a-f]{64}$")) | ltrimstr("sha256:")' \
  coding-result.json)
printf '%s  %s\n' "$patch_sha256" coding.patch | sha256sum -c -
```

Materialize that base from an independently trusted repository. Use temporary Git
index and object directories, matching the worker's verification path, and require
the response's base tree, changed-path inventories, and result tree to agree:

```console
git clone --no-checkout https://example.invalid/owner/application.git handoff-review
git -C handoff-review checkout --detach "$approved_base_commit"
test "$(git -C handoff-review rev-parse HEAD)" = "$approved_base_commit"
test "$(git -C handoff-review rev-parse --show-object-format)" = \
  "$(jq -er '.handoff.object_format' coding-result.json)"
approved_base_tree=$(git -C handoff-review rev-parse "${approved_base_commit}^{tree}")
test "$approved_base_tree" = \
  "$(jq -er '.handoff.base_tree' coding-result.json)"
review_state=$(mktemp -d)
trap 'rm -rf "$review_state"' EXIT
review_git_dir=$(git -C handoff-review rev-parse --absolute-git-dir)
export GIT_DIR="$review_git_dir"
export GIT_WORK_TREE="$PWD/handoff-review"
export GIT_INDEX_FILE="$review_state/index"
export GIT_OBJECT_DIRECTORY="$review_state/objects"
export GIT_ALTERNATE_OBJECT_DIRECTORIES="$review_git_dir/objects"
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_NO_REPLACE_OBJECTS=1
mkdir "$GIT_OBJECT_DIRECTORY"
git -c core.hooksPath=/dev/null -c core.fsmonitor=false read-tree "$approved_base_commit"
if test -s coding.patch; then
  git -c core.hooksPath=/dev/null -c core.attributesFile=/dev/null \
    apply --cached --binary --whitespace=nowarn "$PWD/coding.patch"
fi
test "$(git write-tree)" = "$(jq -er '.handoff.result_tree' coding-result.json)"
declared_paths=$(jq -cer \
  '.changed_paths as $top | .handoff.changed_paths as $nested | select($top == $nested) | $top' \
  coding-result.json)
actual_paths=$(git -c core.quotePath=false diff --cached --name-only --no-renames \
  --no-ext-diff --no-textconv "$approved_base_commit" -- | \
  LC_ALL=C sort | jq -Rsc 'split("\n")[:-1]')
test "$actual_paths" = "$declared_paths"
git -c core.quotePath=false diff --cached --stat --no-renames \
  --no-ext-diff --no-textconv \
  "$approved_base_commit" --
git -c core.quotePath=false diff --cached --binary --full-index --no-renames \
  --no-ext-diff --no-textconv \
  "$approved_base_commit" --
```

Reproducing the tree proves only that these patch bytes transform the named base
into the named result under Git's rules. It does not establish correctness,
provider identity, model identity, or signed artifact attestation. The current
standard connector receipt binds authorization, route, task identity, and terminal
status, not the exact nested response bytes. Review and test the staged result
before committing, merging, or publishing it.
