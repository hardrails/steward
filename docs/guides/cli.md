---
title: Make stewardctl easier to use
description: Save repeated connection settings in named contexts and enable Bash, Zsh, or Fish completion without storing bearer credentials.
section: How-to guide
---

# Make `stewardctl` easier to use

Most `stewardctl control` commands need the same controller address, certificate,
operator token file, tenant, and node. A named context saves those repeated values
once. You keep typing the few values that are specific to the task.

The context stores the **path** to your operator token, not the token itself.
Private signing keys and bearer values are never copied into the context file.

## Set up a context once

Choose a short name such as `production`:

```console
stewardctl context set production \
  -control-url https://control.customer.example:8443 \
  -ca-file /etc/steward-control/pki/ca.crt \
  -token-file /secure/steward-control/tenant-a-operator.token \
  -tenant-id tenant-a \
  -node-id node-a
```

The new context becomes active immediately. A command that previously repeated
five connection and scope flags becomes:

```console
stewardctl control command status -command-id start-agent-1-0001
```

Explicit flags always override the active context. This is useful for a one-time
query against another node:

```console
stewardctl control command status \
  -node-id node-b \
  -command-id start-agent-1-0001
```

Steward does not infer a destructive target. Commands such as node revocation
still require an explicit node or credential identifier even when the context has
a default node.

## Switch between environments

List the saved contexts and select another one:

```console
stewardctl context list
stewardctl context use staging
stewardctl context show
```

For one shell command or automation run, select a context without changing the
saved current context:

```console
STEWARD_CONTEXT=staging stewardctl control operations status
```

Delete a context you no longer use:

```console
stewardctl context delete staging
```

The default file is the operating system's user configuration directory under
`steward/contexts.json`. `STEWARD_CONTEXT_FILE` can select another absolute path
for isolated automation. Steward requires the file and its final directory to be
owner-only, serializes concurrent writers through an owner-only lock, writes
updates atomically, bounds the file to 64 KiB, accepts at most
32 contexts, and rejects unknown or duplicate fields.

Contexts affect `stewardctl control` commands only. They do not supply signing
keys, secret values, workload files, command IDs, capture IDs, or destructive
resource identities. Existing commands with explicit flags continue to work when
no context is selected.

Add `-no-context` to a `stewardctl control` command to ignore the context file
entirely. This is useful for self-contained automation and recovery from a damaged
local context:

```console
stewardctl control operations status -no-context \
  -control-url "$CONTROL_URL" \
  -token-file "$OPERATOR_TOKEN" \
  -ca-file "$CONTROL_CA" \
  -tenant-id tenant-a
```

## Enable shell completion

Completion covers commands, nested subcommands, common flags, and saved context
names. It runs the local `stewardctl` binary and makes no network request.

For Bash:

```console
mkdir -p ~/.local/share/bash-completion/completions
stewardctl completion bash > ~/.local/share/bash-completion/completions/stewardctl
```

Start a new shell, or load it now:

```console
source ~/.local/share/bash-completion/completions/stewardctl
```

For Zsh:

```console
mkdir -p ~/.zfunc
stewardctl completion zsh > ~/.zfunc/_stewardctl
fpath=(~/.zfunc $fpath)
autoload -Uz compinit && compinit
```

Put the `fpath` and `compinit` lines in `.zshrc` to keep completion enabled.

For Fish:

```console
mkdir -p ~/.config/fish/completions
stewardctl completion fish > ~/.config/fish/completions/stewardctl.fish
```

Generated scripts fall back to ordinary file completion when the next value is a
path. Regenerate the script after upgrading Steward so newly added commands and
flags appear.

## Security boundary

The context file reduces typing; it is not a credential store or an authorization
artifact. Anyone who can modify it can redirect commands to another controller or
select a different token file. Keep the user account and configuration directory
trusted, review `stewardctl context show` before a sensitive operation, and keep
operator token files owner-only. Executor still verifies signed command authority
before acting, regardless of which context transported the command.
