---
title: Make stewardctl easier to use
description: Save repeated connection settings in named contexts and enable Bash, Zsh, or Fish completion without storing bearer credentials.
section: How-to guide
---

# Make `stewardctl` easier to use

Most `stewardctl control` and `stewardctl node` commands need the same connection
settings. A named context saves those repeated values once. You keep typing only
the values specific to the task.

The context stores **paths** to token files, not token values. Private signing keys
and bearer values are never copied into the context file.

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

For direct administration of the host-local Executor, create a node context. The
packaged token is readable only by `root` and the Executor service account, so run
both setup and later commands as `root`:

```console
sudo -H stewardctl context set local-node \
  -node-token-file /etc/steward/executor-token
sudo -H stewardctl node maintenance status
```

The loopback URL defaults to `http://127.0.0.1:8090` when
`-node-token-file` is present. Set `-node-url` only when the packaged loopback port
was changed. A single context may contain both Control and local-node settings.

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

Contexts affect `stewardctl control` and `stewardctl node` commands. They do not
supply signing keys, secret values, workload files, command IDs, capture IDs,
runtime references, or destructive resource identities. Existing commands with
explicit flags continue to work when no context is selected. Files written by an
older context schema remain readable and are upgraded on the next edit.

Add `-no-context` to a Control or node command to ignore the context file
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

Completion covers commands, nested subcommands, common flags, saved context names,
and the built-in `hermes` and `openclaw` Gateway service presets. It runs the local
`stewardctl` binary and makes no network request. For example, after
`stewardctl gateway service set -agent ` it offers only those two closed presets.

Install and activate completion for the current shell:

```console
stewardctl completion install
```

The command detects Bash, Zsh, or Fish from `SHELL` and prints the exact files it
changed as JSON. Start a new shell to use completion. If detection is wrong, name
the shell:

```console
stewardctl completion install -shell zsh
```

For Bash and Zsh, the installer writes a generated file under the user
configuration directory and appends one clearly marked source block to `.bashrc`,
`.bash_profile` on macOS when `.bashrc` is absent, or `.zshrc`. Fish loads its
generated file from `fish/completions` without changing `config.fish`. Repeating
the command is a no-op. A conflicting generated file is preserved unless
`-force` is explicit.

To inspect or manage activation yourself, print a script without changing files:

```console
stewardctl completion bash
stewardctl completion zsh
stewardctl completion fish
```

Generated scripts fall back to ordinary file completion when the next value is a
path. Candidate generation stays local and reads only command metadata and saved
context names; it does not read token values or contact Control or Executor.

## Security boundary

The context file reduces typing; it is not a credential store or an authorization
artifact. Anyone who can modify it can redirect commands to another controller,
another loopback port, or another token file. The completion installer also makes
a narrow, visible change to the user's shell startup file. Keep the user account
and configuration directory trusted, inspect those files under a managed-dotfiles
policy, review `stewardctl context show` before a sensitive operation, and keep
token files owner-only. Executor still verifies signed command authority before
acting, regardless of which context transported the command.
