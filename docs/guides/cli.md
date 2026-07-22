---
title: Make stewardctl easier to use
description: Save repeated connection and task-authority paths in named contexts, run a recoverable first task, and enable Bash, Zsh, or Fish completion without copying secret values.
section: How-to guide
---

# Make `stewardctl` easier to use

Most `stewardctl control` and `stewardctl node` commands, plus `stewardctl agent
apply`, `stewardctl agent deploy`, and `stewardctl agent deployment`, need the same connection settings. A named
context saves those repeated values once. You keep typing only the values specific
to the task.

The context stores **paths** to token and key files, not their values. Private
signing keys and bearer values are never copied into the context file.

## Check health before changing anything

Once a context contains a Control or local node connection, start with:

<!-- cli-flags: status | -output -watch -->
```console
stewardctl status
```

This combines bounded Control attention findings and Executor reconciliation
readiness. It prints a short human summary by default. Use `-output json` for
automation or `-watch 5s` for repeated terminal updates.

If Steward needs attention, ask for the cause, impact, and safest next step:

<!-- cli-flags: explain | -output -->
```console
stewardctl explain
stewardctl explain node-a
```

Executor can automatically recover only a reconciliation-proven missing workload.
The command previews the cleanup unless `--apply` is explicit:

<!-- cli-flags: recover | -apply -output -->
```console
sudo -H stewardctl recover executor-DIGEST
sudo -H stewardctl recover executor-DIGEST --apply
```

See [Diagnose and recover Steward safely]({{ '/guides/troubleshooting/' |
relative_url }}) before manual container, journal, or evidence changes.

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

For direct administration of the host-local Executor, create a node context. Start
with the narrowest role that can do the work. The packaged token files are readable
only by `root` and the Executor service account, so run both setup and later
commands as `root`:

```console
sudo -H stewardctl context set local-node \
  -node-token-file /etc/steward/executor-observer-token
sudo -H stewardctl node whoami
sudo -H stewardctl node maintenance status
```

`node whoami` returns the credential ID and role without exposing its value. Use
`/etc/steward/executor-operator-token` for lifecycle or maintenance changes. Use
the host-admin `/etc/steward/executor-token` only for admission, state snapshots,
state clones, or state purge.
These roles are host-wide API limits, not tenant
identities.

After a stateful source is destroyed, host administrators can drive the same
bounded Executor contracts used by signed uplink commands:

```console
sudo -H stewardctl node snapshot-state \
  -tenant-id tenant-a -node-id node-a \
  -instance-id source -lineage-id source-lineage -generation 1 \
  -snapshot-id checkpoint-a

sudo -H stewardctl node clone-state \
  -tenant-id tenant-a -node-id node-a \
  -instance-id fork -lineage-id fork-lineage -generation 1 \
  -snapshot-id checkpoint-a -source-lineage-id source-lineage
```

These direct commands require the explicitly enabled host-administrator intent
compatibility mode. Shared multi-tenant production should deliver the equivalent
tenant-signed `snapshot-state`, `clone-state`, and `delete-snapshot` commands through
the uplink. Purge every clone lineage before deleting its source snapshot:

```console
sudo -H stewardctl node delete-snapshot \
  -tenant-id tenant-a -node-id node-a \
  -instance-id source -lineage-id source-lineage -generation 1 \
  -snapshot-id checkpoint-a
```

The loopback URL defaults to `http://127.0.0.1:8090` when
`-node-token-file` is present. Set `-node-url` only when the packaged loopback port
was changed. A single context may contain both Control and local-node settings.

### Connect the first-task authority

After `site connect` creates the tenant operator context and the node operator
exports Gateway service trust, connect the task paths from the trusted workstation:

```console
stewardctl site task connect /secure/steward/site \
  -trust /secure/steward/service-trust.json \
  -gateway-token-file /secure/steward/gateway-service.token
```

The Gateway origin defaults to `http://127.0.0.1:8091` when its token path is
present. `site task connect` verifies the signed site package, tenant, node,
service inventory, task key, and Gateway credential path before it changes the
context. The service-trust inventory is non-secret but must cross an authenticated
channel. The task private key remains an owner-only external file; the context
stores only its absolute path. Use `-gateway-url`, `-task-key`, or `-context` when
the defaults do not match the installation.

`context set` remains the expert surface for a separately assembled context:

```console
stewardctl context set production \
  -control-url https://control.customer.example:8443 \
  -ca-file /etc/steward-control/pki/ca.crt \
  -token-file /secure/steward-control/tenant-a-operator.token \
  -tenant-id tenant-a \
  -gateway-token-file /secure/steward/gateway-service.token \
  -service-trust /secure/steward/service-trust.json \
  -task-key /secure/steward/tenant-task.private.pem \
  -task-key-id tenant-task-1
```

A higher-assurance site can keep the task key on a separate signing workstation
and use `task issue`, authenticated transfer, `task submit`, and `task wait`.

With the context selected, run a prompt against a durable Hermes
deployment:

```console
stewardctl task run auditor \
  "Review the workspace and report one concrete issue"
```

The command waits for exactly one running instance unless `-instance-id` selects
one. It retains the verified intent and authenticated admission result from
Control, checks that the configured key is admitted for the selected service,
writes the owner-only signed task bundle, dispatches through Gateway, waits, and
writes the result without printing request or result bytes. For prompt mode it
infers the qualified `hermes.run` operation from the authenticated
admission result. It creates an owner-only run directory beside the CLI context,
with `request.json`, `task.bundle.json`, and `result.json`, and returns their paths.
Use `-run-dir` to select a new directory under an existing owner-only parent.

The bundle is created before network dispatch. If dispatch or waiting fails, keep
it and follow the recovery command printed in the error. Reusing the same bundle
is safe and observable; issuing a new task ID could duplicate an effect whose
outcome is still unknown.

For generated requests, the prompt is limited to 32 KiB. Hermes receives it as
`input`. Use the explicit `-request`,
`-operation-id`, `-bundle-out`, and result flags when exact prebuilt JSON, a
different qualified operation, deterministic paths, or off-node signing is
required.

Routine lifecycle commands accept the returned runtime reference directly:

```console
sudo -H stewardctl node status executor-DIGEST
sudo -H stewardctl node logs executor-DIGEST
sudo -H stewardctl node stop executor-DIGEST
```

The existing `-runtime-ref` form remains available for scripts. Supplying both
forms is rejected as ambiguous.

Previewing a drain needs no reason and changes nothing:

```console
sudo -H stewardctl node maintenance drain
```

Applying the plan requires the operator role or host-admin role, an explicit
reason, and `-apply`:

```console
sudo -H stewardctl node maintenance drain \
  -reason "kernel update" \
  -apply
```

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

Contexts affect `stewardctl status`, `stewardctl explain`, `stewardctl recover`,
`stewardctl control`, `stewardctl node`, `stewardctl agent apply`,
`stewardctl agent deploy`, `stewardctl agent deployment`, and `stewardctl task run`.
For `task run`, a context may supply paths to the Gateway token, service-trust
inventory, and task private key plus its public key ID. It never stores the secret
values or silently supplies workload files, command IDs, capture IDs, runtime
references, result paths, or destructive resource identities. Existing commands
with explicit flags continue to work when no context is selected. Files written by
an older context schema remain readable and are upgraded on the next edit.

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
and the built-in `hermes` Gateway service preset. It runs the local
`stewardctl` binary and makes no network request. For example, after
`stewardctl gateway service set -agent ` it offers only the closed Hermes preset.

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
token and key files owner-only. Executor and Gateway still verify the signed
authority before acting, regardless of which context selected the file paths.
