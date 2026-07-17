---
title: Add native CLI contexts and shell completion
description: Why stewardctl saves repeated non-secret defaults and generates completion scripts without adopting a CLI framework or credential store.
section: Architecture decision
---

# Add native CLI contexts and shell completion

- Status: Accepted
- Date: 2026-07-17
- Rung: standard library and native shell facilities

## Context

Routine control-plane commands repeat the controller URL, private CA file,
operator token file, tenant, and node. Repetition makes the safe path harder to
learn, hides the task-specific values in long commands, and encourages operators
to build unreviewed shell aliases. The large command tree is also difficult to
discover without completion.

Steward cannot solve this by storing bearer values in a convenience file. A CLI
context can redirect an operation or select a different credential path, so it is
security-sensitive even when it contains no secret. Destructive operations must
not inherit a target merely because the operator previously inspected that node.

## Decision

Add named `stewardctl` contexts using the Go standard library. A context stores a
controller URL, optional CA path, required operator-token path, and optional tenant
and node defaults. It never stores the bearer value, private signing material, or
command content.

Explicit flags override context values. Connection defaults apply across remote
control commands. Tenant and node defaults apply only to scoped inspection,
command delivery, and evidence workflows. Resource creation, revocation, and
credential administration continue to require their destructive or authority-
creating identities explicitly.
`-no-context` bypasses context loading for a self-contained command or recovery
from a damaged context file.

The configuration is a bounded, strict JSON file in the user's configuration
directory. Steward requires an owner-only final directory and file, permits at
most 32 named contexts, writes changes through an owner-only temporary file and
atomic rename, and rejects unknown fields, duplicate names, symlinks, unsafe
permissions, and relative credential paths. `STEWARD_CONTEXT` selects one profile
for a process without changing the saved current profile.

Generate Bash, Zsh, and Fish completion scripts from `stewardctl completion`.
Each script asks the local binary for command, nested subcommand, common flag, and
saved context-name candidates. It makes no network request and falls back to the
shell's normal file completion for path values.

**Tradeoff:** the command tree and common flags have a small explicit completion
catalog that must change with the CLI. Tests cover important paths, but completion
is not a machine-derived declaration of every flag. Context defaults also make
the effective command less visible in shell history, so `context show` and
explicit overrides remain important for sensitive work.

**Rejected:** adopting Cobra, Viper, or another CLI framework, because a broad CLI
rewrite and external module would violate Steward's zero-dependency contract for
functionality the standard library can provide. Environment variables alone were
rejected because they are difficult to inspect and switch safely. Storing token
values was rejected because it would turn the context into another secret store.

## Consequences

Existing explicit commands remain compatible when no context is selected. A
missing current context does not become an error unless `STEWARD_CONTEXT` names a
profile that does not exist. Context configuration is user-local and is never sent
to the controller as an object; only the same explicit HTTP inputs are produced.

Anyone who can modify the context file can redirect commands or select another
credential file. Operators must protect their local account and inspect the
active context before sensitive operations. Executor verification, signed policy,
and durable fences remain authoritative regardless of which context transported a
command.
