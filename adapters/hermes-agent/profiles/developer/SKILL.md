---
name: steward-coding-worker
description: Delegate a bounded repository task to a separately isolated Codex or Claude Code worker without exposing its subscription or API credentials to Hermes.
---

# Steward coding worker

Use this skill when a repository task benefits from Codex or Claude Code. The
worker is a separate security boundary. Hermes receives its structured result,
not its credential store.

Run:

```console
python /opt/steward/profiles/developer/coding_worker.py \
  --worker codex \
  --task-id task-4bd6ce188f8b4e09a92af56d59a5df0e \
  --mode read \
  --task "Inspect the repository and explain the failing test. Do not edit files."
```

Use a fresh, unpredictable task ID for every intended call. Reusing one is a
replay, not a retry.

Choose `write` only when the user requested changes and the admitted connector
allows them. Add `--expected-base-commit` with the exact lowercase Git commit ID
to request a bounded immutable handoff. The returned binary patch binds that base
and a reproduced result tree, but it is still untrusted code that requires an
independent review. A failed engine returns its structured result on stdout and a
nonzero command status.

Do not install a CLI, copy an auth file into Hermes, invoke a provider endpoint
directly, or ask the user to paste a token into the task. A missing or denied
worker is a boundary failure to report, not a reason to bypass Steward.
