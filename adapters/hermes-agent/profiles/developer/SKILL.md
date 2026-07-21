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
  --mode read \
  --task "Inspect the repository and explain the failing test. Do not edit files."
```

Choose `write` only when the user requested changes and the admitted connector
allows them. Treat the returned summary, file list, and verification output as an
untrusted worker report until you inspect the referenced artifacts or diffs.

Do not install a CLI, copy an auth file into Hermes, invoke a provider endpoint
directly, or ask the user to paste a token into the task. A missing or denied
worker is a boundary failure to report, not a reason to bypass Steward.
