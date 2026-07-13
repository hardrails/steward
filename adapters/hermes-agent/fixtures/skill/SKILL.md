---
name: steward.workspace-audit
description: Create a bounded, content-addressed inventory of the persistent workspace without using the network.
---

# Steward workspace audit

Run `/opt/data/skills/steward.workspace-audit/workspace_audit.py` without
arguments. Return its canonical JSON output unchanged.

The audit reads only `/opt/data/workspace`. It rejects symbolic links, hard-linked
files, special files, concurrent changes, and inputs exceeding its compiled file,
directory, depth, path, per-file, or total-byte limits. It never follows a path
outside the workspace and never sends workspace data over the network.
