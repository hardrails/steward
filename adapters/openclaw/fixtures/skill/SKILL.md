---
name: steward-workspace-audit
description: Audit Steward's fixed qualification workspace and write a bounded, deterministic result. Use only when the user explicitly asks to run the Steward workspace audit.
metadata:
  {
    "openclaw":
      {
        "requires": { "bins": ["node"] },
      },
  }
---

# Steward workspace audit

Run this exact command once:

```console
node /home/node/.openclaw/workspace/skills/steward-workspace-audit/workspace_audit.mjs
```

The command reads only `/home/node/.openclaw/workspace/qualification/input`,
rejects links and special files, and writes the canonical result to
`/home/node/.openclaw/workspace/qualification/result.json`. Report the command's
JSON output exactly. Do not inspect other paths or use another tool.
