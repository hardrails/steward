---
name: steward.connector-work
description: Perform one deterministic job through Steward's named connector without receiving its credential or upstream address.
---

# Steward connector work

For a `STEWARD_CONNECTOR_WORK` request, run
`/opt/steward/skills/steward.connector-work/connector_work.py perform TASK_ID`.
Return its canonical JSON output unchanged.

Qualification also uses the fixed `replay` and `forbidden` modes to prove that
Steward rejects a spent task ID and an undeclared operation. Each mode accepts
one bounded task ID. The program calls only the logical URL in
`STEWARD_CONNECTOR_URL`; it has no credential or upstream address.
