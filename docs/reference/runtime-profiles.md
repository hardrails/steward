---
title: Runtime profile contracts
description: Exact command, identity, state, and service values required by Steward's built-in agent runtime profiles.
section: Reference
---

# Runtime profile contracts

A runtime profile is Steward's fixed host-side contract for an agent image. It
defines the unprivileged Linux identity and the writable state location. Named
runtime adapters also fix the container command and local service endpoint. These
values are security inputs, not suggestions: a capsule that differs is rejected
before signing, import, or admission.

| Profile | Linux identity | Writable state | Command | Local service |
| --- | --- | --- | --- | --- |
| `generic-v1@v1` | `65532:65532` | `/state` (`v1`) | Publisher-defined | Publisher-defined |
| `hermes-v1@v1` | `65532:65532` | `/opt/data` (`v1`) | `serve` | `hermes-api` on `8766` |

Check an unsigned capsule before moving it to a signing workstation:

```console
stewardctl capsule check-profile -in capsule.json
```

`stewardctl capsule sign` and `stewardctl capsule verify` run the same profile
check automatically. `stewardctl agent publish` obtains its Hermes
values from this same built-in registry, so its generated capsule cannot drift
from Executor's admission rules.

The generic profile is intentionally different: its publisher chooses the
command and optional service contract, while Steward still fixes the Linux
identity and state path. Use a named profile when you want an audited adapter
contract instead of a general container contract.
