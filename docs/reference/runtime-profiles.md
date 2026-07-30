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
| `agent-service-v1@v1` | `65532:65532` | `/state` (`v1`) | `serve` | `agent-api` on `8080` |
| `hermes-v1@v1` | `65532:65532` | `/opt/data` (`v1`) | `serve` | `hermes-api` on `8766` |
| `hermes-research-v1@v1` | `65532:65532` | `/opt/data` (`v1`) | `serve` | `hermes-api` on `8766` |
| `hermes-developer-v1@v1` | `65532:65532` | `/opt/data` (`v1`) | `serve` | `hermes-api` on `8766` |

The three Hermes profiles run the same qualified adapter but expose different
signed skill directories and Hermes toolsets. `hermes-v1` is the general
workspace profile. The research profile requires the normalized search and
extract connectors, the opaque-reference browser search and read connectors, and
controller events. The developer profile requires at
least one separately operated Claude Code or Codex connector. Credentials stay
in those services; they are not mounted into Hermes state.

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

The `agent-service-v1` profile fixes only a portable process and HTTP boundary.
It does not qualify an agent's reasoning, prompts, tools, output, or external
effects. The image must start with `serve`, keep mutable state under `/state`,
and expose `steward.agent-service.v1` on `agent-api:8080`. See the
[agent service protocol](https://github.com/hardrails/steward/blob/main/openapi/steward-agent-service.v1.yaml)
for the bounded health, invocation, and result shapes.
