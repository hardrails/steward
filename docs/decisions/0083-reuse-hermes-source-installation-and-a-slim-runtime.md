# 0083. Reuse Hermes source installation and a slim runtime

- Status: Accepted; exact-image qualification remains required
- Date: 2026-09-10
- Rung: installed-dependency

## Context

The July Hermes pin and full uv base carry fixable vulnerability findings.
The September stable Hermes release supplies patched dependency pins, but no
longer supports ordinary wheel distribution: runtime assets are resolved from
its source checkout. Forcing a wheel build would omit assets and contradict the
supported installation path.

## Decision

Use the upstream source-backed editable installation inside the existing bounded,
networkless gVisor builder. Build at `/opt/hermes`, the final immutable path, so
console scripts and editable metadata need no relocation. Assemble the original
verified Git archive, not the source tree modified by packaging hooks, alongside
the validated virtual environment. Runtime UID 65532 cannot modify either.

Use Astral's digest-pinned Python 3.13 slim image and remove only its unused base
`pip` through one fixed offline uninstall command. Dependency preparation remains
uv-based. No upstream build hook executes in the final Docker build. The base
image's pip vendors affected msgpack and setuptools versions even though Hermes's
own dependency environment uses separate pins; leaving that installer is not
required for the runtime.

**Tradeoff:** The slim image omits the full image's incidental compiler, Git, curl
and image-processing packages. Python, uv, shell execution, the Hermes source and
its assets remain. Tool availability must be verified per workload; the separately
isolated developer workers remain the path for repository tooling. Do not describe
this refresh as qualification of every possible tool or dependency installation.

**Rejected:** Maintaining a downstream fork of the July dependency lock creates
ongoing patch ownership. Retaining the full base retains unused vulnerable
packages. Adopting upstream's root-starting image violates native admission.

## Consequences

The runtime qualification now checks source import paths, immutable assets and
absence of base pip. Native functional qualification and exact-image scans must
both pass before promotion; historical evidence cannot certify this refresh.
Retained source includes optional assets, not permission to execute them. The
transitive/base notice inventory remains a separate redistribution requirement.
Revisit if a supported workload requires additional system tools: add reviewed,
pinned tooling with a workload test, rather than restoring an unbounded base.

References: [Hermes stable release](https://github.com/NousResearch/hermes-agent/releases/tag/v2026.9.7),
[upstream installation guard](https://github.com/NousResearch/hermes-agent/blob/2237be355906fbe6065ce1815711eee52b2d646e/setup.py),
[uv container guidance](https://docs.astral.sh/uv/guides/integration/docker/).
