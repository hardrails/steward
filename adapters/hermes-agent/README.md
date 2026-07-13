# Hermes Agent adapter

This directory contains Steward's independently maintained, exact-pinned adapter
for Hermes Agent. It is not an upstream image and it does not qualify arbitrary
Hermes releases, plugins, channels, skills, or configuration.

The build consumes an already-present checkout of the exact upstream revision
recorded in `adapter.json`. `scripts/hermes-feasibility.sh` exports that checkout
with replace refs and repository-local Git commands disabled. The builder runs
the networkless planner and host fetcher described in the operator guide, then runs
upstream dependency and packaging hooks inside a bounded gVisor container with
`--network=none`, read-only inputs, no Docker socket, dropped capabilities,
`no-new-privileges`, fixed resource limits, and bounded artifact output. The final
Dockerfile only assembles that validated output and runs with build networking
disabled. The feasibility gate then runs the hostile-runtime checks.
The build never uses the upstream image: that image starts as root, declares a
volume, and its Dockerfile at the selected revision names two lockfiles that are
not present in the tree.

The adapter replaces upstream's root-only s6 initialization with `entrypoint.py`.
That shim performs only fixed-path, non-root initialization, verifies the signed
`steward.workspace-audit` and `steward.connector-work` skills from an immutable
external skill directory, starts the upstream gateway, and provides the service
endpoint on port 8766. The workspace skill creates a bounded canonical inventory
of `/opt/data/workspace`; it rejects links, special files, limit violations, and
concurrent mutation. The connector skill performs one fixed JSON job through
Steward's logical connector path without being configured with the upstream origin
or credential. The adapter does not change Hermes core source or seed workspace
content into the image.

The port 8766 service is intended to sit behind a Steward authenticated service
grant. It serves `GET /steward/v1/negotiation` itself and forwards only
`GET /health`, `POST /v1/runs`, and `GET /v1/runs/run_<32 lowercase hex>` to the
Hermes API on loopback. It replaces caller credentials with a fixed internal
Bearer token, never forwards cookies, requires a `Content-Length` on run
submissions, limits request bodies to 64 KiB and responses to 1 MiB, and uses a
30-second I/O timeout. The bridge is single-threaded with a bounded connection
queue. Run event streams are deliberately not exposed by the current service
surface. The bridge runs inside the isolated Hermes adapter container under
gVisor; it is not part of the Steward host process.

Production state does not enable an external MCP server. The qualification harness
can enable the fixed `fixture_echo` MCP service with
`STEWARD_HERMES_QUALIFICATION_MCP=enabled`; Executor never injects that variable.
This keeps a test-only dependency from blocking normal startup or becoming an
undeclared production capability.

The pinned build selects upstream's `mcp` extra and its `homeassistant` extra. At
this revision, the latter is the smallest locked extra that supplies `aiohttp`,
which the native API-server adapter requires. No Home Assistant integration is
configured or granted at runtime.

On `linux/amd64`, qualification passed two independent paths. The closed-runtime
gate built the exact source, ran the basic task, signed workspace-audit skill,
qualification-only MCP fixture, and restart under gVisor. The Steward integration
gate then imported the archive through signed admission, brokered inference,
service, and connector traffic through Gateway, and required Hermes to discover and
load the exact signed connector skill before executing it. The gate proved one
authenticated upstream effect, replay and forbidden-operation denial, secret and
origin absence for the fixed qualification material, changed workspace output after
a fresh resumed session, state purge, and verified Executor and connector receipt
chains. These proofs remain limited to the exact pinned inputs and documented
capability surface. Other platforms require their own qualification run.

Maintainers can retain a non-sensitive integration summary by setting
`HERMES_INTEGRATION_EVIDENCE_OUT` when running
`scripts/hermes-steward-acceptance.sh`. A successful run writes a new owner-only file
that binds the archive hash and image digests, available Git or packaged-builder
provenance, Steward binary hashes and versions, the complete gate list, and the
verified receipt-chain head. The harness refuses to overwrite an existing file and
writes nothing on failure. It validates `HERMES_BUILD_ATTESTATION`, or the archive's
default `.attestation.json` sibling when present, before including a bounded metadata
subset. The summary contains no workspace output, credential, log, or agent content;
it is metadata rather than a separately signed attestation.
