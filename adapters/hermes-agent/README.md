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
Dockerfile assembles that validated output and the original verified source,
with RUN networking disabled. Docker's checksum-verified ADD fetches four exact
Debian security packages; native dpkg installs them offline before Hermes source
is copied. The assembly also removes those downloads and the unused base pip
installer; no project build hook runs in Docker assembly. The feasibility
gate then runs the hostile-runtime checks.
The build never uses the upstream image: that image starts as root, declares a
volume, and its Dockerfile at the selected revision names two lockfiles that are
not present in the tree.

The September stable source pin uses upstream's source-backed editable
installation at `/opt/hermes`. Its source, virtual environment, skills and locale
assets are root-owned and read-only to the runtime user. Building at that same
path avoids stale temporary paths in entrypoints and import metadata. The slim
base retains Python, uv and shell execution, not the full base's incidental
compiler, Git, curl or image-processing packages. Additional system tooling needs
an explicit workload test and reviewed image, or a separate worker. See
[ADR 0083](../../docs/decisions/0083-reuse-hermes-source-installation-and-a-slim-runtime.md).

The adapter replaces upstream's root-only s6 initialization with `entrypoint.py`.
That shim performs only fixed-path, non-root initialization, verifies the signed
skills shipped in immutable external skill directories, starts the upstream
gateway, and provides the service endpoint on port 8766. The workspace skill
creates a bounded canonical inventory of `/opt/data/workspace`; it rejects links,
special files, limit violations, and concurrent mutation. The connector skill
performs one fixed JSON job through Steward's logical connector path without being
configured with the upstream origin or credential. The adapter also contains two
explicit tool profiles. `research` exposes fixed search, extraction, and finding
commands. `developer` exposes a fixed client for separately isolated Codex and
Claude Code workers. Both profile skills are signed and verified at startup. They
know only logical Steward connector names; provider credentials and upstream
origins never enter Hermes state. The adapter does not seed workspace content
into the image.

`task-scope.patch` is an explicit delta to the pinned Hermes source. The builder
verifies the upstream inputs, applies the patch only to its exported source tree,
and binds the patch through the adapter file-set digest. The original upstream
revision and archive remain provenance inputs; the resulting image is a patched
adapter, not an unchanged upstream build. Package and activation inventories
include the patch.

The run bridge carries one bounded canonical `X-Steward-Inference-Permit` header
to the private Hermes API. The patched API passes it to the run's model client
after checking that the selected route is the Steward relay. It disables the
client's credential pool and fallback chain for that run. Main-runtime snapshots
and default child credential inheritance remain Hermes-owned; legacy global
mirrors no longer retain API keys. Requests without scope retain compatibility
behavior, but cannot pass a gateway route that requires task scope. Native
qualification must prove the patched model paths before deployment; local bridge
tests and source-patch checks alone do not qualify an image.

The signed acceptance harness also requires two independent workspace tasks to
overlap at the fixture provider, return their own distinct results and retain
their original task-scoped receipts. A bounded two-party barrier rejects serial
execution; ledger ordering independently requires an interval with an authorized,
unfinished inference request from each task, allowing earlier titles to finish.
Each fixture answer also waits for its own background
title request so fast completion cannot close authority before that auxiliary
call starts. Missing titles fail explicitly, without changing the expected count.
The fixture route has four concurrent slots for the two main calls and their
two background titles. Production route limits are unchanged. Gateway HTTP tests
verify that excess calls are rejected before reaching the provider or ledger.
The full fixture expects seven tasks, seven session titles,
22 inference calls and 67 signed gateway records. The retained
[integration evidence](../../docs/reference/evidence/hermes-integration.json)
records successful execution of that expanded fixture; release checks bind it
to the exact adapter inputs. Independent release review remains required.
The workspace profile disables native delegation;
the research profile's delegated model paths still need separate runtime proof.

As container PID 1, the entrypoint reaps orphaned tool processes while preserving
the gateway's exit status. Container SIGTERM/SIGINT starts one ten-second gateway
shutdown deadline; repeated signals do not extend it. The wait loop enters bounded
kill/reap cleanup if the gateway ignores termination, including during startup.
Bridge cleanup uses the same deadline, so a slow HTTP client cannot keep PID 1
waiting indefinitely. At container startup, PID 1 holds the gateway's runtime lock
while removing only `gateway.pid` and `gateway_state.json`: process identity from
an earlier PID namespace is not reusable identity. Sessions, workspace, and the
lock inode remain intact, and an active lock prevents this cleanup.
This container-level shutdown is separate from the run-specific stop operation.

The v2 service contract adds a bounded stop operation. Local HTTP boundary tests
do not qualify an adapter release. CI and release packaging require retained
successful disposable-host gVisor evidence matching the current adapter inputs,
including stopping an active tool. Evidence for different bytes is not sufficient.

The port 8766 service is intended to sit behind a Steward authenticated service
grant. It serves `GET /steward/v1/negotiation` itself and forwards only
`GET /health`, `POST /v1/runs`, and `GET /v1/runs/run_<32 lowercase hex>` to the
Hermes API on loopback. `POST /steward/v1/run-stop` accepts exactly the canonical
49-byte JSON object `{"run_id":"run_<32 lowercase hex>"}` and forwards an empty
object to that run's native `/stop` endpoint. The fixed operation path permits
Gateway to require a signed exact-body operation without a wildcard path grant.
It is not automatically authorized by an existing run-submission permit. The
response may say `stopping`; this is not evidence that execution or an external
effect has halted. Reconcile the same run's terminal status separately.
Native `/approval`, `/events`, and `/stop` subroutes remain unavailable at the
bridge. Existing bounded controller-event and signed-interaction channels are the
intended substrate for progress and business questions; a Hermes workspace helper
and controller integration still need implementation and acceptance. Upstream
command-approval choices are not a business-question protocol.
The bridge replaces caller credentials with a fixed internal
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

The September upstream lock still pins affected `httpx2` and `httpcore2` 2.7.0.
The adapter records a two-package security exception in `security_overrides`:
both use 2.12.0, with exact wheel URLs, byte sizes and hashes. The networkless
planner refuses a missing, partial or different override inventory and refuses
the exception if the original upstream versions change. The
existing bounded fetcher verifies those wheels; uv installs them offline without
resolving more dependencies and checks the installed environment. This is an
explicit adapter-maintained patch, not an unchanged upstream dependency set.
Native qualification also requires the installed distribution versions to match
these exact declarations; successful MCP behavior alone cannot prove patching.
Remove the exception and its mandatory-inventory checks together once a reviewed
upstream lock supplies the fixes.

On `linux/amd64`, qualification exercises two independent paths. The closed-runtime
gate builds the exact source and runs the basic task, signed workspace-audit skill,
qualification-only MCP fixture, active-tool stop, and restart under gVisor. The Steward
integration gate imports the archive through signed admission, brokers inference,
service, and connector traffic through Gateway, and requires Hermes to discover and
load the exact signed connector skill before executing it. The gate checks one
authenticated upstream effect, replay and forbidden-operation denial, secret and
origin absence for the fixed qualification material, changed workspace output after
a fresh resumed session, state purge, and verified Executor and connector receipt
chains. Successful records remain limited to the exact pinned inputs and documented
capability surface. After confirming its containers are absent, the feasibility
harness restores owner access only to its temporary state directories to remove
read-only skill copies. It neither follows links nor traverses another filesystem,
and does not grant root cleanup authority over agent-generated content.
Other platforms require their own qualification run.

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
