# Hermes Agent feasibility adapter

This directory contains Steward's independently maintained feasibility adapter for
Hermes Agent. It is not an upstream image and it is not a claim that arbitrary
Hermes releases work under Steward.

The build consumes an already-present checkout of the exact upstream revision
recorded in `adapter.json`. `scripts/hermes-feasibility.sh` exports that checkout
with `git archive`, builds the adapter, and then runs the hostile-runtime checks.
The build never uses the upstream image: that image starts as root, declares a
volume, and its Dockerfile at the selected revision names two lockfiles that are
not present in the tree.

The adapter replaces upstream's root-only s6 initialization with `entrypoint.py`.
That shim performs only fixed-path, non-root initialization, verifies and installs
the signed `steward.workspace-audit` skill, starts the upstream gateway, and
provides the service endpoint on port 8766. The skill creates a bounded canonical
inventory of `/opt/data/workspace`; it rejects links, special files, limit
violations, and concurrent mutation. It does not change Hermes core source or
seed workspace content into the image.

The port 8766 service is intended to sit behind a Steward authenticated service
grant. It serves `GET /steward/v1/negotiation` itself and forwards only
`GET /health`, `POST /v1/runs`, and `GET /v1/runs/run_<32 lowercase hex>` to the
Hermes API on loopback. It replaces caller credentials with a fixed internal
Bearer token, never forwards cookies, requires a `Content-Length` on run
submissions, limits request bodies to 64 KiB and responses to 1 MiB, and uses a
30-second I/O timeout. The bridge is single-threaded with a bounded connection
queue. Run event streams are deliberately not exposed by this first service
surface. The bridge runs inside the isolated Hermes adapter container under
gVisor; it is not part of the Steward host process.

The pinned build selects upstream's `mcp` extra and its `homeassistant` extra. At
this revision, the latter is the smallest locked extra that supplies `aiohttp`,
which the native API-server adapter requires. No Home Assistant integration is
configured or granted at runtime.

Passing this feasibility gate proves only the capabilities enumerated in the
generated evidence. Full release qualification still requires the later
conformance, recovery, channel, quota, and Gateway-grant tests.
