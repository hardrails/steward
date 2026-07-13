# OpenClaw feasibility adapter

This directory builds a thin adapter on the exact OpenClaw revision recorded in
`adapter.json`. OpenClaw remains a separate upstream project and is never imported
into a Steward process.

The adapter runs as `65532:65532`, keeps state under `/home/node/.openclaw`, reads
Gateway authentication only from the fixed read-only
`/home/node/.config/openclaw/gateway-token` handle, and exposes the upstream HTTP
and WebSocket service through port 18789. The shim adds only side-effect-free
`GET /steward/v1/negotiation` and a byte-preserving HTTP/WebSocket proxy to the
upstream loopback listener.

Run `scripts/openclaw-feasibility.sh <pinned-checkout>` on a disposable Linux host
with Docker and the `runsc` runtime. A passing report is feasibility evidence, not
general OpenClaw support. Publication remains blocked until the built image's npm
and Debian license inventory has been reviewed without unresolved entries.
