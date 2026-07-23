# Browser research worker

This optional worker gives a Hermes research agent access to JavaScript-rendered
public pages without giving the agent a general browser, credentials, or raw
network access.

It exposes two finite operations:

- `POST /v1/search` searches an operator-controlled SearXNG service and returns
  short-lived opaque source references.
- `POST /v1/read` opens only those references in fresh, credential-free browser
processes and returns bounded visible text and an optional viewport screenshot.
References expire after 15 minutes. The worker retains at most 512 references;
when that store is full, new searches fail with `source_capacity_exhausted`
instead of invalidating an active reference early.

The worker rejects local and non-public destinations, pins the selected public
address into Chromium, blocks cross-origin requests, disables service workers
and downloads, and closes every browser process after one source. Run it under
gVisor on a network with no routes to control, node, metadata, or private service
addresses. Browser request interception is defense in depth; network topology
must remain the outer SSRF boundary.

The worker token and optional SearXNG token are owner-only files. Neither token
enters the Hermes instance. See `docs/guides/browser-research.md` for deployment.
