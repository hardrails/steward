---
title: Let Hermes read JavaScript websites safely
description: Deploy Steward's constrained Playwright worker so Hermes can search and read public JavaScript pages without receiving a browser session, URL fetch primitive, or network route.
section: How-to guide
---

# Let Hermes read JavaScript websites safely

Some useful sources render their content with JavaScript. Steward's lightweight
research worker cannot read those pages because it deliberately does not run a
browser. The optional browser research worker adds rendered-page reading without
turning Hermes into a general browser operator.

The worker exposes only two operations:

1. `browser-search` sends a bounded query to SearXNG and returns short-lived,
   opaque source references.
2. `browser-read` opens at most five of those references in fresh,
   credential-free Chromium processes and returns bounded visible text and an
   optional viewport screenshot.

Hermes cannot supply a raw URL, click, type, upload, download, evaluate
JavaScript, reuse cookies, open another origin, or invoke arbitrary Playwright
methods. This is intentionally much smaller than computer use.

Source references expire after 15 minutes. One worker retains at most 512
references. At capacity, a new search fails with
`source_capacity_exhausted` until references expire; it never evicts another
active research session's reference. Run a separate worker for each tenant or
trust domain when they need independent availability.

## Security boundary

Web content remains untrusted. It may contain prompt injection, false claims, or
instructions aimed at the model. The worker limits what happens after Hermes
reads that content:

- every resolved address must be public; mixed public/private DNS answers fail;
- the chosen address is pinned into Chromium for the page load;
- subrequests to another origin, service workers, downloads, permissions, and
  popups are blocked;
- each source gets a new browser process and credential-free context;
- request, response, page text, screenshot, concurrency, and time are bounded;
  and
- the worker runs as UID `65532`, with a read-only root filesystem, no Linux
  capabilities, and gVisor.

Browser interception is defense in depth. The worker network must also have no
route to Steward management endpoints, cloud metadata, node APIs, or private
services. Do not deploy it on a broad host network.

## Build the pinned worker

The release includes an exact Playwright package integrity and official
multi-platform image digest:

```console
docker build --pull=false -t steward-browser-worker workers/browser
```

Steward's weekly pin workflow proposes updates. Each proposal runs the package
audit, browser-boundary tests, and a complete image build. It does not silently
change a deployed worker.

## Create worker credentials

Create separate owner-only files for the worker bearer and optional SearXNG
credential:

```console
sudo install -d -o 65532 -g 65532 -m 0700 /etc/steward/browser-worker
openssl rand -hex 32 | sudo tee /etc/steward/browser-worker/token >/dev/null
sudo chown 65532:65532 /etc/steward/browser-worker/token
sudo chmod 0600 /etc/steward/browser-worker/token

sudo install -o steward-gateway -g steward-gateway -m 0600 \
  /etc/steward/browser-worker/token \
  /etc/steward/credentials/browser-worker
```

If SearXNG requires a bearer, place a separate 0600 file owned by UID `65532` at
`/etc/steward/browser-worker/search-token`.

## Run the worker

This example publishes the worker only on loopback. Replace the SearXNG origin
with a service you operate or trust:

```console
sudo docker run -d --name steward-browser-worker --restart unless-stopped \
  --read-only --runtime runsc --user 65532:65532 --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 128 \
  --memory 1g --cpus 2 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=128m \
  --shm-size 256m \
  -p 127.0.0.1:9081:8080 \
  -e STEWARD_WORKER_TOKEN_FILE=/run/secrets/worker-token \
  -e STEWARD_SEARCH_BASE_URL=https://search.example \
  --mount type=bind,src=/etc/steward/browser-worker/token,dst=/run/secrets/worker-token,readonly \
  steward-browser-worker
```

Add
`-e STEWARD_SEARCH_TOKEN_FILE=/run/secrets/search-token` and a read-only mount
when the search service requires authentication.

## Connect Gateway

Both presets point at the same worker but grant separate operation identities and
budgets:

```console
sudo stewardctl gateway connector set \
  -preset browser-search \
  -base-url http://127.0.0.1:9081 \
  -credential-file /etc/steward/credentials/browser-worker \
  -allow-insecure-http \
  -allow-cidr 127.0.0.0/8 \
  -tenant-budget research=8388608

sudo stewardctl gateway connector set \
  -preset browser-read \
  -base-url http://127.0.0.1:9081 \
  -credential-file /etc/steward/credentials/browser-worker \
  -allow-insecure-http \
  -allow-cidr 127.0.0.0/8 \
  -tenant-budget research=8388608

sudo systemctl restart steward-gateway
```

The Hermes research profile uses `steward-research browser-search` and
`steward-research browser-read`. The signed skill tells Hermes to treat returned
text and screenshots as evidence to assess, never as instructions.

## What this does not provide

This worker is not a logged-in browser, password manager, CAPTCHA bypass,
computer-use desktop, generic Playwright MCP server, or archival crawler.
Authenticated browsing would place cookies and account authority next to hostile
content and needs a separate threat model, origin partitioning, approval design,
and containment boundary.

For static HTML, use the smaller research extractor. For authenticated external
effects, use an exact Steward connector and, when needed, Authorized Effects.

[Run the complete research profile]({{ '/guides/research-agents/' | relative_url }}) ·
[Broker API operations]({{ '/guides/connectors/' | relative_url }}) ·
[Understand Authorized Effects]({{ '/guides/authorized-effects/' | relative_url }})
