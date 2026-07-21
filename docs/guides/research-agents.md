---
title: Run a web research agent
description: Give Hermes bounded web search and page extraction without putting browser access or provider credentials inside the agent.
section: How-to guide
---

# Run a web research agent

The research profile lets Hermes search the web, extract selected pages, and send
findings to Steward Control. Hermes does not receive a browser, public network
route, or search key.

This separation matters because web content is untrusted. A page can contain text
that tells an agent to ignore its task, reveal a secret, or call another service.
Steward does not try to classify that text as safe. It limits the operations and
credentials available after the model reads it.

## What runs where

1. Hermes calls the fixed search or extraction path on its local Steward Relay.
2. Gateway verifies the admitted connector grant, call budget, request size, and
   exact operation.
3. The optional research worker adds its own search credential for SearXNG, or
   fetches an explicitly selected public page through its pinned-address extractor.
4. The worker returns normalized JSON. Its search credential never enters the
   Hermes container.
5. Hermes can publish a bounded finding to Steward Control. The event contains a
   code, severity, summary, source URL, and idempotency key—not the agent's full
   conversation.

The bundled skill tells Hermes to treat every search result and page as data, not
instructions. This is useful defense in depth, but it is not a prompt-injection
detector or proof that a finding is true.

## 1. Run the research worker

Build the worker from a Steward source checkout:

```console
docker build --pull=false -t steward-research-worker workers/research
```

Create a random bearer token in an owner-only file. Give the worker and Gateway
separate files containing the same value so each file can have the correct owner.

```console
sudo install -d -o root -g root -m 0700 /etc/steward/research-worker
openssl rand -hex 32 | sudo tee /etc/steward/research-worker/token >/dev/null
sudo chown 65532:65532 /etc/steward/research-worker/token
sudo chmod 0600 /etc/steward/research-worker/token

sudo install -o steward-gateway -g steward-gateway -m 0600 \
  /etc/steward/research-worker/token \
  /etc/steward/credentials/research-worker
```

Run the worker with gVisor. Replace the search example with a SearXNG service you
operate or trust. Page extraction needs no provider service or credential. The
worker resolves every requested hostname and redirect, rejects the request when
any address is private, loopback, link-local, reserved, or otherwise non-public,
and connects to the chosen address without resolving the name again. This closes
DNS-rebinding and redirect forms of server-side request forgery (SSRF) at the
worker boundary.

```console
sudo docker run -d --name steward-research-worker --restart unless-stopped \
  --read-only --runtime runsc --user 65532:65532 --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 64 --memory 256m \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  -p 127.0.0.1:9080:8080 \
  -e STEWARD_WORKER_TOKEN_FILE=/run/secrets/worker-token \
  -e STEWARD_SEARCH_URL=https://search.example \
  --mount type=bind,src=/etc/steward/research-worker/token,dst=/run/secrets/worker-token,readonly \
  steward-research-worker
```

The reference worker is not a crawler, browser, or search engine. It extracts
bounded text from HTML, XHTML, and plain-text responses; it does not execute
JavaScript. The SearXNG upstream may be omitted when only extraction is needed. See the
[worker reference](https://github.com/hardrails/steward/tree/main/workers/research)
for its complete environment contract.

## 2. Connect the worker to Gateway

The presets fix the connector IDs, methods, paths, and conservative request,
response, concurrency, time, and per-grant call limits. The local HTTP exception
is explicit and restricted to loopback.

```console
sudo stewardctl gateway connector set \
  -preset research-search \
  -base-url http://127.0.0.1:9080 \
  -credential-file /etc/steward/credentials/research-worker \
  -allow-insecure-http \
  -allow-cidr 127.0.0.0/8 \
  -tenant-budget research=8388608

sudo stewardctl gateway connector set \
  -preset research-extract \
  -base-url http://127.0.0.1:9080 \
  -credential-file /etc/steward/credentials/research-worker \
  -allow-insecure-http \
  -allow-cidr 127.0.0.0/8 \
  -tenant-budget research=8388608

sudo systemctl restart steward-gateway
```

Gateway validates the whole candidate configuration before replacing it. The
tenant budget reserves durable connector-receipt capacity; it is not an API spend
limit.

## 3. Authorize the research application

Create the initial site policy with both ordinary connector identities:

```console
stewardctl site init steward-site \
  -tenant-id research \
  -connector-ids steward-research-extract,steward-research-search
```

Start from
[`examples/agents/researcher/agent.json`](https://github.com/hardrails/steward/blob/main/examples/agents/researcher/agent.json).
Replace the placeholder image digest and model route, then use the normal
[build, publish, and apply workflow]({{ '/guides/build-agents/' | relative_url }}).
The definition selects `tool_profile: research`, the signed
`steward-research` skill, both connector IDs, and controller events. Admission
fails if any required part is missing.

Run one top-level task after activating the Hermes service:

```console
stewardctl task run researcher \
  "Compare three primary sources on the requested topic. Cite each source, separate observation from inference, and report material uncertainty."
```

One tenant signature authorizes the exact top-level Hermes request. Inside that
request, the adapter permits at most four child research agents, 12 delegated
iterations, one level of delegation, 180 seconds of delegation time, and 32 total
Hermes turns. Search and extraction still pass through Gateway's independent call
and byte budgets. Steward does not create an unsigned remote-dispatch tier.

## 4. Read findings outside the instance

Use the React control room, or list retained events from a trusted terminal:

```console
stewardctl control event list \
  -tenant-id research \
  -token-file /etc/steward/control-operator.token
```

Delivery is at least once. Consumers must use the event ID or idempotency key to
deduplicate work. A reported finding is an agent assertion with source metadata,
not a trusted security decision. See [Receive agent events]({{ '/guides/controller-events/' |
relative_url }}) for retention and failure behavior.

## Air-gapped research

An air-gapped site cannot search or extract from the public web. Point search at
an internal SearXNG deployment and expose approved corpus services through
separate connector operations. The public-page extractor intentionally rejects
private destinations. Import source data through your site's reviewed media
process; do not give Hermes a temporary unrestricted route for convenience.
