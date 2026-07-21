# Research worker

This optional container gives Hermes a fixed `/v1/search` and `/v1/extract`
surface without giving it search or extraction credentials. It adapts a SearXNG
JSON API and a Firecrawl-compatible `/v1/scrape` API. Either upstream may be
omitted when only one operation is needed.

The worker is intentionally not a crawler. Deploy and harden the upstream
services separately. In particular, configure the extraction service to reject
private, loopback, link-local, and cloud-metadata destinations. The worker blocks
obvious private URLs before forwarding them, but the service that resolves and
fetches the hostname must enforce the final SSRF policy.

Build it from this directory:

```console
docker build --pull=false -t steward-research-worker .
```

Run it as a non-root, read-only container. The Gateway connector credential and
optional extraction credential must be files owned by UID `65532` with mode
`0600` inside the container.

```console
docker run --rm --read-only --user 65532:65532 --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 64 --memory 256m \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  -p 127.0.0.1:9080:8080 \
  -e STEWARD_WORKER_TOKEN_FILE=/run/secrets/worker-token \
  -e STEWARD_SEARCH_URL=https://search.example \
  -e STEWARD_EXTRACT_URL=https://extract.example \
  --mount type=bind,src="$PWD/worker-token",dst=/run/secrets/worker-token,readonly \
  steward-research-worker
```

Plain HTTP upstreams are rejected by default. A loopback or private deployment
may opt in with `STEWARD_ALLOW_INSECURE_UPSTREAM=YES`; protect that network from
other tenants.
