# Research worker

This optional container gives Hermes a fixed `/v1/search` and `/v1/extract`
surface without giving it search credentials or unrestricted network access. It
adapts a SearXNG JSON API and directly extracts bounded text from public HTTP(S)
pages.

The worker is intentionally not a crawler or browser. Before each request and
redirect, it resolves the hostname, rejects the destination if any returned
address is non-public, and connects to a selected public address without a second
DNS lookup. HTTPS still verifies the original hostname. It follows at most five
redirects, accepts only HTML, XHTML, or plain text, and reads at most 4 MiB.
JavaScript-rendered pages are outside the reference worker's contract.

Build it from this directory:

```console
docker build --pull=false -t steward-research-worker .
```

Run it as a non-root, read-only container. The Gateway connector credential must
be a file owned by UID `65532` with mode `0600` inside the container.

```console
docker run --rm --read-only --runtime runsc --user 65532:65532 --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 64 --memory 256m \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  -p 127.0.0.1:9080:8080 \
  -e STEWARD_WORKER_TOKEN_FILE=/run/secrets/worker-token \
  -e STEWARD_SEARCH_URL=https://search.example \
  --mount type=bind,src="$PWD/worker-token",dst=/run/secrets/worker-token,readonly \
  steward-research-worker
```

Plain HTTP search upstreams are rejected by default. A loopback or private deployment
may opt in with `STEWARD_ALLOW_INSECURE_UPSTREAM=YES`; protect that network from
other tenants.
