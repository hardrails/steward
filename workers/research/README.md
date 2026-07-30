# Research worker

This optional container gives Hermes a fixed `/v1/search` and `/v1/extract`
surface without giving it search credentials or unrestricted network access. It
adapts a SearXNG JSON API and directly extracts bounded text from public HTTP(S)
HTML, XHTML, plain-text, and PDF sources.

The worker is intentionally not a crawler or browser. Before each request and
redirect, it resolves the hostname, rejects the destination if any returned
address is non-public, and connects to a selected public address without a second
DNS lookup. HTTPS still verifies the original hostname. It follows at most five
redirects, rejects compressed transport bodies, and reads at most 4 MiB.
JavaScript-rendered pages are outside the reference worker's contract.

PDF extraction uses the pure-Python, BSD-3-Clause `pypdf` 6.14.2 wheel pinned by
version and SHA-256 with no optional or transitive packages. Each PDF is parsed in
a fresh child process with a 4-second CPU limit, 5-second wall timeout, 128 MiB
address-space ceiling, 200-page ceiling, 1,000-object recovery ceiling, 16-file
descriptor ceiling, and 256 KiB normalized-text ceiling. Malformed, encrypted,
image-only, oversized, or otherwise unextractable PDFs fail closed. The worker
does not perform OCR. The v1 extraction request remains fail-fast: one rejected
URL rejects the batch rather than returning an ambiguous partial result.

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

Run the dependency-backed adversarial tests inside the built image:

```console
docker run --rm --entrypoint /usr/local/bin/python3 \
  --mount type=bind,src="$PWD",dst=/src,readonly \
  steward-research-worker -I -B /src/test_research_worker.py
```
