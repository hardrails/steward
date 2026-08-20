# Research worker

This optional container gives agents fixed `/v1/search`, `/v1/extract`, and
`/v2/extract` surfaces without giving them search credentials or unrestricted
network access. It adapts a SearXNG JSON API by default, and automatically uses
the Brave Search API when an owner-only Brave key file is configured. Both
paths normalize to the same fixed result contract before directly extracting
bounded text from public HTTP(S) HTML, XHTML, plain-text, JSON, and PDF sources.
It can also inject an owner-only U.S. EIA API key for one frozen, credential-free
commercial electricity-price request profile.

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
does not perform OCR.

## Extraction contracts

Both extraction versions accept exactly one `urls` field containing one through
ten absolute HTTP(S) URLs. Duplicate URLs are retained.

`POST /v1/extract` preserves the original fail-fast contract. It fetches URLs
sequentially, returns `steward.research-extract-result.v1`, and rejects the whole
call as soon as one source fails.

`POST /v2/extract` is a total-batch contract. It returns
`steward.research-extract-result.v2` with exactly one outcome for each requested
URL, in request order, even when completion order differs:

```json
{
  "schema_version": "steward.research-extract-result.v2",
  "outcomes": [
    {
      "requested_url": "https://example.test/report",
      "disposition": "extracted",
      "resolved_url": "https://cdn.example.test/report.pdf",
      "source_media_type": "application/pdf",
      "title": "Report",
      "content": "Normalized source text",
      "content_type": "text/plain",
      "content_truncated": false
    },
    {
      "requested_url": "https://example.test/missing",
      "disposition": "failed",
      "failure_code": "source_rejected"
    }
  ]
}
```

An extracted outcome has exactly the fields shown. `source_media_type` is the
accepted upstream representation for HTML, plain text, and PDF: `text/html`,
`application/xhtml+xml`, `text/plain`, or `application/pdf`. Every accepted JSON
representation, including `application/*+json`, is reported canonically as
`application/json`. JSON is parsed and serialized with stable key ordering before
it leaves the worker. JSON is limited to 8,192 values and 64 levels, and strings
must be valid UTF-8 scalar text. `content_type` is always `text/plain` and
describes the normalized output. Content is limited to 32 KiB of valid UTF-8;
unsafe control characters are replaced with spaces, and `content_truncated`
states whether the 32 KiB cap removed text.

A failed outcome contains only `requested_url`, `disposition`, and one closed
`failure_code`: `source_unresolvable`, `private_source_denied`,
`source_unavailable`, `invalid_source_redirect`, `source_rejected`,
`unsupported_source`, `source_too_large`, or `pdf_extraction_timeout`. It never
contains an upstream error message. These source-local failures are values under
HTTP 200. Invalid request URLs, malformed requests, authentication and route
failures, service or child-protocol faults, and an overall response-size failure
reject the whole call.

V2 validates the shape of every request URL before starting work. It runs at most
four source process groups concurrently, gives each started source at most 15
seconds, and gives the whole batch 50 seconds. The parent kills a source process
group when its authority expires, so blocking DNS, socket, parser, and descendant
PDF work cannot wedge the single-threaded HTTP server. A source or pending URL
whose deadline expires receives `source_unavailable`.

The EIA profile is available only through `POST /v2/extract`. The request URL
must be the exact HTTPS retail-sales route with annual frequency, commercial
sector, price data, one U.S. state or District of Columbia, descending period,
and a five-row limit. It must not contain `api_key`. The worker permits at most
one EIA URL per extraction call, injects the mounted key only into the outbound
request to `api.eia.gov`, validates the provider response, and returns a small
`steward.eia-commercial-electricity-price.v1` JSON projection. The requested and
resolved URLs remain credential-free. Any wider EIA route, facet, frequency,
column, ordering, length, or caller-supplied key is rejected before egress.

Source children receive a stripped environment and no inherited file
descriptors, but they run under the same UID and container filesystem as the
parent. They are a deadline and bounded-output failure boundary, not a separate
credential trust domain: a child can still open a guessable worker-token mount
that its UID may read. Protect and sandbox the entire worker container, and do
not treat subprocess isolation as a substitute for the container boundary.

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

To use Brave instead of the keyless SearXNG path, mount an owner-only API-key
file and set `STEWARD_BRAVE_API_KEY_FILE` to it. The worker sends that key only
to `https://api.search.brave.com/res/v1/web/search`; the key never enters an agent request,
response, log, or extracted source artifact. Brave results are still subjected
to the same public-destination validation as SearXNG results. If the configured
provider rejects a request or returns no usable results, the fixed search
contract reports the bounded error or empty list; it does not substitute
uncited model output.

To enable the EIA profile, mount a separate owner-only API-key file and set
`STEWARD_EIA_API_KEY_FILE` to it. The key never enters the worker request,
normalized response, log, child-process environment, or source artifact. If no
key is configured, an otherwise valid EIA URL produces the closed
`source_unavailable` outcome.

Run the dependency-backed adversarial tests inside the built image:

```console
docker run --rm --entrypoint /usr/local/bin/python3 \
  --mount type=bind,src="$PWD",dst=/src,readonly \
  steward-research-worker -I -B /src/test_research_worker.py
```
