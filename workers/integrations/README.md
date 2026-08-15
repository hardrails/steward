# Managed integration worker

This optional Steward worker keeps managed-auth broker credentials and end-user
provider credentials outside an agent, model context, application control plane,
log, and artifact. It exposes only reviewed operations; it is not an API proxy,
MCP server, or dynamic action catalog.

The first profile supports Google Drive through Pipedream Connect:

- create a ten-minute, one-use Google Drive Connect Link;
- reconcile a connected account without retrieving credentials;
- list at most 50 file metadata records through one frozen Drive API request;
- read one through ten selected Google Docs, plain-text files, or Markdown files
  through frozen metadata and content requests, with 64 KiB per-file and 640 KiB
  aggregate text bounds and an explicit outcome for every requested ID; and
- verify ownership before revoking one account.

The Pipedream OAuth access token is minted with the exact scopes needed for each
operation and is never cached. The Google OAuth client configured in Pipedream must
request `https://www.googleapis.com/auth/drive.readonly`; the worker will
not mark an account ready without that reported scope. Configure that OAuth app ID
with `STEWARD_GOOGLE_DRIVE_OAUTH_APP_ID`.

The content operation refetches metadata and `capabilities.canDownload` for each
exact caller-selected ID. It exports native Google Docs as `text/plain`, downloads
only `text/plain` and `text/markdown` blobs, validates UTF-8, normalizes line endings,
rejects control characters, and hashes normalized bytes. Unsupported, unavailable,
locked, oversized, or invalid-text files return safe item outcomes; content is never
silently truncated. The caller cannot supply a URL, MIME type, export format, query,
folder, provider header, or abuse acknowledgement.

`drive.readonly` is a restricted Google scope. A public production deployment must
complete Google's current OAuth verification and, when required, restricted-scope
security assessment before enabling this profile. Deterministic worker tests do not
replace that approval or a real consent/read/revoke exercise.

All three credentials are owner-only files, owned by runtime UID `65532`, with no
group or world permission:

```text
STEWARD_WORKER_TOKEN_FILE=/run/secrets/worker-token
STEWARD_PIPEDREAM_CLIENT_ID_FILE=/run/secrets/pipedream-client-id
STEWARD_PIPEDREAM_CLIENT_SECRET_FILE=/run/secrets/pipedream-client-secret
```

The non-secret deployment configuration is:

```text
STEWARD_PIPEDREAM_PROJECT_ID=proj_...
STEWARD_PIPEDREAM_ENVIRONMENT=development
STEWARD_GOOGLE_DRIVE_OAUTH_APP_ID=oa_...
```

Run it read-only as UID/GID `65532:65532`, drop all capabilities, apply
`no-new-privileges`, and provide egress only to `api.pipedream.com:443`. Pipedream
performs the provider request, so the worker does not need direct Google egress.

Provider operations listen on private port `8080`. Readiness is served on a separate
private listener at `http://steward-integrations:8081/healthz`, so slow or saturated
provider work cannot delay the deployment probe. Neither listener should be published.

Every non-health endpoint requires `Authorization: Bearer <worker token>` and an
exact bounded JSON body. Responses set `Cache-Control: no-store`; request logging
is disabled so connect URLs cannot enter an access log.
