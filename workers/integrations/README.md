# Managed integration worker

This optional Steward worker keeps managed-auth broker credentials and end-user
provider credentials outside an agent, model context, application control plane,
log, and artifact. It exposes only reviewed operations; it is not an API proxy,
MCP server, or dynamic action catalog.

The first profile supports Google Drive through Pipedream Connect:

- create a ten-minute, one-use Google Drive Connect Link;
- reconcile a connected account without retrieving credentials;
- list at most 50 file metadata records through one frozen Drive API request; and
- verify ownership before revoking one account.

The Pipedream OAuth access token is minted with the exact scopes needed for each
operation and is never cached. The Google OAuth client configured in Pipedream must
request `https://www.googleapis.com/auth/drive.metadata.readonly`; the worker will
not mark an account ready without that reported scope. Configure that OAuth app ID
with `STEWARD_GOOGLE_DRIVE_OAUTH_APP_ID`.

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

Every non-health endpoint requires `Authorization: Bearer <worker token>` and an
exact bounded JSON body. Responses set `Cache-Control: no-store`; request logging
is disabled so connect URLs cannot enter an access log.
