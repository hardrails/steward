# Managed integration worker

This optional Steward worker keeps managed-auth broker credentials and end-user
provider credentials outside an agent, model context, application control plane,
log, and artifact. It exposes only reviewed operations; it is not an API proxy,
MCP server, or dynamic action catalog.

The worker currently supports Google Drive, Gmail, Google Calendar, and Slack
through Pipedream Connect.
The Google Drive profile can:

- create a ten-minute, one-use Google Drive Connect Link;
- reconcile a connected account without retrieving credentials;
- list at most 50 file metadata records through one frozen Drive API request;
- read one through ten selected Google Docs, plain-text files, or Markdown files
  through frozen metadata and content requests, with 64 KiB per-file, 240 KiB
  aggregate text, one shared 30-second batch deadline, and an explicit outcome for
  every requested ID; and
- verify ownership before revoking one account.

The Gmail profile can:

- create the same bounded, one-use connection link for a configured Gmail OAuth app;
- require exactly `https://www.googleapis.com/auth/gmail.readonly`, rejecting broader
  Gmail scopes;
- read at most 20 messages carrying the `INBOX` label from the last 30 days, within
  one shared 30-second deadline;
- return only bounded `From`, `To`, `Subject`, and `Date` headers plus the first
  UTF-8 `text/plain` MIME body, falling back explicitly to Gmail's snippet; and
- verify app-scoped ownership before every read or revocation.

The Gmail caller cannot supply a URL, search query, label, message ID, MIME format,
attachment request, provider header, or write action. Email is untrusted input;
consumers must treat the normalized result as evidence, never instructions.

The Google Calendar profile can:

- create the same bounded, one-use connection link for a configured Google Calendar
  OAuth app;
- require exactly
  `https://www.googleapis.com/auth/calendar.events.readonly`, rejecting every
  broader or cross-integration scope;
- read at most 50 events from the primary calendar for the next 14 days, expanding
  recurring events and ordering them by start time within one 30-second deadline;
- return bounded normalized times, text, organizer, and at most 20 attendees per
  event; and
- verify app-scoped ownership before every read or revocation.

The Calendar caller cannot supply a calendar ID, query, time range, page token,
attendee limit, URL, provider header, or write action. Event titles, descriptions,
locations, and participants are untrusted input; consumers must treat them as
evidence, never instructions.

The Slack profile can:

- create the same bounded, one-use connection link for a configured Slack user OAuth
  app;
- require exactly `channels:read` and `channels:history`, rejecting identity,
  private-channel, direct-message, directory, search, file, reaction, and write
  scopes;
- list at most 100 non-archived public channels for selection by the authenticated
  service caller; and
- make one request for at most 15 recent messages from that caller-selected public
  channel after independently rechecking current public membership.

The Slack caller cannot supply a URL, query, page token, time range, message count,
private channel, direct message, thread, provider header, or write action. The worker
does not retrieve a member directory. Channel metadata and message text are untrusted
input; consumers must treat the normalized result as evidence, never instructions.
Slack's current commercially distributed non-Marketplace history limit makes
multi-channel and paginated reads separate future capabilities.

This worker is a credential and provider-authority boundary, not an end-user identity
provider. Its bearer-authenticated caller is responsible for authenticating and
persisting the human owner's channel choice, just as it is for Google Drive file IDs.
Railyard is that sole caller in the product deployment. Steward verifies the caller's
opaque external-user/account binding, exact scopes, channel syntax, current public
visibility through one exact `conversations.info` check, and finite operation bounds
before every Slack history request. This exact check does not depend on the bounded
100-channel discovery page. Deployments
must keep the operation listener private; the worker token is service authority, not an
owner session token.

The Pipedream OAuth access token is minted with the exact scopes needed for each
operation and is never cached. The Google OAuth client configured in Pipedream must
request `https://www.googleapis.com/auth/drive.readonly`; the worker will
not mark an account ready without that reported scope. Configure that OAuth app ID
with `STEWARD_GOOGLE_DRIVE_OAUTH_APP_ID`.

The Gmail OAuth app is optional and configured with
`STEWARD_GMAIL_OAUTH_APP_ID`. `gmail.readonly` is also a restricted Google scope;
public production enablement requires Google's current verification and any
required restricted-scope security assessment.

The Google Calendar OAuth app is optional and configured with
`STEWARD_GOOGLE_CALENDAR_OAUTH_APP_ID`. The least-privilege events read-only scope
still requires Google's current OAuth verification before public production use.

The Slack OAuth app is optional and configured with
`STEWARD_SLACK_OAUTH_APP_ID`. It must use Pipedream's `slack` user-account profile
with exactly the two reviewed read scopes. Production enablement requires a real
consent, exact-scope reconcile, public-channel list, selected-channel read, and
revocation exercise; deterministic worker tests do not establish provider approval.

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
STEWARD_GMAIL_OAUTH_APP_ID=oa_...
STEWARD_GOOGLE_CALENDAR_OAUTH_APP_ID=oa_...
STEWARD_SLACK_OAUTH_APP_ID=oa_...
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
