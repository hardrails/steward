---
title: Operate a fleet with the embedded React console
description: Inspect a scoped fleet and submit one exact offline-signed Executor command without placing signing keys or general mutation authority in the browser.
section: How-to guide
---

# Operate a fleet with the embedded React console

Steward Control serves an observation-first operator control room at `/console/`.
It shows the operations summary, derived attention findings, enrolled nodes,
observed agent runtimes, durable Workrooms, command metadata, and credential
metadata already available through the bounded control API.

The console has one deliberately narrow mutation: it can submit the exact bytes
of an Executor command that was already signed outside the browser. It cannot
create, edit, approve, sign, retry, revoke, enroll, acknowledge, dismiss, export,
or delete anything. Private signing keys and secret plaintext never belong in the
console.

## Open the console

The simplest path uses the selected CLI context:

```console
stewardctl console
```

Keep the command running and open the printed loopback URL. `stewardctl`
verifies the controller's HTTPS certificate with the context's configured CA,
then serves the console on a temporary `http://127.0.0.1:PORT/console/` address.
The local listener accepts only the exact printed Host value and never injects
the saved operator token. Enter a least-privilege operator token in the page.

This avoids installing a private CA in every browser profile. It also works
through an SSH tunnel when the context's Control URL points at the tunnel:

```console
ssh -N -L 8443:127.0.0.1:8443 operator@control-host
stewardctl console
```

The first command keeps the remote controller on loopback. The second verifies
Control through that tunnel and gives the browser a separate loopback-only
address without a certificate warning.

### Direct browser access

The console has no separate listener, port, account database, or authentication
mode. It is embedded in `steward-control` and uses the same `-addr`, TLS
configuration, control API, and operator bearer authentication.

For the default literal-loopback listener, open this exact URL on the controller
host:

```text
http://127.0.0.1:8443/console/
```

Do not substitute `localhost`. Steward derives an exact Host-header gate
automatically. Without TLS, it accepts only the actual bound literal IP and port.
A malformed or different Host value fails before console or API route dispatch.

Direct access is useful when Control uses a certificate already trusted by the
operator's browser. Use a local port other than the controller's bound port only
through `stewardctl console` or a trusted proxy that rewrites the upstream Host
to the controller's exact bound authority.

For a direct TLS listener, use an exact DNS name or IP address from the loaded
leaf certificate's Subject Alternative Names (SANs):

```text
https://control.customer.example:8443/console/
```

The Host value must match an exact, non-wildcard DNS or IP SAN at the bound port.
The port may be omitted only for HTTPS port `443`. A wildcard-only certificate
does not establish an accepted Host value. Install the private certificate
authority in the hardened browser profile or operating-system trust store, or
use `stewardctl console` so the browser needs no private-CA configuration.

If an operator-managed reverse proxy fronts a loopback controller, configure the
proxy to replace the upstream Host header with the controller's exact bound
authority. Do not forward an arbitrary client-supplied Host header.

## Enter the least-privilege credential

Enter an existing site-administrator or tenant-operator bearer in the password
field. The page sends it only in the `Authorization: Bearer` header on same-origin
`/v1/` requests. It omits cookies, rejects redirects, and never accepts a token in
the console URL. Do not paste a bearer into a query string, bookmark, or browser
address bar.

Prefer a tenant operator for routine inspection. A tenant operator sees only its
tenant. A site administrator can view the site-wide summary and select a tenant
projection. The console does not expand the credential's existing API scope.

The credential is held in a JavaScript memory reference, not a cookie,
`localStorage`, or `sessionStorage`. The input field is cleared immediately after
submission. Locking the page aborts in-flight requests and clears the credential,
fleet snapshot, and selected tenant from application state.

Initial authentication has a two-minute hard deadline. Navigation or `pagehide`
also clears the credential while those first reads are still in flight; a stalled
response cannot retain pre-session authority indefinitely.

## Find the right view

Every view starts with the effective command-delivery state for the selected
scope. A green banner means Control may deliver new commands. A red striped banner
shows whether the whole site or the selected tenant is frozen, together with the
retained reason, revision, and change time. The banner also states the important
limit: already accepted work is not instantly revoked, while heartbeats, reports,
and evidence continue.

The console does not set or clear a freeze. Use the authenticated
`stewardctl control freeze` workflow described in
[Freeze new command delivery during an incident]({{ '/guides/control-plane/' | relative_url }}#freeze-new-command-delivery-during-an-incident).

The navigation groups everyday fleet monitoring first and keeps infrastructure
and security records separate. Start with **Overview**, then open **Needs
review** when the console reports a finding.

| Group | View | What it shows | What it omits |
| --- | --- | --- | --- |
| Monitor | Overview | Fleet health, capacity, evidence posture, failures, schedules, and open questions | Mutation controls, workflow content, and raw evidence frames |
| Monitor | Needs review | Deterministic findings with cause, impact, and safest next step | Acknowledgement, retry, or direct remediation |
| Monitor | Timeline | Current containment, evidence divergence, revocation, and failed-workload facts | Complete history, prompts, logs, and result bodies |
| Agents | Agents | Last successful workload status, latest signed operation, node, and delegated routes; low-level identities are under **Technical details** | Desired state, command bytes, task authorities, and secrets |
| Agents | Questions | Bounded agent questions, choices, expiry, workload identity, and response state | Private keys, browser-side signing, or proof that agent-authored text is trustworthy |
| Agents | Tasks | Bounded task progress, findings, reported lifecycle, and preserved conflicts | Task submission, verified result claims, and retries |
| Agents | Workrooms | Projects, sessions, task links, external artifact digests, selected memory, and recent work | Prompts, result bytes, artifact bytes, and storage credentials |
| Agents | Schedules | Finite schedule metadata, next run, recent states, overlap policy, and a cancellation command | Request bodies, private keys, or browser-side cancellation |
| Agents | Agent updates | Identity-stamped bounded status and finding events | Proof that agent-authored content is correct or action authority |
| Infrastructure | Nodes | State, placement, drain progress, last observation, capacity, and capabilities | Node credentials and direct node actions |
| Infrastructure | Capacity pools | Provider-neutral capacity intent, deficits, conditions, and scale-in candidates | Cloud credentials, provider mutations, and enrollment authority |
| Security | Activity | Retained command state and an advanced courier for one offline-signed command | Command creation, signature verification, private keys, and result text |
| Security | Access | Credential identity, kind, role, scope, creation time, and revoked state | Bearer values, token message-authentication codes, and private keys |

The Timeline view is a retained chronology, not an append-only audit log. A later
transition replaces the earlier retained state, and bounded records can disappear.
Use the CLI support bundle to preserve the current metadata snapshot, and preserve
signed evidence or export events to your own SIEM when historical reconstruction
is required.

The Workrooms view is a bounded index, not a content store. It is shown only for
one tenant projection. Create sessions, enqueue signed tasks, and register
external artifacts with `stewardctl`; the console receives no task-signing or
storage credential. See
[Keep agent work in a durable Workroom]({{ '/guides/workrooms/' | relative_url }}).

The Schedules and Questions views keep authorization outside the browser. Create
or cancel finite task authority with `stewardctl task schedule`; answer an open
question with `stewardctl control interaction respond`. See
[Run finite scheduled tasks]({{ '/guides/scheduled-tasks/' | relative_url }}) and
[Answer a running agent safely]({{ '/guides/agent-interactions/' | relative_url }}).

The Agents view keeps workload status separate from operation outcome. For
example, if a running agent receives a stop command that fails, the card shows
`running` as the last successful observation and flags the failed stop as the
latest operation. This avoids claiming the workload stopped or failed when
Executor reported neither result. An `unknown` status means Control has signed
runtime identity but no unambiguous successful workload observation.

Attention guidance comes from Control's stable reason-code catalog, not from raw
Docker or upstream error text. Copying a diagnostic command does not execute it or
grant authority. Run the command in a trusted terminal, review its current output,
and use the [diagnosis and recovery guide]({{ '/guides/troubleshooting/' |
relative_url }}) before applying a change.

The console refreshes a visible page every 30 seconds and also provides a manual
refresh. Operations pages request at most 100 records; the selected tenant's node
view and the site-administrator node-pool view each request at most 500. The tenant
selector loads at most 500 records at a time and offers the next page when more
tenants exist. When another view says more records exist, use the bounded API
cursor through an authenticated client; the console does not silently claim that
its first page is complete.

## Submit one offline-signed command

Create and sign the command on a trusted signing station. The station should not
be the browser host. Follow [Sign, submit, and observe one command]({{ '/guides/control-plane/' | relative_url }}#sign-submit-and-observe-one-command)
through the `stewardctl executor-command issue` step, but do not run the CLI
submission command.

Calculate the digest on the signing station before transferring the file:

```console
sha256sum start-agent-1-0001.dsse.json
```

Then use the console:

1. Sign in with the least-privilege tenant operator. A site administrator must
   select one tenant; command transfer is disabled for the site-wide projection.
2. Open **Activity**, expand **Submit an offline-signed command**, and choose the
   DSSE JSON file. The file must be no larger
   than 750 KiB so its Base64-wrapped API request remains inside the controller's
   one-mebibyte body limit.
3. Compare the displayed `sha256:` digest with the digest calculated on the
   signing station. Also review the signed command ID, operation, tenant, node,
   instance, runtime reference, lifecycle fences, validity window, and signature
   key identifiers.
4. Type the exact `SUBMIT <command_id>` phrase and re-enter the same operator
   bearer used for the current console session.
5. Submit. The password input is cleared immediately. The controller authenticates
   the operator, strictly parses the signed tenant and node route, and queues the
   unchanged envelope. It does not verify the command signature. The Executor
   verifies the original bytes against signed site policy before acting.

The local preview is not proof that a signature is valid or authorized. It rejects
common malformed files and labels the result **UNVERIFIED LOCAL PREVIEW**, but the
Executor remains the signature authority. The preview expires after five minutes
or when the signed command expires. Changing tenants, locking, navigating away, or
a successful submission clears the loaded command from React state.

The controller submission is idempotent for the same command ID and exact bytes.
An accepted response means the command is queued or already retained; it does not
mean the Executor verified or executed it. Watch the command inventory or use
`stewardctl control command status` to distinguish `pending`, `leased`, and
terminal outcomes.

Digest comparison catches accidental file substitution only when the signing
station and display are trustworthy. A compromised browser or extension can show
one value while submitting another valid signed command it possesses. It still
cannot forge an authorized command signature, but it can misuse any valid command
and operator bearer it can read. Use a dedicated browser profile and keep signed
command files short-lived.

## Understand the session boundary

The page locks and clears its in-memory credential after:

- an explicit **Lock** action;
- a `pagehide` event, including ordinary navigation away;
- 15 minutes without trusted pointer or keyboard activity; or
- eight hours from successful sign-in, regardless of activity.

Returning focus or visibility after suspension immediately checks both deadlines.
A session from before a lock has a separate epoch; its aborted or late responses
cannot re-enter the current React state.

These are browser-side controls. Clearing the page does not revoke the bearer at
Steward Control or change its server-side lifetime. Revoke or rotate a bearer
through the normal operator workflow when its authority must end.

## Use a hardened browser profile

Browser extensions execute inside the browser trust boundary and may be able to
read page content, form input, or JavaScript memory. Content Security Policy does
not protect against a privileged or compromised extension. Use a dedicated,
patched operator profile with no unapproved extensions, no cloud synchronization,
and no unrelated browsing sessions. Treat screenshots and visible fleet metadata
as sensitive even though the console omits secret values.

Steward serves only the committed HTML, JavaScript, CSS, icon, and third-party
notice text assets. Security headers prohibit framing, external scripts, external
styles, form submission, workers, media, and broad browser capabilities; responses
are `no-store` and send no referrer. These controls reduce browser attack surface
but do not make an untrusted browser, host, or extension safe.

## Air-gapped and source builds

The production React bundle is committed under
`internal/controlplane/console/dist` and embedded into the `steward-control` Go
binary. An operator install, normal `go build ./...`, or air-gapped Go build does
not run npm and does not require Node.js. The running controller needs no CDN,
telemetry endpoint, JavaScript registry, or Node.js runtime.

Frontend maintainers use the lockfile-pinned React and Vite dependencies. With
Node.js 24 LTS, reproduce the committed bundle from the repository root:

```console
npm ci --prefix internal/controlplane/console --ignore-scripts --no-audit --no-fund
npm audit --prefix internal/controlplane/console --audit-level=moderate
npm --prefix internal/controlplane/console run check
npm --prefix internal/controlplane/console run build
git diff --exit-code -- internal/controlplane/console/dist
```

`npm audit` contacts the configured package registry. This maintainer rebuild lane
is separate from an operator installation or disconnected Go build. CI runs the
same checks with a pinned Node 24 LTS toolchain and rejects a build whose output
differs from the committed distribution. Review the lockfile, generated diff, and
`internal/controlplane/console/public/THIRD_PARTY_NOTICES.txt` before accepting a
dependency update.

For controller installation, scoped operator issuance, command delivery, evidence
exports, and backup, continue with
[Operate the bundled Steward control plane]({{ '/guides/control-plane/' | relative_url }}).
The frontend dependency and embedding rationale is recorded in
[Embed an observation-first React operator console]({{ '/decisions/0020-embedded-react-operator-console/' | relative_url }})
and [Use the browser as a signed-command courier]({{ '/decisions/0023-native-signed-command-console-courier/' | relative_url }}).
