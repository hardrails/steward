---
title: Operate a fleet with the embedded React console
description: Inspect a scoped fleet and submit one exact offline-signed Executor command without placing signing keys or general mutation authority in the browser.
section: How-to guide
---

# Operate a fleet with the embedded React console

Steward Control serves an observation-first operator control room at `/console/`.
It shows the operations summary, derived attention findings, enrolled nodes,
observed agent runtimes, command metadata, and credential metadata already
available through the bounded control API.

The console has one deliberately narrow mutation: it can submit the exact bytes
of an Executor command that was already signed outside the browser. It cannot
create, edit, approve, sign, retry, revoke, enroll, acknowledge, dismiss, export,
or delete anything. Private signing keys and secret plaintext never belong in the
console.

## Open the correct origin

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

To keep the controller on loopback while using a separate hardened workstation,
forward the exact loopback authority:

```console
ssh -N -L 8443:127.0.0.1:8443 operator@control-host
```

Then open `http://127.0.0.1:8443/console/` on the workstation. Use a local port
other than `8443` only behind a trusted local proxy that rewrites the upstream
Host to the controller's exact bound authority; the automatic gate has no separate
allowlist setting.

For a direct TLS listener, use an exact DNS name or IP address from the loaded
leaf certificate's Subject Alternative Names (SANs):

```text
https://control.customer.example:8443/console/
```

The Host value must match an exact, non-wildcard DNS or IP SAN at the bound port.
The port may be omitted only for HTTPS port `443`. A wildcard-only certificate
does not establish an accepted Host value. Install the private certificate
authority in the hardened browser profile or operating-system trust store; the
browser console has no `-ca-file` option.

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

## Read the six views

Every view starts with the effective command-delivery state for the selected
scope. A green banner means Control may deliver new commands. A red striped banner
shows whether the whole site or the selected tenant is frozen, together with the
retained reason, revision, and change time. The banner also states the important
limit: already accepted work is not instantly revoked, while heartbeats, reports,
and evidence continue.

The console does not set or clear a freeze. Use the authenticated
`stewardctl control freeze` workflow described in
[Freeze new command delivery during an incident]({{ '/guides/control-plane/' | relative_url }}#freeze-new-command-delivery-during-an-incident).

| View | What it shows | What it omits |
| --- | --- | --- |
| Overview | Attention totals, active and retained node counts, evidence posture, command-failure counts, and retained-state capacity | Mutation controls and raw evidence frames |
| Attention | Deterministic findings derived from retained facts and current process observations; evidence recency becomes conservatively stale or unknown after a controller restart until the node reports again | Acknowledgement, dismissal, retry, remediation, or incident workflow |
| Nodes | Node state, placement mode, durable drain state and request ID, failed drain instance when applicable, last observation time, tenant bindings, and reported capabilities for one selected tenant | Node credentials and direct node actions |
| Commands | A local, unverified preview and exact SHA-256 digest for one offline-signed command; submission after confirmation and bearer re-entry; retained command ID, digest, tenant, node, lifecycle state, and creation time | Command creation or editing, signature verification, private keys, terminal result text, prompts, and task bodies |
| Credentials | Credential ID, kind, role or node, scope, creation time, and revoked state | Bearer values, token message-authentication codes, and private keys |
| Agents | One card per signed runtime identity and instance generation with its last successful workload status, latest signed operation, node, logical egress routes, and connector IDs | Desired state, automatic recovery promises, command bytes, task authorities, relay endpoints, free-form errors, and secrets |

The Agents view keeps workload status separate from operation outcome. For
example, if a running agent receives a stop command that fails, the card shows
`running` as the last successful observation and flags the failed stop as the
latest operation. This avoids claiming the workload stopped or failed when
Executor reported neither result. An `unknown` status means Control has signed
runtime identity but no unambiguous successful workload observation.

The console refreshes a visible page every 30 seconds and also provides a manual
refresh. Operations pages request at most 100 records and the selected tenant's
node view requests at most 500. The tenant selector loads at most 500 records at
a time and offers the next page when more tenants exist. When another view says
more records exist, use the bounded API cursor through an authenticated client;
the console does not silently claim that its first page is complete.

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
2. Open **Commands** and choose the DSSE JSON file. The file must be no larger
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
