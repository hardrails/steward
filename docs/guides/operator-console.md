---
title: Inspect a fleet with the embedded operator console
description: Open Steward Control's read-only console, use a scoped operator credential safely, understand its five views, and reproduce its committed air-gapped assets.
section: How-to guide
---

# Inspect a fleet with the embedded operator console

Steward Control serves a read-only operator control room at `/console/`. It shows
the operations summary, derived attention findings, enrolled nodes, command
metadata, and credential metadata already available through the bounded control
API. It does not create, revoke, enroll, submit, approve, sign, retry, or delete
anything.

Use the console to decide what needs investigation. Use `stewardctl`, an approved
offline signing workflow, or another authenticated API client for changes. Private
signing keys and secret plaintext never belong in the console.

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

## Read the five views

| View | What it shows | What it omits |
| --- | --- | --- |
| Overview | Attention totals, active and retained node counts, evidence posture, command-failure counts, and retained-state capacity | Mutation controls and raw evidence frames |
| Attention | Deterministic findings derived from retained facts and current process observations; evidence recency becomes conservatively stale or unknown after a controller restart until the node reports again | Acknowledgement, dismissal, retry, remediation, or incident workflow |
| Nodes | Node state, last observation time, tenant bindings, and reported capabilities for one selected tenant | Node credentials and direct node actions |
| Commands | Command ID and digest, tenant, node, lifecycle state, and creation time | Signed command bytes, terminal result text, prompts, and task bodies |
| Credentials | Credential ID, kind, role or node, scope, creation time, and revoked state | Bearer values, token message-authentication codes, and private keys |

The console refreshes a visible page every 30 seconds and also provides a manual
refresh. Operations pages request at most 100 records and the selected tenant's
node view requests at most 500. The tenant selector loads at most 500 records at
a time and offers the next page when more tenants exist. When another view says
more records exist, use the bounded API cursor through an authenticated client;
the console does not silently claim that its first page is complete.

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
[Embed a read-only React operator console]({{ '/decisions/0020-embedded-react-operator-console/' | relative_url }}).
