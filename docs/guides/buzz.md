---
title: Connect Hermes to Buzz
description: Turn an allowed, cryptographically signed Buzz mention into one signed Steward task and one reply without giving Buzz credentials to Hermes.
section: Guides
---

# Connect Hermes to Buzz

Buzz can be the place where people ask a Hermes agent for work and receive the
answer. Steward remains the security boundary: every accepted message becomes one
exact tenant-signed task, Hermes runs inside its existing isolated deployment, and
the reply returns to the same verified Buzz conversation.

The important separation is simple:

```text
Buzz relay ── signed events ──> trusted bridge ── signed task ──> Steward Gateway ──> Hermes
    ^                                  |
    └──────── signed reply ────────────┘
```

The bridge holds the Buzz identity and Steward task key. Hermes holds neither. A
message cannot choose another tenant, deployment, operation, channel, or thread.

## What this supports

The initial surface is deliberately narrow:

- a kind-9 Buzz message with exactly one cryptographic mention of the bridge;
- an exact, configured author public key and channel UUID;
- one bounded `hermes.run` task against one configured durable deployment; and
- one plain-text reply to the triggering event.

DMs, forum-wide listening, uploads, channel administration, workflows, Git
operations, arbitrary Buzz commands, and open-to-anyone dispatch are not enabled.
Use a normal Hermes research deployment if messages should trigger web research;
the bridge does not grant new tools or bypass existing connector policy.

## Before you start

You need:

1. A separately operated Buzz relay and an agent identity created with Buzz's
   administration tool. Steward does not install Buzz, PostgreSQL, Redis, or
   object storage.
2. A running, task-enabled Hermes deployment. Complete [Build and run an
   agent]({{ '/guides/build-agents/' | relative_url }}) first.
3. A trusted Linux or macOS integration host for the bridge. Do not place the
   Buzz or task signing key inside the Hermes container or on an untrusted agent
   node.
4. A protected route from the integration host to the node's loopback Gateway.
   The current bridge uses an SSH local-forward or an equivalent operator-owned
   private tunnel. Gateway itself remains loopback-only.

## 1. Build the pinned bridge bundle

Download the `steward-buzz_<version>_<os>_<arch>.tar.gz` kit for the trusted
integration host and verify it with the release `checksums.txt`. Extract it, then
run:

```console
./build-buzz --output ./steward-buzz-bundle
```

The kit contains target-native Steward binaries. Its builder fetches the exact
Buzz source commit recorded in
`integrations/buzz/source-lock.json`, verifies every consumed input, applies the
reviewed local-verification patch, builds with Buzz's locked Rust dependencies,
and packages `buzz`, `steward-buzz-bridge`, and `stewardctl` together.

Maintainers working from an authenticated Steward source checkout can run the
underlying builder directly:

```console
scripts/build-buzz-bridge.sh --output ./steward-buzz-bundle
```

For an air-gapped build, mirror the pinned Buzz checkout and Cargo sources first,
then use:

```console
./build-buzz \
  --source-dir /srv/mirror/buzz-pinned \
  --offline \
  --output ./steward-buzz-bundle
```

Both commands refuse a different commit, dirty checkout, mismatched input hash,
wrong Rust toolchain, patch drift, or existing output directory. Review the Buzz
Apache-2.0 license included in the bundle before redistribution.

Install the bundle for a dedicated, non-human service account:

```console
sudo useradd --system --home /var/lib/steward-buzz --shell /usr/sbin/nologin steward-buzz
sudo install -d -o root -g root -m 0755 /usr/local/lib/steward-buzz
sudo install -o root -g root -m 0555 steward-buzz-bundle/{buzz,stewardctl,steward-buzz-bridge} \
  /usr/local/lib/steward-buzz/
sudo install -d -o root -g steward-buzz -m 0750 /etc/steward-buzz
sudo install -d -o steward-buzz -g steward-buzz -m 0700 /var/lib/steward-buzz
```

## 2. Prepare credentials without copying them into Hermes

Use a separate Buzz identity and task authority for each tenant integration.
Place the following as files owned by `steward-buzz`, mode `0400` or `0600`:

- the Buzz `nsec` private key;
- the Buzz API token when the relay requires it;
- the Buzz owner-attestation tag when the relay uses one;
- a Control operator token scoped to the configured tenant;
- the Gateway service bearer, exported service trust, and task-authority private
  key used by the existing `stewardctl task run` flow; and
- the private Control CA bundle when Control uses a private CA.

The bridge validates every protected file before reporting a valid configuration.
It rejects symlinks, unsafe group/world access, multiple hard links, unexpected
secret owners, oversized values, and files that change while being read. It
disables core dumps. Secrets enter only the short-lived, pinned Buzz CLI process
that must sign a relay request; the `stewardctl` and Hermes processes receive a
separate, minimal environment.

## 3. Keep Gateway private

Create an operator-owned tunnel from the trusted integration host to the exact
node that runs the selected deployment. This example binds only local port 18091:

```console
ssh -NT \
  -L 127.0.0.1:18091:127.0.0.1:8091 \
  steward-node@node.example.com
```

Use an SSH key restricted to local forwarding and the one destination. Run the
tunnel under its own supervised service in production. The node sees a signed
task bundle, never the task private key. If the tunnel is down, the bridge keeps
the durable inbox record and reports a clear failure; it does not mint different
authority on retry.

## 4. Configure exact identities

Copy `integrations/buzz/bridge.example.json` to
`/etc/steward-buzz/bridge.json`. Replace every example value. Author public keys
and channel UUIDs must be sorted and unique. The bridge's own public key cannot
appear in `allowed_authors`. Install the final configuration as
`root:steward-buzz` mode `0640`; the service account can read it but cannot change
its own authority.

```console
sudo -u steward-buzz /usr/local/lib/steward-buzz/steward-buzz-bridge \
  -config /etc/steward-buzz/bridge.json \
  -check-config
```

`gateway_url` must remain a literal-loopback HTTP origin. `relay_url` must be one
exact HTTPS origin without user information, a query, fragment, or trailing
slash. Proxy environment variables are not inherited by child processes.

## 5. Start and prove a real task

Install the hardened service unit:

```console
sudo install -o root -g root -m 0644 \
  deploy/systemd/steward-buzz-bridge.service \
  /etc/systemd/system/steward-buzz-bridge.service
sudo systemctl daemon-reload
sudo systemctl enable --now steward-buzz-bridge
curl --fail --silent http://127.0.0.1:9082/health
```

Add the bridge identity to one configured Buzz channel. From an allowed author,
send a message that cryptographically mentions the agent, for example: “Research
the latest primary sources on this topic and explain what is uncertain.”

The first successful poll writes an owner-only record before task dispatch. The
task ID is deterministic from the tenant, integration, and verified Buzz event
ID. If the process stops after dispatch, it resubmits the same retained bundle and
waits for the same result. Before retrying a reply after an ambiguous relay
failure, it searches the verified thread for the same signed author, parent, and
content. This prevents a normal restart from producing duplicate work or replies.
Reply text is sent literally: `@names` and `nostr:` references remain text and do
not create additional mention tags selected by the agent.

Inspect non-secret status locally:

```console
curl --fail --silent http://127.0.0.1:9082/status
journalctl -u steward-buzz-bridge --since today
```

The health endpoint returns 503 until the first complete poll succeeds. The status
endpoint reports integration identity, last successful poll, a bounded
error, and completed count. It never returns message content, model output, task
bundles, or credentials.

## Failure and recovery behavior

- Invalid signatures or event IDs are rejected by the patched Buzz CLI before
  Steward reads any event field.
- Wrong authors, channels, kinds, timestamps, missing or duplicate `h`/`p` tags,
  and self-authored loops create no task.
- An owner-only advisory lock prevents overlapping bridge processes from
  submitting or replying to the same event concurrently. The operating system
  releases the lock if a process crashes, so the next poll can recover.
- An unavailable Control plane, Gateway tunnel, Hermes service, or Buzz relay
  leaves a durable record with a bounded error and makes `/health` return 503.
- `max_records` stops intake without deleting old work. Archive completed record
  and run directories through a reviewed operator procedure before raising it.
- A failed Hermes task is not published as an answer. Inspect the retained signed
  bundle/result path and Gateway receipt chain with the normal task tools.

Buzz content is untrusted input even after its signature verifies: the signature
proves who authored the bytes, not that the bytes are safe. The bridge quotes the
message as untrusted data, while Hermes' existing egress, connector, inference,
and action policy remains authoritative.

## Automatic upstream refresh

`.github/workflows/buzz-pin.yml` checks weekly and can be run manually. It waits
24 hours after a stable Buzz source snapshot, resolves the tag to one immutable
commit, recalculates source and Steward bridge hashes, and opens one pull request.
It never auto-merges, force-replaces bytes already under review, or treats Buzz's
desktop, relay, chart, and rolling Sprig labels as the same version.

A pin pull request must rebuild the patched CLI from the locked source and pass
the bridge tests before review. Production operators should also require their
normal license, advisory, image, secret-isolation, malicious-relay, restart, and
gVisor qualification gates for the new exact bytes.

The rationale and rejected alternatives are recorded in [ADR 0054]({{ '/decisions/0054-reuse-buzz-protocol-behind-a-steward-bridge/' | relative_url }}).
