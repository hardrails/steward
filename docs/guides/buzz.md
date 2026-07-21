---
title: Connect Hermes to Buzz
description: Reliably turn allowed, cryptographically signed Buzz mentions into isolated Steward tasks and verified replies without giving credentials to Hermes.
section: Guides
---

# Connect Hermes to Buzz

Buzz can be the place where people ask a Hermes agent for work and receive the
answer. Steward remains the security boundary: every accepted message is first
saved to a durable inbox, then becomes one exact tenant-signed task. Hermes runs
inside its existing isolated deployment, and the bridge marks work complete only
after it can read the signed reply back from the correct Buzz conversation.

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
- one bounded `hermes.run` task against one configured durable deployment;
- a bounded worker pool, so one slow task does not block every other accepted
  message; and
- one plain-text reply to the triggering event, verified after publication.

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
- the Buzz owner-attestation tag when the relay uses one;
- a Control operator token scoped to the configured tenant;
- the Gateway service bearer, exported service trust, and task-authority private
  key used by the existing `stewardctl task run` flow; and
- the private Control CA bundle when Control uses a private CA.

Buzz authentication is the signing key, with an optional owner-attestation tag;
there is no separate API-token setting. The bridge validates every protected file
before reporting a valid configuration.
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
slash. Proxy environment variables are not inherited by child processes. The
configuration check derives the public key from `buzz_private_key_file`, verifies
the optional owner-attestation tag against that key, and refuses a different
`agent_public_key`; it does not contact the relay.

The configuration schema is `steward.buzz-bridge-config.v2`. To migrate an older
configuration, change the schema value, remove `buzz_api_token_file`, and add
`max_workers` if the default of four concurrent tasks is not appropriate.
`max_event_age_seconds` is the first-start discovery window. After a cursor has
been saved, the bridge resumes from that cursor even after a longer outage.

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

The first successful poll writes owner-only records and then advances an
owner-only channel cursor. Task workers run independently of polling. Each task
ID is deterministic from the tenant, integration, and verified Buzz event ID. If
the process stops after dispatch, it resubmits the same retained bundle and waits
for the same result. Before publishing, the bridge stores one immutable Nostr
creation timestamp. Every retry signs the same author, timestamp, kind, tags,
and content, which produces the same Nostr event ID. The relay can therefore
accept a repeated submission after delayed visibility without creating a second
logical reply. The bridge also searches the verified thread for the same author,
parent, and content before each submission. A send that cannot be verified
remains `publish_outcome_unknown`; it is never reported as complete.
Reply text is sent literally: `@names` and `nostr:` references remain text and do
not create additional mention tags selected by the agent.

Inspect non-secret status locally:

```console
curl --fail --silent http://127.0.0.1:9082/status
journalctl -u steward-buzz-bridge --since today
```

List durable work without printing message or model content:

```console
sudo -u steward-buzz /usr/local/lib/steward-buzz/steward-buzz-bridge \
  -config /etc/steward-buzz/bridge.json -list-records
```

After correcting the underlying problem, explicitly requeue one failed or
dead-lettered event:

```console
sudo -u steward-buzz /usr/local/lib/steward-buzz/steward-buzz-bridge \
  -config /etc/steward-buzz/bridge.json \
  -retry-record <64-character-event-id>
```

The retry command takes the same per-event kernel lock as a worker, refuses a
completed event, restores the recorded safe phase, and resets its ten-attempt
budget. It never deletes the signed task bundle or creates a new task identity.

The health endpoint returns 503 until the first complete poll succeeds. The status
endpoint reports integration identity, last successful poll, bounded error,
completed count, queued count, failed count, and active worker count. It never
returns message content, model output, task bundles, or credentials.

## Failure and recovery behavior

- Invalid signatures or event IDs are rejected by the patched Buzz CLI before
  Steward reads any event field.
- The patched CLI exposes Buzz's timestamp-and-event-ID pagination cursor. The
  bridge drains verified history in 200-event pages and examines as many as
  10,000 events in one poll, subject to `max_records`. A larger or non-advancing result returns
  `buzz_backlog_saturated` or `buzz_pagination_stalled` without advancing that
  channel's durable cursor. Records accepted before that stop remain safe and
  are deduplicated during the next poll; no truncated page is treated as complete.
- Wrong authors, channels, kinds, timestamps, missing or duplicate `h`/`p` tags,
  and self-authored loops create no task.
- An owner-only advisory lock prevents overlapping bridge processes from
  submitting or replying to the same event concurrently. The operating system
  releases the lock if a process crashes, so the next poll can recover.
- An unavailable Control plane, Gateway tunnel, Hermes service, or Buzz relay
  leaves a durable record with a machine-readable error code, bounded diagnostic
  detail, attempt count, exponential retry time, and makes `/health` return 503.
- Authentication and invalid-result failures enter `dead_letter` instead of
  retrying forever. Retryable failures stop after ten attempts for operator
  review.
- `max_records` bounds active and recently completed inbox records. When the
  limit is reached, the bridge removes only verified `replied` records whose
  completion is older than the five-minute replay window, oldest first. It
  retains pending, failed, and recent deduplication records, and stops intake
  rather than deleting them. Retained task run directories are separate audit
  evidence; archive them through a reviewed operator procedure.
- A failed Hermes task is not published as an answer. Inspect the retained signed
  bundle/result path and Gateway receipt chain with the normal task tools.

Buzz content is untrusted input even after its signature verifies: the signature
proves who authored the bytes, not that the bytes are safe. The bridge quotes the
message as untrusted data, while Hermes' existing egress, connector, inference,
and action policy remains authoritative.

The cursor proves what the bridge has durably accepted from relay query results;
it cannot prove that a faulty relay disclosed every event it received. Each poll
replays the previous five minutes to catch late and same-second delivery, and
event IDs make that replay idempotent. Operators that require stronger delivery
evidence must also retain and audit the relay's own append-only event log.

## Automatic upstream refresh

`.github/workflows/buzz-pin.yml` checks daily and can be run manually. It waits
24 hours after a stable Buzz source snapshot, resolves the tag to one immutable
commit, recalculates source and Steward bridge hashes, and opens one pull request.
An upstream release still inside the observation window is a successful no-op,
not a failed workflow, so it is reconsidered the next day.
It never auto-merges, force-replaces bytes already under review, or treats Buzz's
desktop, relay, chart, and rolling Sprig labels as the same version.

A pin pull request must rebuild the patched CLI from the locked source and pass
the bridge tests before review. Production operators should also require their
normal license, advisory, image, secret-isolation, malicious-relay, restart, and
gVisor qualification gates for the new exact bytes.

The rationale and rejected alternatives are recorded in [ADR 0054]({{ '/decisions/0054-reuse-buzz-protocol-behind-a-steward-bridge/' | relative_url }}).
