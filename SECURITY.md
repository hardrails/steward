# Security reports

Steward does not currently publish a private vulnerability-reporting channel.
Do not put exploit details, secrets, tenant data, or sensitive environment data in
a public issue.

Report security defects that can be described safely through the
[GitHub issue tracker](https://github.com/hardrails/steward/issues). If a report
requires confidential details, wait for the project to publish a private reporting
path. This is a project limitation, not a request to disclose the details publicly.

## Prompt injection and external effects

Treat calendar invitations, email, web pages, documents, tool results, and agent
memory as hostile input. A stored or indirect prompt injection can make a capable
agent use legitimate permissions for an attack. In a documented example, malicious
calendar content drove an agentic browser through an authenticated password-vault
session to reveal secrets, change account settings, and exfiltrate recovery
material. This did not require breaking the vault's cryptography.

Do not rely on prompt-injection detection, model self-review, or the agent's stated
reason as the only control for a sensitive action. Steward's Authorized Effects
mode assumes the agent is fully compromised and moves authorization into Gateway:

- site-root-signed tenant policy pins action public keys and an approval threshold
  to connector IDs and can make the mode `required`;
- authenticated instance intent explicitly selects `effect_mode`, and authorized
  mode prohibits generic egress;
- Gateway requires a complete version-2 or multi-party version-3 permit signed over
  the exact operation and request bytes, keeps the upstream credential outside the
  workload, and durably consumes the permit before DNS; and
- format-5 or format-6 signed evidence binds the authorized mode, operation policy,
  and any multi-party signer threshold. Repeated
  invalid permits can create only one stable denial marker per retained grant, and
  that marker does not claim a verified permit or authority key.

That denial marker is first-observed, attacker-selectable evidence. A compromised
workload chooses the task ID and request bytes accompanying the first invalid
permit, and later attempts are not enumerated. It proves at least one denial
occurred, not that it was the only denial.

This control applies only to Steward-mediated named connectors. It does not protect
an unmanaged credential or network channel, inference confidentiality, local
filesystem or computer-use effects, a compromised host root or signing key, an
approver who misunderstood the request, or an upstream operation after an ambiguous
response. Steward provides at-most-once local permit spend within the retained
ledger boundary, not exactly-once upstream execution.

See [Authorize exact external effects](docs/guides/authorized-effects.md) for the
configuration, attack boundary, and offline audit procedure. The complete trust and
isolation model is in [Security model](docs/concepts/security-model.md).

## Embedded operator console

Treat the browser and its extensions as part of the operator trust boundary.
Steward Control's `/console/` surface is read-only, but the operator bearer entered
there may authorize mutations when used by another API client. A malicious browser
extension that steals it can act with that existing authority. Use a dedicated,
patched profile without unapproved extensions or cloud synchronization, and prefer
a tenant-scoped operator over a site administrator.

The console stores the bearer only in JavaScript memory. It clears that reference,
aborts in-flight requests, and discards displayed state on explicit lock,
`pagehide`, 15 minutes of inactivity, or eight hours from sign-in. These are
client-side session controls; they do not revoke or expire the server-side bearer.
Use the normal credential revocation or rotation workflow when authority must end.

The page makes only same-origin reads of bounded summary, attention, node, command,
and credential metadata. It never returns bearer values, token
message-authentication codes, secret plaintext, private signing material, raw
signed command bytes, or terminal result text. Mutations and signing remain outside
the browser surface. Fleet metadata is still sensitive and must be protected in
transit, on screen, and from browser extensions.

Static assets are embedded in `steward-control`; there is no CDN, telemetry call,
or runtime Node.js service. Restrictive browser headers and the automatic exact
Host gate reduce cross-origin, framing, and DNS-rebinding exposure. They do not
make a compromised browser or controller host trustworthy. See
[Inspect a fleet with the embedded operator console](docs/guides/operator-console.md).

## Gateway credentials

Do not put inference keys or connector tokens in agent environment variables,
mounts, images, skills, prompts, commands, or the operator console. Gateway reads
owner-only credential files and presents only admitted inference routes or named
connector operations to a workload. OpenBao Agent or another trusted service may
materialize those files without becoming a Steward dependency.

`stewardctl secret openbao compile` can generate exact KV v2 read policy,
fail-closed Agent templates, an expected-version manifest, and a systemd sandbox.
The compiler neither contacts OpenBao nor accepts provider credentials. Review the
generated policy and unit before installation; OpenBao, its AppRole bootstrap,
audit, recovery, and transport remain operator-managed trust boundaries.

Run `stewardctl secret materialization check` as the Gateway service identity
before validation. It verifies deterministic tenant paths, ownership, modes,
link and filesystem boundaries, stable reads, bounded visible-ASCII values, and,
for a compiled OpenBao handoff, an expected provider-version marker. It never
prints a value, hash, length, provider path, or filesystem path. Value and marker
templates are not atomic, so the result is a convergence preflight rather than a
cryptographic version binding. Gateway's later stable value read remains
authoritative.
The materializer, Gateway, and host root are trusted components, and plaintext
still exists in the protected destination file and Gateway memory. See
[Store and distribute credentials without exposing them to agents](docs/guides/secrets.md).
