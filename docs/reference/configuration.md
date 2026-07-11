---
title: Configuration reference
description: Steward and Steward Executor configuration sources, precedence, packaged defaults, validation commands, security-sensitive flags, paths, and service behavior.
section: Reference
---

# Configuration reference

## Steward configuration precedence

The supervisor accepts flags, matching `STEWARD_` environment variables, and a JSON
file. Precedence is **flag → environment → config file → built-in default**. Convert
a flag such as `-max-instances` to `STEWARD_MAX_INSTANCES`; JSON uses
`max_instances`.

The packaged service starts with:

```console
steward -config /etc/steward/steward.json \
  -audit-log-file /var/log/steward/audit.jsonl
```

Its safe node template uses an outbound-only uplink, durable state, process execution
off, and TLS verification on.

### Supervisor settings

| Flag | Default | Purpose |
| --- | --- | --- |
| `-addr` | `127.0.0.1:8080` | Inbound listener address |
| `-log-level` | `info` | `debug`, `info`, `warn`, or `error` |
| `-max-instances` | `1024` | Capacity cap for tracked instances |
| `-max-requests-per-second` | `20` | Per-source inbound rate; non-positive disables |
| `-state-file` | empty | Durable JSON state path |
| `-disable-inbound-listener` | `false` | Outbound-only operation; requires uplink |
| `-enable-metrics` | `false` | Expose Prometheus `/metrics` on inbound listener |
| `-audit-log-file` | empty | Append-only JSON Lines command audit path |
| `-uplink-url` | empty | Control-plane base URL |
| `-uplink-credential-file` | empty | Owner-only node credential; required with uplink |
| `-uplink-poll-interval` | `10s` | Base poll cadence with jitter/backoff |
| `-uplink-command-queue-depth` | `256` | Bounded received-command queue |
| `-uplink-tls-ca-file` | system roots | Private CA bundle |
| `-uplink-tls-client-cert` | empty | Optional mTLS certificate |
| `-uplink-tls-client-key` | empty | Owner-only mTLS key |
| `-uplink-tls-skip-verify` | `false` | Dangerous diagnostic acknowledgement |
| `-enable-process-exec` | `false` | Trusted local OS-process supervision only |
| `-allow-nonloopback-process-exec` | `false` | Dangerous topology acknowledgement |
| `-allow-root-process-exec` | `false` | Dangerous privilege acknowledgement |
| `-process-stop-grace-period` | `10s` | SIGTERM-to-SIGKILL delay |

`-version`, `-check-config`, and `-schema` perform an action and exit. Generate the
authoritative JSON Schema and validate the fully resolved configuration with the
running release:

```console
steward -schema > steward.config.schema.json
steward -check-config -config /etc/steward/steward.json
```

Only `max_instances` is reloadable with `SIGHUP`; failed reload leaves the prior
value active. Other changes require a restart.

## Executor configuration

Executor uses flags. The packaged unit maps `/etc/steward/executor.env` values into
explicit flags and forces `-disable-inbound-listener`.

| Flag | Default | Purpose |
| --- | --- | --- |
| `-addr` | `127.0.0.1:8090` | Optional host-local API listener |
| `-docker-socket` | `/var/run/docker.sock` | Docker Engine Unix socket |
| `-token-file` | required | Owner-only local API bearer token |
| `-disable-inbound-listener` | `false` | Outbound-only operation; requires uplink |
| `-uplink-url` | empty | Control-plane base URL |
| `-uplink-credential-file` | empty | Owner-only Executor node credential |
| `-uplink-state-file` | empty | Durable anti-replay state; required with uplink |
| `-uplink-poll-interval` | `10s` | Base outbound poll cadence |
| `-uplink-tls-ca-file` | system roots | Private CA bundle |
| `-uplink-tls-client-cert`, `-uplink-tls-client-key` | empty | Optional mTLS identity |
| `-max-memory-bytes` | `536870912` | Per-workload admission ceiling |
| `-max-cpu-millis` | `1000` | Per-workload CPU ceiling |
| `-max-pids` | `128` | Per-workload process ceiling |
| `-max-workloads` | `32` | Managed workload cap for the host |
| `-max-workloads-per-tenant` | `4` | Managed workload cap per tenant |
| `-admission-policy-file` | empty | Signed site-policy DSSE; enables v1.2 signed admission |
| `-admission-site-root-public-key-file` | empty | Base64 Ed25519 site-root public key |
| `-admission-site-root-key-id` | empty | Required signature key ID for the site policy |
| `-admission-node-id` | empty | Stable node ID bound into intents and receipts |
| `-admission-fence-file` | `/var/lib/steward-executor/admission-fences.bin` | Policy/generation high-water store |
| `-initialize-admission-fence` | `false` | Exclusively create the empty fence and exit; normal startup never recreates it |
| `-admission-allow-host-admin-intent` | `false` | Break glass: let the host-wide local token select an intent tenant |
| `-admission-journal-file` | `/var/lib/steward-executor/operation-journal.bin` | Fsynced host-mutation journal |
| `-admission-evidence-file` | `/var/lib/steward-executor/evidence.bin` | Signed receipt chain |
| `-admission-evidence-key-file` | empty | Owner-only PKCS#8 Ed25519 receipt private key |
| `-admission-evidence-epoch` | `1` | Receipt-key epoch expected by offline verification |

The break-glass `-uplink-allow-insecure-http` and `-uplink-tls-skip-verify` flags
weaken transport authentication and are off by default. They are not appropriate for
production configuration.

Signed admission is opt-in but atomic: setting any trust input requires the
complete policy, site-root key and ID, node ID, and evidence key. The packaged
unit accepts the matching optional `EXECUTOR_ADMISSION_*` values from
`/etc/steward/executor.env`. See [signed admission and receipts]({{ '/guides/signed-admission/' | relative_url }}).

Validate the same token, Docker, `runsc`, policy, fence, TLS, and credential paths
used during real startup without binding or polling:

```console
sudo -u steward-executor steward-executor -check-config <the-service-flags>
```

The packaged preflight assembles this command for you:

```console
sudo /usr/local/libexec/steward/node-preflight
```

For exact accepted flags, always use the installed version's `steward -h` and
`steward-executor -h` output. The [public APIs]({{ '/reference/api/' | relative_url }})
are separately versioned contracts.
