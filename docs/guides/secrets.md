---
title: Store and distribute credentials without exposing them to agents
description: Keep inference API keys and connector tokens outside agent containers while OpenBao or another trusted service manages their lifecycle.
section: Guide
---

# Store and distribute credentials without exposing them to agents

An agent needs access to capabilities, not reusable secret bytes. Steward Gateway
holds inference API keys and connector tokens, sends them only to fixed admitted
upstreams, and gives each agent a private Relay endpoint instead. A prompt-injected
or malicious workload cannot read the Gateway credential file through that
interface.

Steward does not implement a general-purpose vault. You can install credentials
manually, or use [OpenBao](https://openbao.org/) to store, distribute, rotate, and
audit them. OpenBao is optional and can run inside the same air gap. HashiCorp Vault
Agent and other trusted tools can use the same file handoff, but Steward neither
links to nor calls their APIs.

## Security boundary

The materializer and Gateway are trusted node services. Agent images, skills,
prompts, tool results, and tenant configuration remain untrusted.

- Never mount the materialization directory into an agent or Relay container.
- Never place a secret value or provider token in a capsule, site policy, instance
  intent, command, evidence record, environment variable, or web form.
- Give the materializer read access only to the exact node and tenant paths it must
  render. Do not use an OpenBao root token.
- Verify OpenBao TLS with a pinned CA. Do not set `tls_skip_verify`.
- Do not expose an OpenBao Agent listener or token sink when file templates are the
  only required function.
- Treat host root, Gateway, and the materializer as part of the trusted computing
  base. This design isolates tenant workloads; it cannot protect secrets after
  those trusted components are compromised.

## Compile a closed OpenBao handoff

Install and operate OpenBao separately. Steward does not download it, link to it,
or manage its storage, unseal keys, backups, or high availability. Verify the
OpenBao package and checksum using its
[installation guidance](https://openbao.org/docs/install/) before placing `bao` on
the node.

Create only the trusted roots. The generated service creates tenant directories;
it never creates a root, secret value, or version marker.

```console
sudo install -d -o steward-gateway -g steward-gateway -m 0700 \
  /var/lib/steward-gateway/secrets \
  /var/lib/steward-gateway/secret-status
sudo install -d -o root -g steward-gateway -m 0750 \
  /etc/steward/openbao \
  /etc/steward/openbao-agent
sudo install -d -o steward-gateway -g steward-gateway -m 0700 \
  /run/steward-openbao
```

Create a non-secret compiler plan. `expected_version` is the positive KV v2
version returned after the secret is written. Provider paths and tenant identifiers
are still sensitive inventory, so protect the plan even though it contains no
credential.

```json
{
  "schema_version": "steward.openbao-materializer-plan.v1",
  "openbao_address": "https://openbao.internal:8200",
  "auth_mount": "auth/approle",
  "ca_file": "/etc/steward/openbao/ca.pem",
  "role_id_file": "/etc/steward/openbao/role-id",
  "secret_id_file": "/run/steward-openbao/secret-id",
  "bao_path": "/usr/bin/bao",
  "stewardctl_path": "/usr/bin/stewardctl",
  "install_root": "/etc/steward/openbao-agent",
  "secret_root": "/var/lib/steward-gateway/secrets",
  "status_root": "/var/lib/steward-gateway/secret-status",
  "bindings": [
    {
      "tenant_id": "tenant-a",
      "secret_id": "inference-primary",
      "purpose": "inference",
      "kv_path": "steward-kv/data/tenant-a/inference-primary",
      "field": "value",
      "expected_version": 7
    },
    {
      "tenant_id": "tenant-a",
      "secret_id": "ticketing",
      "purpose": "connector",
      "kv_path": "steward-kv/data/tenant-a/ticketing",
      "field": "token",
      "expected_version": 3
    }
  ]
}
```

Install the plan as root-owned mode `0640`, then compile into a new directory:

```console
sudo install -o root -g steward-gateway -m 0640 openbao-plan.json \
  /etc/steward/openbao/plan.json
sudo stewardctl secret openbao compile \
  -plan /etc/steward/openbao/plan.json \
  -out /root/steward-openbao-bundle
```

The compiler strictly decodes a bounded plan and rejects HTTP origins, credentials
in URLs, wildcards, path traversal, missing KV v2 `/data/` paths, zero versions,
shared provider fields, overlapping tenant targets, and writable paths that overlap
configuration, trust, or executable paths. It creates a mode-`0700` directory with
four mode-`0640` files:

- `openbao-read-policy.hcl`: exact `read` access to each listed data path, without
  list, write, wildcard, or metadata authority;
- `agent.hcl`: AppRole auto-auth and two templates per binding, for the value and
  its KV version marker;
- `materialization.json`: the provider-neutral expected-version manifest; and
- `steward-openbao-agent.service`: a systemd unit with a closed capability set,
  a read-only host view, and write access only to the two handoff roots and the
  one-time SecretID directory.

Install the files only after reviewing the diff:

```console
sudo install -o root -g steward-gateway -m 0640 \
  /root/steward-openbao-bundle/agent.hcl \
  /root/steward-openbao-bundle/materialization.json \
  /root/steward-openbao-bundle/openbao-read-policy.hcl \
  /etc/steward/openbao-agent/
sudo install -o root -g root -m 0644 \
  /root/steward-openbao-bundle/steward-openbao-agent.service \
  /etc/systemd/system/steward-openbao-agent.service
sudo rm -rf -- /root/steward-openbao-bundle
```

## Give the node exact OpenBao authority

Use an OpenBao administrator identity to install the generated policy. Associate it
with a distinct AppRole for this one node. Do not attach a root, default, tenant
prefix, list, write, metadata, or secret-management policy. A separate node identity
makes revocation local to one machine.

OpenBao's [KV v2 engine](https://openbao.org/docs/secrets/kv/kv-v2/) exposes data
reads under `/data/` and returns a monotonic version in response metadata. Use
check-and-set (`-cas`) for operator writes so concurrent rotation cannot silently
replace a newer value. Configure a
[declarative audit device](https://openbao.org/docs/configuration/audit/) on every
OpenBao server and protect the audit output as sensitive data.

OpenBao [AppRole auto-auth](https://openbao.org/docs/agent-and-proxy/autoauth/methods/approle/)
reads RoleID and SecretID files. Install the RoleID as
`root:steward-gateway` mode `0640`. Deliver the SecretID through a separate trusted
bootstrap channel as `steward-gateway:steward-gateway` mode `0600` at
`/run/steward-openbao/secret-id`. The generated Agent configuration removes that
file after reading it. Do not put either value in cloud user data, Terraform state,
the compiler plan, a shell transcript, or the web console.

The generated templates deliberately override unsafe defaults documented by
[OpenBao Agent templates](https://openbao.org/docs/agent-and-proxy/agent/template/):
destination files are mode `0600`, backups are disabled, parent creation is
disabled, and a missing field becomes a terminal error. The configuration contains
no listener, cache, token sink, render command, or reload hook.

Start the materializer only after the CA, RoleID, and one-time SecretID are present:

```console
sudo systemctl daemon-reload
sudo systemctl enable --now steward-openbao-agent.service
sudo systemctl status steward-openbao-agent.service
```

The `ExecStartPre` step runs `stewardctl secret materialization prepare` as
`steward-gateway`. It creates only mode-`0700` tenant directories below the two
existing roots and refuses unsafe existing boundaries.

## Validate before Gateway uses a value

Run the check as the same service identity that owns the rendered files:

```console
sudo -u steward-gateway stewardctl secret materialization check \
  -manifest /etc/steward/openbao-agent/materialization.json \
  -root /var/lib/steward-gateway/secrets \
  -status-root /var/lib/steward-gateway/secret-status
```

Successful output contains identifiers and version markers, never credentials,
credential hashes, lengths, provider paths, or filesystem paths:

```json
{"schema_version":"steward.secret-materialization-report.v2","ready":true,"bindings":[{"tenant_id":"tenant-a","secret_id":"inference-primary","purpose":"inference","expected_epoch":7,"observed_epoch":7},{"tenant_id":"tenant-a","secret_id":"ticketing","purpose":"connector","expected_epoch":3,"observed_epoch":3}]}
```

`ready` is false when any observed version differs from the expected version. A
missing, zero, whitespace-padded, linked, aliased, unstable, or incorrectly owned
marker is an error. Secret values must be 12 through 16,384 visible ASCII bytes
without whitespace; their roots and tenant directories must be caller-owned mode
`0700`, and their stable single-link files must be mode `0600` on the same
filesystem.

The value and marker are separate OpenBao templates. The check validates each
stable file but does not prove they were rendered atomically or cryptographically
bind the bytes to the reported version. It is a convergence preflight, not an
authorization or anti-rollback proof. Gateway's later descriptor-pinned load is
authoritative. Protect the secret-free report because tenant inventory can still be
sensitive.

Then point an inference route or connector at the deterministic value file and run
the complete Gateway validation:

```console
sudo -u steward-gateway stewardctl gateway validate \
  -config /etc/steward/gateway.json
```

Gateway repeats stable owner-only file checks. Validation does not grant workload
access; signed admission must still select the route or connector.

## Rotate without changing authority underneath a workload

Do not ask the materializer to signal Gateway automatically. Coordinate a rotation:

1. Stop new admission for affected routes and drain or destroy their retained
   grants.
2. Write the provider value with KV v2 check-and-set and record the returned version.
3. Change the plan's `expected_version`, compile a new directory, review it, and
   replace the installed Agent configuration and manifest.
4. Restart the materializer and wait until `materialization check` reports the
   expected and observed epochs equal. An observed version ahead of the plan is a
   failed rollout, not implicit approval.
5. For a permit-protected connector, increase `credential_epoch` in Gateway
   configuration.
6. Run Gateway validation, reload or restart Gateway, and then admit replacement
   workloads.

Gateway holds a loaded credential in memory and retained grants bind the effective
route policy and credential material. It rejects a silent authority change beneath
an existing grant. An ambiguous upstream failure is still ambiguous: rotating a
key does not prove whether an earlier external action occurred.

## Availability and persistence choices

OpenBao manages encrypted central storage, but its rendered node file is plaintext.
Use encrypted node disks and protected backups. Choose the destination deliberately:

- `/var/lib/steward-gateway/secrets` preserves the last rendered value during a
  disconnected restart, improving air-gapped availability; or
- a mode-`0700` tmpfs under `/run` removes node persistence, but Gateway must remain
  stopped whenever the materializer cannot authenticate and render after boot.

Steward does not infer lease expiry from a file. If OpenBao becomes unavailable,
Gateway continues using the value it already loaded until the upstream rejects it
or the operator drains the route. Monitor OpenBao Agent authentication and template
errors, and test seal recovery, backups, revocation, and rotation before production
rollout.

## Reproduce the OpenBao compatibility check

Maintainers can exercise the compiler and runtime handoff end to end:

```console
bash scripts/openbao-materializer-smoke.sh
```

The script uses Docker and the digest-pinned official OpenBao 2.5.4 multi-platform
image. It starts an isolated TLS development server, enables AppRole and KV v2,
installs the generated exact policy, renders a credential and version, verifies
one-use SecretID removal, checks secret-free readiness with the Linux
`stewardctl`, rotates the value with check-and-set, and verifies convergence on the
new version. It removes the container and temporary files on exit.

This is a compatibility test, not a production OpenBao deployment test. Development
mode uses in-memory storage and does not exercise unseal procedures, high
availability, declarative audit, systemd, backup, recovery, or node firewall rules.

## Why not send encrypted values into the container?

An agent able to decrypt a value can usually exfiltrate it. Encrypting delivery to
the container protects only transport, not the prompt-injected or malicious process
that receives the plaintext. Keep reusable values at Gateway and expose narrow
inference routes or [named connector operations]({{ '/guides/connectors/' | relative_url }})
instead.

Native per-node sealed envelopes may later distribute ciphertext to Gateway on a
disconnected node. That requires a reviewed recipient-key, recovery, rotation,
anti-rollback, quota, and audit protocol. It is not a safe substitute for a mature
secret manager until those guarantees exist.
