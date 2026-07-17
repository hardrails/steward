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

## Create the deterministic handoff

The initial materialization contract supports `inference` and `connector` values.
Each file is `<root>/<tenant_id>/<secret_id>`. Run the materializer as the
`steward-gateway` service user so its mode-`0600` output is readable by Gateway and
no other service identity.

```console
sudo install -d -o steward-gateway -g steward-gateway -m 0700 \
  /var/lib/steward-gateway/secrets \
  /var/lib/steward-gateway/secrets/tenant-a
sudo install -d -o root -g steward-gateway -m 0750 \
  /etc/steward/secret-materialization
```

Create a non-secret preflight manifest:

```json
{
  "schema_version": "steward.secret-materialization.v1",
  "bindings": [
    {
      "tenant_id": "tenant-a",
      "secret_id": "inference-primary",
      "purpose": "inference"
    },
    {
      "tenant_id": "tenant-a",
      "secret_id": "ticketing",
      "purpose": "connector"
    }
  ]
}
```

Install it as
`/etc/steward/secret-materialization/manifest.json`, owned by
`root:steward-gateway` with mode `0640`. The manifest contains no provider path,
token, or secret value.

## Render from OpenBao

Use OpenBao KV v2 or an appropriate dynamic secrets engine. Separate tenant paths
with exact ACLs; for example, a node materializer for `tenant-a` should receive
`read` access only to the listed data paths. Enable an
[audit device](https://openbao.org/docs/configuration/audit/) and use an auto-auth
method suitable for the environment. OpenBao documents
[AppRole](https://openbao.org/docs/auth/approle/) for machine authentication, but
its SecretID is itself a bootstrap secret and must be delivered out of band.

Do not grant a node token a tenant prefix when it needs only two values. An exact
KV v2 read policy for this example is:

```hcl
path "steward-kv/data/tenant-a/inference-primary" {
  capabilities = ["read"]
}

path "steward-kv/data/tenant-a/ticketing" {
  capabilities = ["read"]
}
```

This policy cannot list sibling keys, read another tenant, change a value, or manage
the secrets engine. Use a distinct materializer identity per node so revoking one
node does not interrupt the rest of the fleet.

The following fragment shows the security-relevant Agent template settings. Adapt
the `auto_auth` method and paths to your OpenBao deployment.

```hcl
vault {
  address  = "https://openbao.internal:8200"
  ca_cert = "/etc/steward/openbao/ca.pem"

  retry {
    num_retries = 5
  }
}

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path                   = "/etc/steward/openbao/role-id"
      secret_id_file_path                 = "/run/steward-openbao/secret-id"
      remove_secret_id_file_after_reading = true
    }
  }
}

template_config {
  exit_on_retry_failure       = true
  static_secret_render_interval = "5m"
}

template {
  contents = "{% raw %}{{ with secret \"steward-kv/data/tenant-a/inference-primary\" }}{{ .Data.data.value }}{{ end }}{% endraw %}"
  destination = "/var/lib/steward-gateway/secrets/tenant-a/inference-primary"
  create_dest_dirs = false
  error_on_missing_key = true
  perms = "0600"
  backup = false
}
```

Repeat the `template` block for each binding. These settings matter:

- `perms = "0600"` avoids OpenBao Agent's new-file default of `0644`;
- `backup = false` avoids a second plaintext copy during rotation;
- `create_dest_dirs = false` makes a missing pre-created tenant boundary fail;
- `error_on_missing_key = true` plus `exit_on_retry_failure = true` prevents a
  missing field from becoming a plausible placeholder; and
- omitting `listener`, `cache`, and `sink` leaves no local provider API or token
  file for an agent to target.

The rendered value must be 12 through 16,384 ASCII bytes in the range `0x21`
through `0x7e`, with no whitespace. OpenBao Agent automatically renews renewable
values and
periodically retrieves static values. See the official
[template renewal behavior](https://openbao.org/docs/agent-and-proxy/agent/template/)
when choosing engine and lease settings.

## Validate before Gateway uses a value

Run the provider-neutral check as the same user that owns the files:

```console
sudo -u steward-gateway stewardctl secret materialization check \
  -manifest /etc/steward/secret-materialization/manifest.json \
  -root /var/lib/steward-gateway/secrets
```

Successful output contains no credential or credential-derived field:

```json
{"schema_version":"steward.secret-materialization-report.v1","ready":true,"bindings":[{"tenant_id":"tenant-a","secret_id":"inference-primary","purpose":"inference"},{"tenant_id":"tenant-a","secret_id":"ticketing","purpose":"connector"}]}
```

The check rejects unknown manifest fields, ambiguous identifiers, duplicate
bindings, relative paths, symlinks, hard links, filesystem crossings, wrong owners
or modes, changed files, multiline values, and over-sized input. It does not return,
hash, or report the length of a secret.

Tenant and secret identifiers can still be sensitive operational metadata. Protect
the report as you would other tenant inventory; "secret-free" does not mean safe to
publish.

This command is a point-in-time preflight, not an authorization, rotation, or
anti-rollback proof. A trusted materializer can change a file after the check.
Gateway therefore performs its own descriptor-pinned, stable read when it loads the
configuration; the bytes Gateway loads are authoritative.

Then point an inference route or connector at the deterministic file and run the
complete Gateway validation:

```console
sudo -u steward-gateway stewardctl gateway validate \
  -config /etc/steward/gateway.json
```

Gateway repeats its own stable owner-only file checks. Validation does not grant an
agent access; signed admission must still select the inference route or connector.

## Rotate without changing authority underneath a workload

Do not ask the materializer to signal Gateway automatically. Coordinate a rotation:

1. Stop new admission for affected routes and drain or destroy their retained
   grants.
2. Rotate the provider value and wait for the exact destination file to change.
3. For a permit-protected connector, increase `credential_epoch` in Gateway
   configuration.
4. Run both materialization and Gateway validation.
5. Reload or restart Gateway, then admit replacement workloads.

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
