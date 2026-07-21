---
title: Manage Gateway secrets
description: Keep inference API keys and connector credentials outside agent containers with a provider-neutral, owner-only file handoff.
section: How-to guides
---

# Manage Gateway secrets

Steward Gateway needs reusable credentials for inference endpoints and authenticated
connectors. The agent must not receive those values. Steward therefore separates
secret storage from secret use:

1. Your existing secret manager stores, rotates, audits, and recovers the value.
2. A trusted materializer writes the value to an owner-only file on the node.
3. Steward validates the file identity, permissions, and expected rotation epoch.
4. Gateway reads the file and injects the credential only into the approved
   outbound request.
5. The agent receives a logical Steward route, not the secret or upstream origin.

Steward does not implement a vault or connect directly to one provider's API. This
keeps provider authentication, unsealing, recovery, replication, lease renewal, and
audit ownership in the system designed for those jobs.

## Threat boundary

The following components remain trusted:

- the chosen secret manager and its administrators;
- the materializer process and transport;
- host root and the node filesystem;
- Steward Gateway; and
- the configured upstream service.

The agent container, Steward Control, React console, MCP adapter, and signed receipt
exports do not need secret plaintext.

A rendered file is still plaintext on the node. Disk encryption, host access
control, backups, crash dumps, and incident response must protect it.

## Create a non-secret manifest

A schema-v2 manifest lists identity and expected rotation epochs without containing
values:

```json
{
  "schema_version": "steward.secret-materialization.v2",
  "bindings": [
    {
      "tenant_id": "tenant-a",
      "secret_id": "inference-primary",
      "purpose": "inference",
      "expected_epoch": 7
    },
    {
      "tenant_id": "tenant-a",
      "secret_id": "tickets-api",
      "purpose": "connector",
      "expected_epoch": 12
    }
  ]
}
```

Install it in a root-owned configuration directory:

```console
sudo install -d -o root -g steward-gateway -m 0750 /etc/steward/secrets
sudo install -o root -g steward-gateway -m 0640 materialization.json \
  /etc/steward/secrets/materialization.json
```

## Prepare protected destinations

```console
sudo stewardctl secret materialization prepare \
  -manifest /etc/steward/secrets/materialization.json \
  -root /var/lib/steward-gateway/secrets \
  -status-root /var/lib/steward-gateway/secret-status
```

Preparation creates only directories. It never creates placeholder secret values
that Gateway could mistake for valid credentials.

Your materializer must atomically write each value to:

```text
/var/lib/steward-gateway/secrets/<tenant_id>/<secret_id>
```

and the corresponding decimal epoch to:

```text
/var/lib/steward-gateway/secret-status/<tenant_id>/<secret_id>.epoch
```

Files must be regular, non-symlink, owner-only material readable by Gateway. Keep
temporary files in the same protected directory and rename them atomically. Do not
write through a world-writable directory or preserve old values in backup files.

## Validate readiness

```console
sudo stewardctl secret materialization check \
  -manifest /etc/steward/secrets/materialization.json \
  -root /var/lib/steward-gateway/secrets \
  -status-root /var/lib/steward-gateway/secret-status
```

The JSON report identifies missing, stale, or unsafe materialization and reports
expected and observed epochs. It never returns the value or its path outside the
fixed root.

Run the check before starting Gateway, after rotation, and from node monitoring.
Treat a stale epoch as unavailable authority, not as a warning to ignore.

## Configure Gateway

Gateway configuration refers to the materialized secret identity through its
bounded credential configuration. Keep configuration and secret files separate:
configuration may be copied to an auditor; secret material must not.

Use `stewardctl gateway inference set -credential-file …` to bind an inference
route to the materialized file. The
[inference-provider guide]({{ '/guides/inference/' | relative_url }}) lists provider
presets and authentication modes.

Restart or reload Gateway according to the deployment guide after a rotation if the
configured credential is loaded at process start. Verify the new epoch before
draining the old provider version.

## Choose a materializer

Any trusted system that can make atomic owner-only file updates can satisfy this
contract:

- an existing Vault or OpenBao Agent deployment;
- a cloud secret manager reached through a separately hardened node service;
- SOPS plus configuration management;
- a hardware-backed internal credential service; or
- a manual offline transfer for a disconnected evaluation.

Use the provider's supported authentication and rotation features. Grant the
materializer access only to the exact node and tenant values it needs. Do not give
it a root or broad read token merely because Steward's filesystem contract is
narrow.

## Failure behavior

If the materializer is unavailable, the last rendered file may still exist.
Steward cannot infer provider lease status from that file. Choose and monitor a
rotation policy that matches the upstream credential lifetime. When freshness
cannot be established, remove or disable the affected Gateway route rather than
silently using uncertain authority.

Never expose the secret root to an agent volume, browser, MCP result directory,
evidence export, Terraform state, or control-plane enrollment bundle.
