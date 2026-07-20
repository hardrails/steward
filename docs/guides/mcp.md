---
title: Operate Steward through MCP
description: Configure Steward's local MCP server for bounded fleet, node, and optional pre-signed task lifecycle operations.
section: How-to
---

# Operate Steward through MCP

`steward-mcp` lets a Model Context Protocol (MCP) client operate Steward Control, a
local Steward node, or both. It communicates through standard input and output; it
does not open a network listener. Fleet tools call the authenticated Steward
Control API. Read-only operations tools return tenant-projected summaries,
deterministic attention findings, and secret-free command or credential metadata.
Node tools call the same loopback Executor API as `stewardctl node`. The read-only
evidence tool requires site-admin authority and returns a bounded checkpoint
projection rather than raw proof signatures or export files. Optional task tools
call the loopback Gateway API and accept only an exact request with a tenant-signed
permit.

MCP is an interface, not an authorization boundary. Executor and Gateway still
apply signed policy, generation fences, durable replay controls, journals, quotas,
and receipts. An MCP client cannot use these tools to mint task authority or bypass
those controls.

## Security boundary

The control operator, Executor, and Gateway bearer tokens are privileged
credentials. A control operator token can read or change the tenants and nodes in
its scope and submit any already valid signed command it possesses. Controller MCP
does not issue operator or enrollment secrets. The Executor and Gateway tokens are
**host-administrator credentials**. A
client that can invoke node tools can admit, start, stop, destroy, and purge state
within Executor's configured authority. A client with task tools can spend a valid
pre-signed permit and cause its exact external effect. Do not expose either token,
the MCP process, or its standard-input channel to an untrusted agent or shared
account.

`acknowledge_external_effects=true` is a model-visible safety acknowledgment. It is
not evidence of human approval and does not grant authority. The tenant signature,
the exact permit scope, and Gateway's current policy are the authorization boundary.
Tool annotations likewise help clients present risk; they do not enforce approval.

## Configure fleet tools

Copy a least-privilege control operator token and the public controller CA
certificate into owner-only operator paths. Then configure a controller-only MCP
server:

```json
{
  "mcpServers": {
    "steward-control": {
      "command": "/usr/local/bin/steward-mcp",
      "args": [
        "-control-url", "https://control.customer.example:8443",
        "-control-token-file", "/home/alice/.config/steward/tenant-a-operator.token",
        "-control-ca-file", "/home/alice/.config/steward/control-ca.crt"
      ]
    }
  }
}
```

The token file must be owner-only. The CA is a public trust file and may be mode
`0644`. Steward Control accepts HTTP only for a literal loopback origin, uses TLS
1.3 remotely, ignores ambient proxy variables, and never follows a
redirect with the bearer. When `-control-ca-file` is set, that CA bundle replaces
the host's system root set for this controller connection.

Use a tenant-scoped operator token for ordinary fleet tools. Configure a separate
trusted controller-only MCP process with a site-admin token only when the client
must create tenants, call `steward_control_evidence_status`, or perform site-wide
revocation. Do not give that process to an untrusted model or shared user.

To expose fleet and local node tools from one process, add `-node-url` and
`-token-file` to the same argument list. Gateway task tools still require local
node configuration.

The packaged Executor and Gateway listen on literal loopback addresses. The MCP
server accepts only loopback origins and owner-only token files. Task results never
enter MCP JSON or standard output as raw agent-controlled bytes.

## Configure node tools

Set `OPERATOR` to the existing operating-system user that runs the MCP client. Copy
the Executor operator token into an owner-only directory for that account:

```bash
OPERATOR=alice
OPERATOR_HOME=$(getent passwd "$OPERATOR" | cut -d: -f6)
OPERATOR_GROUP=$(id -gn "$OPERATOR")
sudo install -d -o "$OPERATOR" -g "$OPERATOR_GROUP" -m 0700 \
  "$OPERATOR_HOME/.config/steward"
sudo install -o "$OPERATOR" -g "$OPERATOR_GROUP" -m 0600 \
  /etc/steward/executor-operator-token "$OPERATOR_HOME/.config/steward/executor-token"
```

Use this server entry in a client that supports local stdio MCP servers. Replace
`/home/alice` if the resolved home directory differs:

```json
{
  "mcpServers": {
    "steward": {
      "command": "/usr/local/bin/steward-mcp",
      "args": [
        "-node-url", "http://127.0.0.1:8090",
        "-token-file", "/home/alice/.config/steward/executor-token"
      ]
    }
  }
}
```

Restart the MCP client, list tools, and call `steward_status` with an
`executor-…` runtime reference. The server writes newline-delimited JSON-RPC to
standard output and diagnostics only to standard error.

With the operator credential, `steward_admit` and `steward_purge_state` remain
visible but fail with `insufficient_role`. Give a separate trusted MCP process the
host-admin token only when it must expose those authority-sensitive operations. A
tool being visible is not evidence that the configured credential authorizes it.

## Enable task tools

Task tools are all-or-nothing. Configure `-gateway-url`, `-gateway-token-file`, and
`-task-result-dir` together. Copy the Gateway service token to the same trusted
operator account and create an empty result directory:

```bash
sudo install -o "$OPERATOR" -g "$OPERATOR_GROUP" -m 0600 \
  /etc/steward/gateway-service-token \
  "$OPERATOR_HOME/.config/steward/gateway-service-token"
sudo install -d -o "$OPERATOR" -g "$OPERATOR_GROUP" -m 0700 \
  "$OPERATOR_HOME/.local" \
  "$OPERATOR_HOME/.local/state" \
  "$OPERATOR_HOME/.local/state/steward" \
  "$OPERATOR_HOME/.local/state/steward/task-results"
```

Add the three task arguments to the MCP server entry:

```json
{
  "mcpServers": {
    "steward": {
      "command": "/usr/local/bin/steward-mcp",
      "args": [
        "-node-url", "http://127.0.0.1:8090",
        "-token-file", "/home/alice/.config/steward/executor-token",
        "-gateway-url", "http://127.0.0.1:8091",
        "-gateway-token-file", "/home/alice/.config/steward/gateway-service-token",
        "-task-result-dir", "/home/alice/.local/state/steward/task-results"
      ]
    }
  }
}
```

The result directory must be a clean absolute path, owned by the MCP process user,
and mode `0700`. Every ancestor must be a non-symlink directory owned by root or
that user and must not be replaceable by another account. Root-owned sticky
directories such as `/tmp` are accepted as ancestors, but a dedicated operator
state directory is easier to audit.

At startup, Steward rejects unexpected or unsafe entries. It accepts at most 1,024
result files and 256 MiB in total; each verified result is at most 1 MiB. Results
are new mode-`0600` files named deterministically from the task and permit digests:
`<task-sha256>.<permit-sha256>.result`. The client cannot choose a `result_name` or
overwrite a prior result. Steward fsyncs a private temporary file, publishes the
final name atomically without overwrite, and fsyncs the directory. On startup it
removes incomplete temporaries and reconciles a crash between publication and
temporary cleanup; it never accepts a partial file as a completed result.

## Tools

Dead Simple Signing Envelope (DSSE) binds a typed payload to its signatures. A
lineage is one workload's persistent state history.

| Tool | Effect |
| --- | --- |
| `steward_control_tenant_list` / `steward_control_tenant_create` | Page through visible tenants or create one after `acknowledge_tenant_creation=true`. |
| `steward_control_node_list` / `steward_control_node_status` | Read bounded tenant-scoped fleet inventory and last-contact metadata. |
| `steward_control_node_revoke` | Site-wide node and credential revocation after `acknowledge_node_revocation=true`; unavailable to a tenant operator without site authority. |
| `steward_control_command_submit` | Retain one canonical-base64 signed Executor command after `acknowledge_command_submission=true`; the node still verifies signature and policy. |
| `steward_control_command_status` | Read durable delivery lease and terminal-report metadata for one signed command. |
| `steward_control_operations_summary` | Read capacity, command, evidence, and action-required totals for the credential's tenant projection or a site-admin-selected scope. |
| `steward_control_attention_list` | Page through deterministic findings for node contact, evidence, command outcome, and capacity pressure. Findings cannot be acknowledged or cleared through MCP. |
| `steward_control_agent_list` | Page through non-secret agent runtime observations. It reports the last successful workload status separately from the latest signed operation and never schedules, retries, or mutates a workload. |
| `steward_control_command_list` | Page and filter secret-free command metadata without returning the signed command body, terminal result body, reported status text, or error codes. |
| `steward_control_credential_list` | Page and filter non-secret operator and node credential metadata without returning bearer material or token verifiers. |
| `steward_control_evidence_status` | Read the site-admin-only last-good receipt checkpoint and sticky rollback or equivocation finding. Returns receipt identity digests but omits raw public keys, signatures, and portable export files. |
| `steward_admit` | Submit a base64 DSSE capsule and strict instance-intent JSON. |
| `steward_status` | Read current hardened workload state. |
| `steward_logs` | Read bounded container logs. |
| `steward_egress` | Read bounded egress counters and last destination or decision. |
| `steward_start` / `steward_stop` | Transition the agent, relay, and Gateway grant; signed workloads use the mutation journal and receipts. |
| `steward_destroy` | Destroy the containers, network, and grant while retaining state. |
| `steward_snapshot_state` | Create an immutable cold snapshot after the complete signed source lineage is destroyed. |
| `steward_clone_state` | Create a new quota-enforced copy-on-write lineage from a same-tenant snapshot; normal signed admission is still required before it can run. |
| `steward_purge_state` | Permanently remove an inactive persistent-state lineage after signed authorization. |
| `steward_task_submit` | Submit one exact request and signed permit. Required arguments are `service_path`, `operation_path`, `request_base64`, `permit_base64`, and `acknowledge_external_effects=true`. Returns task and permit digests plus the durable receipt marker, never raw agent output. |
| `steward_task_status` | Read durable lifecycle metadata by task and permit digest without contacting the agent. |
| `steward_task_observe` | Make one bounded status observation. If terminal output is available, verify its digest and length and save it under the deterministic result path. MCP receives only the path, digest, length, and status metadata. |

Create the version-2 lifecycle bundle with `stewardctl task issue` on the trusted
signing station. Its `service_path`, `operation.path`, `request_base64`, and
`permit_base64` fields are the exact `steward_task_submit` inputs. The private key
never belongs on the node or in the MCP client.

There is no MCP wait tool. Use `steward_task_status` for passive inspection. When
the task reaches dispatch, call `steward_task_observe`; if Gateway reports a retry
interval, wait at least that long before observing again. Preserve the same task and
permit digests after any timeout or transport error. Creating a replacement task
could duplicate an effect whose result is merely ambiguous.

For a terminal Gateway failure, MCP omits the internal error code and returns a
derived `retry_safety` value. `replacement_safe_after_new_authority` means Gateway
knows it did not contact the service; a new task still needs new signed authority.
`replacement_unsafe` means the service may have processed the request, so automatic
replacement could duplicate the effect. `failed_without_dispatch_evidence` by
itself must never be read as proof that no dispatch occurred.

The implementation follows MCP revision `2025-11-25` and supports initialization,
`ping`, `tools/list`, and `tools/call`. It has no network MCP transport. Stdio keeps
the adapter host-local; Steward's existing control channels handle remote
authentication.

## Diagnose

Run the binary directly and send one JSON-RPC message per line. A successful
initialize response reports server name `steward-mcp` and protocol version
`2025-11-25`. If the process reports a token or result-directory permission error,
correct the owner and mode. Do not make credentials or results group- or
world-readable.

For non-MCP automation, use
[`stewardctl node`]({{ '/guides/workload-lifecycle/' | relative_url }}), the
[`stewardctl task` lifecycle]({{ '/reference/offline-tools/#submit-and-recover-a-service-task' | relative_url }}),
or the [Executor OpenAPI]({{ '/reference/api/' | relative_url }}).
