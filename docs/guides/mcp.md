---
title: Operate Steward through MCP
description: Configure Steward's MCP 2025-11-25 stdio server and use its bounded admission, lifecycle, log, and state tools.
section: How-to
---

# Operate Steward through MCP

`steward-mcp` lets a Model Context Protocol (MCP) client manage one local Steward
node. It communicates over standard input and output and calls the same loopback
Executor API as `stewardctl node`. When signed admission is configured, generation
fences reject older workload generations, drift checks compare Docker state with
the signed record, the mutation journal records host changes, and receipts provide
signed evidence. MCP cannot bypass those controls. In unsigned mode, the same
host-administrator API controls Docker without the signed journal and receipt path.

## Security boundary

The token passed to `steward-mcp` is a **host-administrator credential**. Any MCP
client that can invoke the server can admit, start, stop, destroy, and purge state
within Executor's configured authority. Do not expose it to an untrusted agent or
shared desktop account. Tool annotations and confirmation text help users avoid
mistakes; they do not enforce authorization.

The packaged Executor listens only on `127.0.0.1:8090`. The MCP server accepts only
a syntactically valid loopback origin and an owner-only token file.

## Configure a client

Set `OPERATOR` to the existing operating-system user that runs the MCP client. The
commands resolve that account's real primary group and home directory, create the
destination, and make an owner-only copy of the Executor token:

```bash
OPERATOR=alice
OPERATOR_HOME=$(getent passwd "$OPERATOR" | cut -d: -f6)
OPERATOR_GROUP=$(id -gn "$OPERATOR")
sudo install -d -o "$OPERATOR" -g "$OPERATOR_GROUP" -m 0700 \
  "$OPERATOR_HOME/.config/steward"
sudo install -o "$OPERATOR" -g "$OPERATOR_GROUP" -m 0600 \
  /etc/steward/executor-token "$OPERATOR_HOME/.config/steward/executor-token"
```

Use this server entry in a client that supports local stdio MCP servers. Replace
`/home/alice` if the resolved home directory is different:

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
stdout and diagnostics only to stderr.

## Tools

Dead Simple Signing Envelope (DSSE) binds a typed payload to its signatures. A
lineage is one workload's persistent state history.

| Tool | Effect |
| --- | --- |
| `steward_admit` | Submit a base64 DSSE capsule and strict instance-intent JSON. |
| `steward_status` | Read current hardened workload state. |
| `steward_logs` | Read bounded container logs. |
| `steward_egress` | Read bounded egress counters and last destination/decision. |
| `steward_start` / `steward_stop` | Transition the agent, relay, and Gateway grant; signed workloads use the mutation journal and receipts. |
| `steward_destroy` | Destroy the containers, network, and grant while retaining state. |
| `steward_purge_state` | Permanently remove an inactive persistent-state lineage after signed authorization; persistent state is available only in dedicated-host compatibility mode. |

The implementation follows MCP revision `2025-11-25` and supports initialization,
`ping`, `tools/list`, and `tools/call`. It has no network MCP transport. Stdio keeps
the adapter local; Steward's existing control channels handle remote authentication.

## Diagnose

Run the binary directly and send one JSON-RPC message per line. A successful
initialize response reports server name `steward-mcp` and protocol version
`2025-11-25`. If the process reports a token-permission error, correct the file
ownership. Do not make the token group- or world-readable.

For non-MCP automation, use [`stewardctl node`]({{ '/guides/workload-lifecycle/' | relative_url }})
or the [Executor OpenAPI]({{ '/reference/api/' | relative_url }}).
