---
title: Operate Steward through MCP
description: Configure Steward's MCP 2025-11-25 stdio server and use its bounded admission, lifecycle, log, and state tools.
section: How-to
---

# Operate Steward through MCP

`steward-mcp` lets an MCP-capable operator tool manage one local Steward node.
It is a stdio adapter over the same loopback Executor API used by
`stewardctl node`; it cannot bypass signed admission, generation fences,
drift checks, the mutation journal, or receipts.

## Security boundary

The token passed to `steward-mcp` is a **host-administrator credential**. Every
MCP client that can invoke this server can start, stop, destroy, admit, and purge
state within the authority allowed by the configured Executor. Do not expose it
to an untrusted agent or a shared desktop account. MCP tool annotations and
confirmation text are usability signals, not authorization controls.

Executor listens only on `127.0.0.1:8090` in the packaged v1.3 unit. The MCP
server accepts only a syntactic loopback origin and an owner-only token file.

## Configure a client

Create a dedicated owner-only copy of the Executor token for the trusted OS user
that runs your MCP client:

```bash
sudo install -o OPERATOR -g OPERATOR -m 0600 \
  /etc/steward/executor-token /home/OPERATOR/.config/steward/executor-token
```

Use this server entry in a client that supports local stdio MCP servers:

```json
{
  "mcpServers": {
    "steward": {
      "command": "/usr/local/bin/steward-mcp",
      "args": [
        "-node-url", "http://127.0.0.1:8090",
        "-token-file", "/home/OPERATOR/.config/steward/executor-token"
      ]
    }
  }
}
```

Restart the MCP client, list tools, and call `steward_status` with an
`executor-…` runtime reference. The server writes newline-delimited JSON-RPC to
stdout and diagnostics only to stderr.

## Tools

| Tool | Effect |
| --- | --- |
| `steward_admit` | Submit a base64 DSSE capsule and strict instance-intent JSON. |
| `steward_status` | Read current hardened workload state. |
| `steward_logs` | Read bounded container logs. |
| `steward_start` / `steward_stop` | Transition the agent, relay, and gateway grant as one journaled operation. |
| `steward_destroy` | Destroy runtime topology while retaining state. |
| `steward_purge_state` | Permanently remove an inactive lineage after signed authorization. |

The implementation follows MCP revision `2025-11-25`, supports the standard
initialize lifecycle, `ping`, `tools/list`, and `tools/call`, and deliberately
ships no network MCP transport. Stdio keeps the adapter local and leaves remote
authentication to Steward's existing control channels.

## Diagnose

Run the binary directly and send one JSON-RPC message per line. A healthy
initialize response reports server name `steward-mcp` and protocol version
`2025-11-25`. If the process reports a token-permission error, fix ownership;
do not make the token group- or world-readable.

For non-MCP automation, use [`stewardctl node`]({{ '/guides/workload-lifecycle/' | relative_url }})
or the [Executor OpenAPI]({{ '/reference/api/' | relative_url }}).
