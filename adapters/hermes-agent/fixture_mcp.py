#!/usr/bin/env python3
"""Bounded, stateless Streamable HTTP MCP fixture."""

from __future__ import annotations

import http.server
import json
from typing import Any

MAX_BODY = 64 << 10


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_HEAD(self) -> None:  # noqa: N802
        if self.path != "/mcp":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/mcp":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY:
            self.send_error(413)
            return
        request = json.loads(self.rfile.read(length))
        method = request.get("method") if isinstance(request, dict) else None
        request_id = request.get("id") if isinstance(request, dict) else None
        if method == "initialize":
            params = request.get("params", {})
            requested_version = params.get("protocolVersion") if isinstance(params, dict) else None
            if not isinstance(requested_version, str) or len(requested_version) > 32:
                requested_version = "2025-06-18"
            result: object = {
                "protocolVersion": requested_version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "steward-fixture-echo", "version": "1"},
            }
        elif method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Returns the exact bounded input value.",
                        "inputSchema": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["value"],
                            "properties": {"value": {"type": "string", "maxLength": 128}},
                        },
                    }
                ]
            }
        elif method == "tools/call":
            params = request.get("params", {})
            arguments = params.get("arguments", {}) if isinstance(params, dict) else {}
            value = arguments.get("value") if isinstance(arguments, dict) else None
            if params.get("name") != "echo" or not isinstance(value, str) or len(value) > 128:
                self._response(request_id, error={"code": -32602, "message": "invalid echo arguments"})
                return
            result = {"content": [{"type": "text", "text": value}], "isError": False}
        elif method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        else:
            self._response(request_id, error={"code": -32601, "message": "method not found"})
            return
        self._response(request_id, result=result)

    def _response(self, request_id: object, *, result: object = None, error: object = None) -> None:
        payload: dict[str, object] = {"jsonrpc": "2.0", "id": request_id}
        payload["error" if error is not None else "result"] = error if error is not None else result
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("0.0.0.0", 8767), Handler).serve_forever()
